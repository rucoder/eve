// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Attaching to a guest's D-Bus display without a bus daemon.
//!
//! EVE has no system or session bus and does not need one. QEMU's
//! `-display dbus,p2p=on` accepts an already-connected socket handed to it over
//! QMP rather than dialling a bus:
//!
//! ```text
//! socketpair() -> getfd (SCM_RIGHTS) -> add_client "@dbus-display"
//!              -> D-Bus auth over our end
//! ```
//!
//! QEMU rejects `add_client` with "p2p connections not accepted in bus mode"
//! unless the display was started with `p2p=on`.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// How long to wait for any one QMP reply. QEMU answers in microseconds when
/// its main loop is running; when the BQL is held by a stuck device model or a
/// long savevm it answers never. Without this the read blocks forever on the
/// render thread, and the console freezes with DRM master held and a stale
/// frame on screen - no keyboard, no tab switch, nothing short of a reboot.
const QMP_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(500);

/// Apply `QMP_TIMEOUT` to both directions of the socket.
fn set_timeouts(sock: &UnixStream) -> anyhow::Result<()> {
    sock.set_read_timeout(Some(QMP_TIMEOUT))?;
    sock.set_write_timeout(Some(QMP_TIMEOUT))?;
    Ok(())
}

/// Read one QMP reply, failing on an error object.
fn qmp_line(r: &mut BufReader<UnixStream>) -> anyhow::Result<String> {
    let mut s = String::new();
    anyhow::ensure!(r.read_line(&mut s)? > 0, "qmp: connection closed");
    anyhow::ensure!(!s.contains("\"error\""), "qmp error: {}", s.trim());
    Ok(s)
}

/// Hand QEMU one end of a socketpair and get back the other, already accepted
/// as a D-Bus peer connection.
pub fn connect_display(qmp: &Path) -> anyhow::Result<OwnedFd> {
    let stream = UnixStream::connect(qmp)?;
    set_timeouts(&stream)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut w = stream.try_clone()?;

    qmp_line(&mut reader)?; // greeting
    w.write_all(b"{\"execute\":\"qmp_capabilities\"}\r\n")?;
    qmp_line(&mut reader)?;

    let (ours, theirs) = UnixStream::pair()?;
    send_fd(
        &stream,
        theirs.as_raw_fd(),
        b"{\"execute\":\"getfd\",\"arguments\":{\"fdname\":\"guifd\"}}\r\n",
    )?;
    qmp_line(&mut reader)?;

    w.write_all(
        b"{\"execute\":\"add_client\",\"arguments\":{\"protocol\":\"@dbus-display\",\"fdname\":\"guifd\"}}\r\n",
    )?;
    qmp_line(&mut reader)?;
    drop(theirs);
    Ok(OwnedFd::from(ours))
}

/// `sendmsg` with SCM_RIGHTS: QMP's `getfd` takes the descriptor out of band.
fn send_fd(sock: &UnixStream, fd: i32, payload: &[u8]) -> anyhow::Result<()> {
    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut _;
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(4) } as _;

    unsafe {
        let c = libc::CMSG_FIRSTHDR(&msg);
        anyhow::ensure!(!c.is_null(), "no cmsg header");
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::copy_nonoverlapping(&fd as *const i32, libc::CMSG_DATA(c) as *mut i32, 1);
        anyhow::ensure!(
            libc::sendmsg(sock.as_raw_fd(), &msg, 0) >= 0,
            "sendmsg: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A QEMU whose main loop is wedged accepts the connection and then says
    /// nothing. The handshake must give up, not hang: it runs on the render
    /// thread, and a hang there freezes the whole console.
    #[test]
    fn gives_up_on_a_silent_peer() {
        let dir = std::env::temp_dir().join(format!("eve-gui-qmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("qmp.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // Accept and hold the connection open without ever writing a greeting.
        let held = std::thread::spawn(move || listener.accept().map(|(s, _)| s));

        let t0 = std::time::Instant::now();
        let err = connect_display(&path).expect_err("should not hang");
        let waited = t0.elapsed();

        assert!(
            waited < QMP_TIMEOUT * 4,
            "took {waited:?}, which means it was not bounded by QMP_TIMEOUT"
        );
        let _ = held.join();
        let _ = std::fs::remove_dir_all(&dir);
        // Any error will do; what matters is that one arrived promptly.
        let _ = err;
    }

    /// Requires a QEMU started with:
    ///   -display dbus,p2p=on -qmp unix:/tmp/qmp-test.sock,server=on,wait=off
    #[test]
    #[ignore]
    fn connects_as_a_dbus_peer() {
        let fd = connect_display(Path::new("/tmp/qmp-test.sock")).expect("handshake");
        let mut sock = UnixStream::from(fd);
        use std::io::Read;
        // EXTERNAL carries the uid as its ASCII decimal spelling, hex-encoded
        // byte by byte: 1000 -> "1000" -> 31303030. Not the uid in hex.
        let uid: String = unsafe { libc::getuid() }
            .to_string()
            .bytes()
            .map(|b| format!("{b:02x}"))
            .collect();
        sock.write_all(format!("\0AUTH EXTERNAL {uid}\r\n").as_bytes())
            .unwrap();
        let mut buf = [0u8; 64];
        let n = sock.read(&mut buf).unwrap();
        assert!(buf[..n].starts_with(b"OK "), "got {:?}", &buf[..n]);
    }
}
