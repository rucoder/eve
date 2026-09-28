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
fn set_timeouts(sock: &UnixStream) -> std::io::Result<()> {
    sock.set_read_timeout(Some(QMP_TIMEOUT))?;
    sock.set_write_timeout(Some(QMP_TIMEOUT))?;
    Ok(())
}

/// What can go wrong talking to a QMP monitor.
///
/// Typed rather than stringly: the caller that polls for VNC clients wants to
/// treat "this guest has no VNC configured" (a remote error) differently from
/// "the monitor went away" (the guest is gone), and neither should be
/// indistinguishable from a parse bug of ours.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("qmp i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("qmp: malformed json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("qmp: the monitor closed the connection")]
    Closed,
    #[error("qmp: {class}: {desc}")]
    Remote { class: String, desc: String },
    #[error("qmp: {0}")]
    Protocol(String),
}

type Result<T> = std::result::Result<T, Error>;

/// One QMP session, already past the capabilities handshake.
pub struct Qmp {
    reader: BufReader<UnixStream>,
    sock: UnixStream,
}

impl Qmp {
    /// Connect and negotiate. The greeting is consumed here so that every
    /// later read is either a reply or an event.
    pub fn connect(path: &Path) -> Result<Self> {
        let sock = UnixStream::connect(path)?;
        set_timeouts(&sock)?;
        let mut q = Qmp {
            reader: BufReader::new(sock.try_clone()?),
            sock,
        };
        let greeting = q.recv()?;
        if greeting.get("QMP").is_none() {
            return Err(Error::Protocol(format!("expected a greeting, got {greeting}")));
        }
        q.execute("qmp_capabilities", serde_json::Value::Null)?;
        Ok(q)
    }

    /// One JSON object off the wire.
    fn recv(&mut self) -> Result<serde_json::Value> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(Error::Closed);
        }
        Ok(serde_json::from_str(&line)?)
    }

    /// Run a command and return its `return` value.
    ///
    /// QMP interleaves asynchronous events with replies on the same socket,
    /// so anything carrying an "event" key is skipped rather than mistaken
    /// for the answer - a VNC_CONNECTED arriving between the command and its
    /// reply is exactly the case this polls for. The skip is bounded so a
    /// guest generating events faster than we read cannot pin us here; the
    /// socket timeout covers everything else.
    pub fn execute(&mut self, cmd: &str, args: serde_json::Value) -> Result<serde_json::Value> {
        let mut req = serde_json::Map::new();
        req.insert("execute".into(), cmd.into());
        if !args.is_null() {
            req.insert("arguments".into(), args);
        }
        self.send(&serde_json::Value::Object(req), None)?;
        self.reply(cmd)
    }

    /// `execute`, with a file descriptor passed alongside the command.
    ///
    /// QMP's `getfd` names a descriptor the monitor is to keep; the
    /// descriptor itself travels out of band as SCM_RIGHTS on the same
    /// `sendmsg`, so it cannot be sent as part of the JSON.
    pub fn execute_with_fd(
        &mut self,
        cmd: &str,
        args: serde_json::Value,
        fd: std::os::fd::RawFd,
    ) -> Result<serde_json::Value> {
        let mut req = serde_json::Map::new();
        req.insert("execute".into(), cmd.into());
        if !args.is_null() {
            req.insert("arguments".into(), args);
        }
        self.send(&serde_json::Value::Object(req), Some(fd))?;
        self.reply(cmd)
    }

    fn send(&mut self, req: &serde_json::Value, fd: Option<std::os::fd::RawFd>) -> Result<()> {
        let mut line = serde_json::to_vec(req)?;
        line.extend_from_slice(b"\r\n");
        match fd {
            Some(fd) => send_fd(&self.sock, fd, &line)
                .map_err(|e| Error::Protocol(format!("sending a descriptor: {e}")))?,
            None => self.sock.write_all(&line)?,
        }
        Ok(())
    }

    fn reply(&mut self, cmd: &str) -> Result<serde_json::Value> {
        // Generous: events are rare next to replies, and the read timeout is
        // the real bound. This only stops an unbounded loop.
        for _ in 0..64 {
            let v = self.recv()?;
            if let Some(ev) = v.get("event").and_then(|e| e.as_str()) {
                log::debug!("qmp event while awaiting {cmd}: {ev}");
                continue;
            }
            if let Some(err) = v.get("error") {
                return Err(Error::Remote {
                    class: err.get("class").and_then(|c| c.as_str()).unwrap_or("?").to_string(),
                    desc: err.get("desc").and_then(|d| d.as_str()).unwrap_or("?").to_string(),
                });
            }
            if let Some(ret) = v.get("return") {
                return Ok(ret.clone());
            }
            return Err(Error::Protocol(format!("{cmd}: unexpected reply {v}")));
        }
        Err(Error::Protocol(format!("{cmd}: drowned in events")))
    }
}

/// The parts of `query-vnc` we use. Everything is optional because a domain
/// without VNC configured answers `{"enabled": false}` and nothing else.
#[derive(serde::Deserialize, Default)]
struct VncInfo {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    clients: Vec<serde_json::Value>,
}

/// How many VNC clients are attached to this domain.
///
/// Polled rather than subscribed: QEMU's VNC_CONNECTED/VNC_DISCONNECTED
/// events go to the `listener.qmp` monitor, which domainmgr already holds
/// open, and a second reader there would be competing for someone else's
/// event stream. A short-lived query on the executor socket is the pattern
/// `connect_display` already uses and steps on nobody.
pub fn vnc_clients(qmp: &Path) -> Result<usize> {
    let mut q = Qmp::connect(qmp)?;
    let info: VncInfo = serde_json::from_value(q.execute("query-vnc", serde_json::Value::Null)?)?;
    Ok(if info.enabled { info.clients.len() } else { 0 })
}

/// Hand QEMU one end of a socketpair and get back the other, already accepted
/// as a D-Bus peer connection.
pub fn connect_display(qmp: &Path) -> anyhow::Result<OwnedFd> {
    let mut q = Qmp::connect(qmp)?;
    let (ours, theirs) = UnixStream::pair()?;
    q.execute_with_fd(
        "getfd",
        serde_json::json!({ "fdname": "guifd" }),
        theirs.as_raw_fd(),
    )?;
    q.execute(
        "add_client",
        serde_json::json!({ "protocol": "@dbus-display", "fdname": "guifd" }),
    )?;
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

