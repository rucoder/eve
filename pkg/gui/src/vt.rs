// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Ownership of the virtual terminal, and process shutdown.
//!
//! Two things the kernel does on our behalf that we have to take back:
//! the VT keyboard driver acting on chords before userspace sees them, and
//! SIGHUP killing us when the launching session goes away.

use std::sync::atomic::{AtomicBool, Ordering};

static RUN: AtomicBool = AtomicBool::new(true);

/// False once a shutdown signal has arrived; the frame loop polls this.
pub fn running() -> bool {
    RUN.load(Ordering::SeqCst)
}

extern "C" fn on_signal(_sig: libc::c_int) {
    RUN.store(false, Ordering::SeqCst);
}

/// Catch the signals a supervisor actually sends, so we can release DRM master
/// and the scanout buffers instead of leaving them dangling.
pub fn install_signal_handlers() {
    unsafe {
        // NOT SIGHUP. nohup(1) sets it to SIG_IGN and we inherit that; arming a
        // handler here threw that away, so the app died the moment the session
        // that launched it disconnected. We own a VT - we are not a terminal
        // job, and nothing reloads configuration on SIGHUP.
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        for sig in [libc::SIGINT, libc::SIGTERM] {
            libc::signal(sig, on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t);
        }
    }
}

const KDGKBMODE: libc::c_ulong = 0x4B44;
const KDSKBMODE: libc::c_ulong = 0x4B45;
const K_OFF: i32 = 0x04;
const K_UNICODE: i32 = 0x03;

/// Takes the VT's keyboard away from the kernel for as long as it is held.
///
/// In the normal VT modes the kernel keyboard driver acts on some chords BEFORE
/// userspace ever sees them: Ctrl+Alt+Del reboots the machine, Ctrl+Alt+Fn
/// switches VT (which yanks our DRM master and kills us). Neither is something
/// a VM console may swallow - Ctrl+Alt+Del in particular is exactly the chord a
/// Windows guest needs at its logon screen.
///
/// `K_OFF` makes the VT driver ignore the keyboard entirely. We still get every
/// key, because libinput reads the evdev devices directly and does not care what
/// mode the VT is in. This is what a Wayland compositor does.
///
/// Restored on Drop. If the process is SIGKILLed the VT keyboard stays dead;
/// recover with `kbd_mode -u -C /dev/ttyN`. Opt out with `GUI_VT_KBD=0`.
pub struct VtKeyboard {
    fd: i32,
    saved: i32,
    owned: bool,
}

impl VtKeyboard {
    pub fn take() -> Option<Self> {
        if std::env::var("GUI_VT_KBD").as_deref() == Ok("0") {
            log::warn!("VT keyboard: left to the kernel; Ctrl+Alt+Del will REBOOT THE HOST");
            return None;
        }
        // openvt(1) hands us the VT as stdio, so fd 0 is it; /dev/tty is the
        // controlling terminal and works when started some other way.
        let (fd, owned) = match std::fs::File::open("/dev/tty") {
            Ok(f) => (std::os::fd::IntoRawFd::into_raw_fd(f), true),
            Err(_) => (0, false),
        };
        let mut saved: i32 = 0;
        if unsafe { libc::ioctl(fd, KDGKBMODE, &mut saved) } < 0 {
            log::warn!("VT keyboard: cannot read mode; Ctrl+Alt+Del will reboot the HOST");
            if owned {
                unsafe { libc::close(fd) };
            }
            return None;
        }
        if unsafe { libc::ioctl(fd, KDSKBMODE, K_OFF) } < 0 {
            log::warn!("VT keyboard: cannot set K_OFF; Ctrl+Alt+Del will reboot the HOST");
            if owned {
                unsafe { libc::close(fd) };
            }
            return None;
        }
        // Finding K_OFF already set means a previous instance was killed before
        // it could restore; "restoring" that would leave the console keyboard
        // dead forever. Put it back to unicode instead.
        if saved == K_OFF {
            log::warn!("VT keyboard was already K_OFF (stale from a killed run); will restore K_UNICODE");
            saved = K_UNICODE;
        }
        log::info!("VT keyboard: K_OFF (was {saved}); Ctrl+Alt+Del and Ctrl+Alt+Fn now reach the guest");
        Some(Self { fd, saved, owned })
    }
}

impl Drop for VtKeyboard {
    fn drop(&mut self) {
        unsafe { libc::ioctl(self.fd, KDSKBMODE, self.saved) };
        if self.owned {
            unsafe { libc::close(self.fd) };
        }
        log::info!("VT keyboard: restored mode {}", self.saved);
    }
}
