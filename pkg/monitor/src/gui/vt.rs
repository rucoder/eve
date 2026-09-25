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

/// Stops Ctrl+Alt+Del from rebooting the host, and nothing else.
///
/// The kernel acts on Ctrl+Alt+Del before any userspace process sees it, which
/// is wrong for a VM console: that chord is exactly what a Windows guest needs
/// at its logon screen. `RB_DISABLE_CAD` turns off the reboot specifically -
/// the kernel then delivers SIGINT to init instead, which linuxkit's init
/// ignores.
///
/// Deliberately NOT `KDSKBMODE`/`K_OFF`, which is the usual compositor trick.
/// K_OFF takes the whole keyboard away from the VT layer, and with it
/// Ctrl+Alt+Fn - so the operator can no longer reach a text console, which on a
/// device whose only other access is a serial line makes it undebuggable. The
/// TUI this console replaced never touched the keyboard mode and VT switching
/// worked; there is no reason for us to be different. libinput reads evdev
/// directly, so we still see every key including Ctrl+Alt+Del and can forward
/// it to the guest, whatever the VT layer does with its copy.
///
/// Restored on Drop. Opt out with `GUI_VT_KBD=0`.
pub struct CtrlAltDelGuard {
    restore: bool,
}

impl CtrlAltDelGuard {
    pub fn take() -> Option<Self> {
        if std::env::var("GUI_VT_KBD").as_deref() == Ok("0") {
            log::warn!("Ctrl+Alt+Del left to the kernel; it will REBOOT THE HOST");
            return None;
        }
        if unsafe { libc::reboot(libc::RB_DISABLE_CAD) } < 0 {
            let e = std::io::Error::last_os_error();
            log::warn!("cannot disable Ctrl+Alt+Del ({e}); it will REBOOT THE HOST");
            return None;
        }
        log::info!("Ctrl+Alt+Del disabled at the kernel; VT switching (Ctrl+Alt+Fn) still works");
        Some(Self { restore: true })
    }
}

impl Drop for CtrlAltDelGuard {
    fn drop(&mut self) {
        if self.restore {
            unsafe { libc::reboot(libc::RB_ENABLE_CAD) };
            log::info!("Ctrl+Alt+Del handed back to the kernel");
        }
    }
}
