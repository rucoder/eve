// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! THROWAWAY SPIKE — libinput capture and routing (GUI <-> guest).
//! Opens /dev/input/event* directly as root: no udev, no logind, no seat.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use smithay::reexports::input as li;
use li::event::keyboard::{KeyState, KeyboardEventTrait};
use li::event::pointer::{Axis, ButtonState, PointerEventTrait};
use li::event::EventTrait;
use li::{Libinput, LibinputInterface};

/// CLOCK_MONOTONIC microseconds - the same clock libinput stamps events with,
/// so we can measure how stale an event is by the time we handle it.
fn now_usec() -> u64 {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
}

/// /dev/input also holds mice, mouseN and jsN aliases of the same hardware.
/// Only the evdev nodes are libinput's business.
fn is_event_node(p: &Path) -> bool {
    p.file_name().and_then(|s| s.to_str()).is_some_and(|s| s.starts_with("event"))
}

fn dev_id(d: &li::Device) -> String {
    format!("{}:{}", d.sysname(), d.name())
}

struct Iface;
impl LibinputInterface for Iface {
    fn open_restricted(&mut self, path: &Path, flags: i32) -> Result<OwnedFd, i32> {
        OpenOptions::new()
            .custom_flags(flags)
            .read(true)
            .write(flags & libc::O_RDWR != 0 || flags & libc::O_WRONLY != 0)
            .open(path)
            .map(|f| f.into())
            .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
    }
    fn close_restricted(&mut self, fd: OwnedFd) { drop(File::from(fd)); }
}

/// Where input currently goes.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Focus { Gui, Guest }

/// evdev keycodes we synthesise from the UI.
pub const KEY_LEFTSHIFT: u32 = 42;
/// Pressed in order and released in reverse, as a real keyboard would.
pub const CTRL_ALT_DEL: &[(u32, bool)] = &[
    (29, true), (56, true), (111, true),     // LEFTCTRL, LEFTALT, DELETE
    (111, false), (56, false), (29, false),
];

/// Something to do to the guest, drained by the caller each frame.
#[derive(Debug)]
pub enum GuestAct {
    /// The area we will draw this guest in changed - fullscreen toggled, a
    /// head changed mode. Tell it, so it renders at exactly that size and we
    /// blit one pixel to one pixel instead of scaling.
    Ui(usize, crate::gui::guest::HeadGeometry),
    /// A remote session took the display, or gave it back. Exactly one
    /// consumer owns the guest's monitors at a time: see the handler.
    Remote(bool),
    /// Whether the heads we do not draw may be switched off.
    ///
    /// Only sent once a guest has proved it acts on SetUIInfo. Taking a
    /// head away from a guest that ignores us is a one-way door: we can
    /// disable it and never get it back.
    ManageHeads(bool),
    AbsPos(u32, u32),
    /// Raw motion for a guest whose pointer is relative (QEMU's IsAbsolute
    /// is false, e.g. no usb-tablet, only the PS/2 mouse). The guest applies
    /// its own acceleration and owns its monitor layout.
    RelMotion(i32, i32),
    Btn(u32, bool),
    Key(u32, bool),
}

/// State shared between the input thread and the render loop.
/// Input latency counters. Atomics, so the input thread updates them with
/// three relaxed adds and never takes a lock, allocates, or does I/O on the
/// latency-critical path. The render loop drains and reports them.
#[derive(Default)]
pub struct Stats {
    pub age_sum_us: std::sync::atomic::AtomicU64,
    pub age_n: std::sync::atomic::AtomicU64,
    pub age_max_us: std::sync::atomic::AtomicU64,
    /// Events dropped because a guest's input queue was full, i.e. its pump
    /// stopped draining. Counted rather than logged: this is the hot path.
    pub guest_dropped: std::sync::atomic::AtomicU64,
}

impl Stats {
    /// avg_us, count, max_us - and reset.
    pub fn take(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.age_n.swap(0, Relaxed);
        (self.age_sum_us.swap(0, Relaxed), n, self.age_max_us.swap(0, Relaxed))
    }
}

/// One head's guest image: where it is on the host, and what it is in the
/// guest. Everything needed to turn a host pointer position into a point in
/// the guest's desktop, for the one head the pointer happens to be over.
#[derive(Clone, Copy, Default, Debug)]
pub struct GuestArea {
    /// The guest image on the host, in combined host pixels: x, y, w, h.
    pub view: (f32, f32, f32, f32),
    /// The scanout the guest renders for this head.
    pub size: (u32, u32),
    /// Where that scanout sits in the guest's own desktop - the offsets we
    /// gave it in `SetUIInfo`, which is the only layout either side knows.
    pub off: (u32, u32),
}

#[derive(Default)]
pub struct State {
    pub x: f64,
    pub y: f64,
    pub focus_guest: bool,
    /// The active guest's pointer is relative. Published by the render loop
    /// from what the guest pump read off QEMU's IsAbsolute.
    pub relative: bool,
    /// One per head, in head order. Empty until the render loop has drawn.
    pub areas: Vec<GuestArea>,
    /// The guest's whole desktop: the bounding box of every `area.off+size`.
    pub desktop: (u32, u32),
    /// Chrome drawn ON TOP of the guest, in host pixels. The guest does not
    /// get pointer buttons here even while it holds the pointer.
    pub chrome: Option<(f32, f32, f32, f32)>,
    pub egui_events: Vec<egui::Event>,
    pub want_tab: Option<usize>,
    /// Ctrl+Alt+F was pressed; the render loop toggles fullscreen and clears it.
    pub want_fullscreen: bool,
}

/// Handle held by the render loop. The input thread blocks on the libinput fd
/// and forwards guest input itself, so guest input latency is independent of
/// our frame rate - polling libinput once per frame added up to a frame of lag.
pub struct Handle {
    pub stats: std::sync::Arc<Stats>,
    /// The area the pointer may move in, packed as `w << 32 | h`. Shared
    /// rather than owned because the input thread blocks in `poll()` and a
    /// monitor can be plugged in while it is asleep.
    bounds: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub state: std::sync::Arc<std::sync::Mutex<State>>,
    pub active_tx: std::sync::Arc<std::sync::Mutex<Option<std::sync::mpsc::SyncSender<GuestAct>>>>,
    /// Write side of the eventfd that wakes the thread's `poll()` for
    /// shutdown; see `shutdown()`.
    shutdown_fd: std::os::unix::io::RawFd,
    join: std::thread::JoinHandle<()>,
}

impl Handle {
    /// A head changed size or went away: keep the pointer inside the panel.
    pub fn set_bounds(&self, w: i32, h: i32) {
        self.bounds.store(
            ((w.max(1) as u64) << 32) | h.max(1) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub fn set_active(&self, tx: std::sync::mpsc::SyncSender<GuestAct>) {
        *self.active_tx.lock().unwrap() = Some(tx);
    }

    /// No guest owns the keyboard and pointer: events go nowhere rather than
    /// to whichever VM happens to sit at the old index.
    pub fn clear_active(&self) {
        *self.active_tx.lock().unwrap() = None;
    }

    /// Stop the input thread and wait for it, so libinput's context - and
    /// every `/dev/input/event*` fd it opened directly, with no udev to do it
    /// for us - is closed before this returns. Must run before the process
    /// calls `spawn` again (e.g. switching back to the GUI after a stint in
    /// text mode), or the same devices get opened a second time.
    pub fn shutdown(self) {
        let one: u64 = 1;
        let ptr = &one as *const u64 as *const libc::c_void;
        if unsafe { libc::write(self.shutdown_fd, ptr, 8) } < 0 {
            log::warn!("input: shutdown signal: {}", std::io::Error::last_os_error());
        }
        if self.join.join().is_err() {
            log::warn!("input: thread panicked while shutting down");
        }
        unsafe { libc::close(self.shutdown_fd) };
    }
}

/// Start the input thread. It owns libinput until `Handle::shutdown` is
/// called.
pub fn spawn(w: i32, h: i32, scale: f64) -> anyhow::Result<Handle> {
    let state = std::sync::Arc::new(std::sync::Mutex::new(State {
        x: w as f64 / 2.0, y: h as f64 / 2.0,
        // Empty until the render loop publishes a real guest viewport. Not the
        // whole screen: in_view() drives click-to-grab, and a full-screen
        // default means any click grabs into a guest that may not exist - the
        // pointer then routes nowhere and looks like it vanished, with no way
        // back except the release chord.
        ..Default::default()
    }));
    let active_tx: std::sync::Arc<std::sync::Mutex<Option<std::sync::mpsc::SyncSender<GuestAct>>>> =
        Default::default();
    let stats: std::sync::Arc<Stats> = Default::default();
    let bounds = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
        ((w.max(1) as u64) << 32) | h.max(1) as u64,
    ));
    let bnd = bounds.clone();
    let st = state.clone();
    let tx = active_tx.clone();
    // Paste as keystrokes into whichever guest has the keyboard.
    crate::gui::typist::spawn(active_tx.clone());
    let sts = stats.clone();
    // Wakes the poll() below on shutdown; libinput's own fd carries the real
    // events and an infinite poll timeout otherwise never notices a request
    // to stop.
    let shutdown_fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
    if shutdown_fd < 0 {
        return Err(anyhow::anyhow!("input: eventfd: {}", std::io::Error::last_os_error()));
    }
    let join = std::thread::Builder::new().name("input".into()).spawn(move || {
        // libinput's context holds raw pointers and an Rc, so it is not Send:
        // it must be CREATED on this thread, not moved in.
        let mut inp = match Input::new(w, h) {
            Ok(i) => i,
            Err(e) => { log::error!("input thread: {e}"); return; }
        };
        inp.scale = scale;
        inp.stats = sts;
        inp.bounds = bnd;
        let fd = inp.fd();
        let hotplug_fd = inp.hotplug_fd();
        loop {
            // BLOCK until the kernel has something, or a shutdown is
            // requested. No timeout, no polling: the thread sleeps and wakes
            // on the event itself.
            let mut pfds = [
                libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: shutdown_fd, events: libc::POLLIN, revents: 0 },
                libc::pollfd { fd: hotplug_fd, events: libc::POLLIN, revents: 0 },
            ];
            if unsafe { libc::poll(pfds.as_mut_ptr(), 3, -1) } < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted { continue; }
                // Anything else is permanent (a bad fd after device teardown);
                // retrying would spin a core for the life of the process.
                log::error!("input: poll failed: {e}; input thread stopping");
                return;
            }
            if pfds[1].revents & libc::POLLIN != 0 {
                log::info!("input: shutdown requested; closing libinput");
                return; // drops `inp` here, closing every device fd it opened
            }
            if pfds[2].revents & libc::POLLIN != 0 {
                inp.handle_hotplug();
            }
            inp.take_bounds();
            inp.pump(crate::gui::points_per_pixel());
            // forward to the guest IMMEDIATELY, at device rate
            if !inp.guest.is_empty() {
                if let Some(t) = tx.lock().unwrap().as_ref() {
                    // try_send, never send: the queue is bounded, and blocking
                    // here on a guest whose pump has wedged would stall input
                    // for the host UI and every other tab too.
                    use std::sync::atomic::Ordering::Relaxed;
                    for a in inp.guest.drain(..) {
                        if t.try_send(a).is_err() { inp.stats.guest_dropped.fetch_add(1, Relaxed); }
                    }
                } else { inp.guest.clear(); }
            }
            // publish what the render loop needs
            let mut s = st.lock().unwrap();
            // The render loop sleeps until something changes; this is a
            // change only if it moves something it draws. A grabbed relative
            // pointer leaves x and y frozen, so guest motion wakes nothing.
            if s.x != inp.x || s.y != inp.y || s.focus_guest != (inp.focus == Focus::Guest)
                || !inp.egui_events.is_empty() || inp.want_tab.is_some() || inp.want_fullscreen
            {
                crate::gui::wake::wake();
            }
            s.x = inp.x; s.y = inp.y;
            s.focus_guest = inp.focus == Focus::Guest;
            s.egui_events.append(&mut inp.egui_events);
            if let Some(t) = inp.want_tab.take() { s.want_tab = Some(t); }
            if std::mem::take(&mut inp.want_fullscreen) { s.want_fullscreen = true; }
            // render loop publishes these back
            inp.areas.clear();
            inp.areas.extend_from_slice(&s.areas);
            inp.desktop = s.desktop;
            inp.chrome = s.chrome;
            inp.relative = s.relative;
        }
    })?;
    Ok(Handle { stats, bounds, state, active_tx, shutdown_fd, join })
}

pub struct Input {
    li: Libinput,
    pub focus: Focus,
    pub x: f64,
    pub y: f64,
    w: f64,
    h: f64,
    ctrl: bool,
    alt: bool,
    last_toggle: Option<std::time::Instant>,
    /// Set when a grabbing click was consumed, so its release is too.
    swallow_release: Option<u32>,
    /// Sub-detent scroll remainder, v120 units (120 = one wheel click).
    scroll_acc: (f64, f64),
    /// Devices that have sent absolute motion. Only THOSE devices get their
    /// relative events ignored - a global flag also killed the physical mouse.
    abs_devices: std::collections::HashSet<String>,
    /// See `State::relative`. While grabbed into a relative guest, motion
    /// goes out as raw deltas and the host pointer stays where it is.
    relative: bool,
    /// Sub-count remainder of scaled relative motion.
    rel_acc: (f64, f64),
    /// Last position from an absolute device, to turn it into deltas for a
    /// relative guest.
    abs_last: Option<(f64, f64)>,
    scale: f64,
    /// See `Handle::bounds`.
    bounds: std::sync::Arc<std::sync::atomic::AtomicU64>,
    stats: std::sync::Arc<Stats>,
    /// Keys currently held down IN THE GUEST, so we can release them on
    /// ungrab - otherwise Ctrl/Alt stay stuck down in the guest.
    held: std::collections::HashSet<u32>,
    pub egui_events: Vec<egui::Event>,
    pub guest: Vec<GuestAct>,
    /// One per head: the guest image on screen and what it maps to.
    pub areas: Vec<GuestArea>,
    pub desktop: (u32, u32),
    pub chrome: Option<(f32, f32, f32, f32)>,
    /// Tab the user asked for via Ctrl+Alt+N; consumed by the caller.
    pub want_tab: Option<usize>,
    /// Ctrl+Alt+F, consumed by the caller.
    pub want_fullscreen: bool,
    abs_n: u64,
    /// inotify on /dev/input. usbhid is a module (CONFIG_USB_HID=m) and lands
    /// ~24s into boot, long after this process starts, so a one-shot scan of
    /// /dev/input finds the ACPI buttons and nothing else - no keyboard, no
    /// mouse, forever, because the path backend has no udev to tell it about
    /// devices that appear later.
    inotify_fd: RawFd,
    /// Every node we handed to libinput, so a node that goes away can be
    /// handed back. path_remove_device needs the Device, not the path.
    devices: HashMap<PathBuf, li::Device>,
}

/// inotify_event has 4-byte alignment; a bare [u8; N] on the stack does not
/// promise that, and we cast straight into it.
#[repr(C, align(8))]
struct InotifyBuf([u8; 4096]);

impl Drop for Input {
    fn drop(&mut self) {
        // The libinput context closes the device fds itself; the watch is ours.
        unsafe { libc::close(self.inotify_fd) };
    }
}

impl Input {
    /// Adopt a head set that changed under us, clamping the pointer into it.
    /// A pointer left outside the panel is invisible and cannot be recovered
    /// with the mouse, only by unplugging the monitor that was removed.
    fn take_bounds(&mut self) {
        let v = self.bounds.load(std::sync::atomic::Ordering::Relaxed);
        let (w, h) = ((v >> 32) as f64, (v & 0xFFFF_FFFF) as f64);
        if (w, h) == (self.w, self.h) {
            return;
        }
        log::info!("input: area {}x{} -> {w}x{h}", self.w, self.h);
        self.w = w;
        self.h = h;
        self.x = self.x.min(w - 1.0).max(0.0);
        self.y = self.y.min(h - 1.0).max(0.0);
    }

    pub fn new(w: i32, h: i32) -> anyhow::Result<Self> {
        let li = Libinput::new_from_path(Iface);

        // Watch BEFORE the initial scan. The other order has a hole: a node
        // created between the scan and the watch is in neither, and stays
        // invisible until the process restarts.
        let inotify_fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if inotify_fd < 0 {
            return Err(anyhow::anyhow!("input: inotify_init1: {}", std::io::Error::last_os_error()));
        }
        let dir = std::ffi::CString::new("/dev/input").unwrap();
        let mask = libc::IN_CREATE | libc::IN_DELETE | libc::IN_MOVED_TO | libc::IN_MOVED_FROM;
        if unsafe { libc::inotify_add_watch(inotify_fd, dir.as_ptr(), mask) } < 0 {
            let e = std::io::Error::last_os_error();
            unsafe { libc::close(inotify_fd) };
            return Err(anyhow::anyhow!("input: watching /dev/input: {e}"));
        }

        let mut me = Self {
            li, focus: Focus::Gui, x: w as f64 / 2.0, y: h as f64 / 2.0,
            w: w as f64, h: h as f64, ctrl: false, alt: false, last_toggle: None, swallow_release: None, scroll_acc: (0.0, 0.0), abs_devices: Default::default(),
            relative: false, rel_acc: (0.0, 0.0), abs_last: None,
            scale: std::env::var("GUI_PTR_SCALE").ok()
                     .and_then(|v| v.parse().ok()).unwrap_or(1.0),
            bounds: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                ((w.max(1) as u64) << 32) | h.max(1) as u64,
            )),
            stats: Default::default(),
            held: Default::default(),
            egui_events: Vec::new(), guest: Vec::new(),
            areas: Vec::new(), desktop: (0, 0), chrome: None, abs_n: 0, want_tab: None,
            want_fullscreen: false,
            inotify_fd, devices: HashMap::new(),
        };

        let mut seen = 0;
        for e in std::fs::read_dir("/dev/input")? {
            let p = e?.path();
            if is_event_node(&p) {
                seen += 1;
                me.try_add(&p);
            }
        }
        let n = me.devices.len();
        if n == 0 && seen > 0 {
            log::error!("libinput: no input devices usable out of {seen} event node(s) - waiting for hotplug");
        } else if seen == 0 {
            log::error!("libinput: /dev/input has no event nodes - waiting for hotplug");
        }
        log::info!("libinput: {n}/{seen} device(s) opened directly (no udev/logind/seat)");
        log::info!("pointer: raw 1:1, scale {}",
                 std::env::var("GUI_PTR_SCALE").unwrap_or_else(|_| "1.0".into()));
        Ok(me)
    }

    /// The fd to poll for device arrivals and departures.
    pub fn hotplug_fd(&self) -> RawFd { self.inotify_fd }

    /// Hand one node to libinput. Quiet about nodes we already hold, so a
    /// duplicate inotify event is harmless.
    fn try_add(&mut self, p: &Path) {
        if self.devices.contains_key(p) { return; }
        // libinput hands back a bare None when it refuses a device and its own
        // diagnostics go nowhere unless a log handler is installed, so probe
        // the node ourselves first: that separates "we cannot open it"
        // (namespace, permissions) from "libinput refused it" (its own device
        // checks), which otherwise look identical from here.
        if let Err(err) = std::fs::File::open(p) {
            log::warn!("libinput: {} not openable: {err}", p.display());
            return;
        }
        match self.li.path_add_device(&p.to_string_lossy()) {
            Some(d) => { self.devices.insert(p.to_path_buf(), d); }
            None => log::warn!("libinput: refused {} (opened fine, libinput said no)", p.display()),
        }
    }

    fn try_remove(&mut self, p: &Path) {
        if let Some(d) = self.devices.remove(p) {
            log::info!("libinput: {} went away", p.display());
            self.li.path_remove_device(d);
        }
    }

    /// Drain inotify and add or drop devices. Called when `hotplug_fd` polls
    /// readable; the fd is non-blocking, so this returns once drained.
    pub fn handle_hotplug(&mut self) {
        const HDR: usize = std::mem::size_of::<libc::inotify_event>();
        let mut buf = InotifyBuf([0u8; 4096]);
        loop {
            let got = unsafe {
                libc::read(self.inotify_fd, buf.0.as_mut_ptr() as *mut libc::c_void, buf.0.len())
            };
            if got <= 0 { return; }          // EAGAIN once drained
            let got = got as usize;
            let mut off = 0usize;
            while off + HDR <= got {
                // SAFETY: the kernel writes whole inotify_event records, and
                // InotifyBuf is aligned for them.
                let ev = unsafe { &*(buf.0.as_ptr().add(off) as *const libc::inotify_event) };
                let (mask, len) = (ev.mask, ev.len as usize);
                let name = buf.0.get(off + HDR..off + HDR + len).and_then(|nb| {
                    let end = nb.iter().position(|&c| c == 0).unwrap_or(nb.len());
                    std::str::from_utf8(&nb[..end]).ok().map(str::to_owned)
                });
                off += HDR + len;
                let Some(name) = name else { continue };
                let path = PathBuf::from("/dev/input").join(&name);
                if !is_event_node(&path) { continue; }
                if mask & (libc::IN_CREATE | libc::IN_MOVED_TO) != 0 {
                    let before = self.devices.len();
                    self.try_add(&path);
                    if self.devices.len() > before {
                        log::info!("libinput: {} appeared, now {} device(s)",
                                   path.display(), self.devices.len());
                    }
                } else if mask & (libc::IN_DELETE | libc::IN_MOVED_FROM) != 0 {
                    self.try_remove(&path);
                }
            }
        }
    }

    pub fn fd(&self) -> i32 { self.li.as_raw_fd() }

    /// The head whose guest image the pointer is over, if any.
    fn area_at(&self, x: f32, y: f32) -> Option<&GuestArea> {
        self.areas.iter().find(|a| {
            let (vx, vy, vw, vh) = a.view;
            // A head with no scanout yet is not a place to grab into: a tab
            // can exist before its guest has produced a frame, and a click
            // there used to route the pointer nowhere.
            a.size != (0, 0)
                && vw > 0.0
                && vh > 0.0
                && x >= vx && x < vx + vw && y >= vy && y < vy + vh
        })
    }

    /// Map host cursor -> what to hand `SetAbsPosition`.
    ///
    /// The guest has ONE absolute pointer covering its whole desktop, however
    /// many monitors it has, and QEMU scales whatever we send by the width of
    /// the console we send it on. So the answer is a point in the guest's
    /// DESKTOP, expressed as a fraction and then rescaled into console 0's
    /// pixel range - not a point in the scanout under the cursor, which would
    /// sweep the entire desktop across one monitor.
    ///
    /// With one head this is the identity it always was: the desktop is that
    /// one scanout and the rescale cancels.
    fn to_guest(&self) -> Option<(u32, u32)> {
        let a = self.area_at(self.x as f32, self.y as f32)?;
        let (vx, vy, vw, vh) = a.view;
        let (gw, gh) = a.size;
        let (dw, dh) = self.desktop;
        // Console 0's scanout is the range SetAbsPosition accepts; it rejects
        // anything at or past its own width.
        let (cw, ch) = self.areas.first().map_or((0, 0), |c| c.size);
        if gw == 0 || gh == 0 || dw < 2 || dh < 2 || cw < 2 || ch < 2 {
            return None;
        }
        let rx = ((self.x as f32 - vx) / vw).clamp(0.0, 1.0);
        let ry = ((self.y as f32 - vy) / vh).clamp(0.0, 1.0);
        // Where the cursor is in the guest's desktop.
        let dx = a.off.0 as f32 + rx * (gw - 1) as f32;
        let dy = a.off.1 as f32 + ry * (gh - 1) as f32;
        // round, don't truncate: `as u32` floors, which biases every event
        // half a pixel toward the origin and makes the last row and column of
        // the guest unreachable.
        let sx = (dx / (dw - 1) as f32 * (cw - 1) as f32).round() as u32;
        let sy = (dy / (dh - 1) as f32 * (ch - 1) as f32).round() as u32;
        Some((sx.min(cw - 1), sy.min(ch - 1)))
    }

    pub fn pump(&mut self, ppp: f32) {
        let _ = self.li.dispatch();
        let events: Vec<_> = (&mut self.li).collect();
        for ev in events {
            match ev {
                li::Event::Pointer(p) => match p {
                    li::event::PointerEvent::Motion(m) => {
                        // Per device, not global: a composite device may report
                        // both relative and absolute and the two fight, but a
                        // global flag would also silence a plain mouse.
                        if self.abs_devices.contains(&dev_id(&m.device())) { continue; }
                        // RAW. libinput's accelerated dx() is useless here
                        // anyway (path backend, no udev, so no device DPI), but
                        // the curve we used instead was worse than nothing:
                        // velocity estimated from ONE event's delta/gap is very
                        // noisy, so the multiplier swung between 1.0 and 2.5
                        // within a single gesture. That was the "jumping".
                        // One mouse count = one host pixel, times GUI_PTR_SCALE.
                        let (rdx, rdy) = (m.dx_unaccelerated(), m.dy_unaccelerated());
                        // Three relaxed atomic ops. No lock, no allocation and
                        // above all no println: a stdout lock plus a write(2)
                        // here would be exactly the stall we are measuring.
                        use std::sync::atomic::Ordering::Relaxed;
                        let age = now_usec().saturating_sub(m.time_usec());
                        self.stats.age_sum_us.fetch_add(age, Relaxed);
                        self.stats.age_n.fetch_add(1, Relaxed);
                        self.stats.age_max_us.fetch_max(age, Relaxed);
                        if self.focus == Focus::Guest && self.relative {
                            // The guest owns its layout: hand it the counts
                            // and leave the host pointer where it is.
                            self.rel_acc.0 += rdx * self.scale;
                            self.rel_acc.1 += rdy * self.scale;
                            let (ix, iy) = (self.rel_acc.0.trunc(), self.rel_acc.1.trunc());
                            self.rel_acc.0 -= ix;
                            self.rel_acc.1 -= iy;
                            if ix != 0.0 || iy != 0.0 {
                                self.guest.push(GuestAct::RelMotion(ix as i32, iy as i32));
                            }
                            continue;
                        }
                        self.x = (self.x + rdx * self.scale).clamp(0.0, self.w - 1.0);
                        self.y = (self.y + rdy * self.scale).clamp(0.0, self.h - 1.0);
                        self.on_move(ppp);
                    }
                    li::event::PointerEvent::MotionAbsolute(m) => {
                        let id = dev_id(&m.device());
                        if self.abs_devices.insert(id.clone()) {
                            log::debug!("pointer: {id} reports absolute; ignoring ITS relative events");
                        }
                        let (nx, ny) = (m.absolute_x_transformed(self.w as u32),
                                        m.absolute_y_transformed(self.h as u32));
                        let last = self.abs_last.replace((nx, ny));
                        if self.focus == Focus::Guest && self.relative {
                            // A relative guest can only take deltas.
                            if let Some((lx, ly)) = last {
                                let (dx, dy) = ((nx - lx).round(), (ny - ly).round());
                                if dx != 0.0 || dy != 0.0 {
                                    self.guest.push(GuestAct::RelMotion(dx as i32, dy as i32));
                                }
                            }
                            continue;
                        }
                        self.x = nx;
                        self.y = ny;
                        self.on_move(ppp);
                    }

                    // The wheel was simply never handled: the match had Motion,
                    // MotionAbsolute and Button and nothing else, so scrolling
                    // did nothing at all in either the GUI or the guest.
                    li::event::PointerEvent::ScrollWheel(a) => {
                        use li::event::pointer::PointerScrollEvent;
                        // v120: 120 units per physical detent, so a hi-res
                        // wheel that reports fractions still works.
                        let dx = if a.has_axis(Axis::Horizontal) { a.scroll_value_v120(Axis::Horizontal) } else { 0.0 };
                        let dy = if a.has_axis(Axis::Vertical)   { a.scroll_value_v120(Axis::Vertical)   } else { 0.0 };
                        self.scroll(dx, dy);
                    }
                    li::event::PointerEvent::ScrollFinger(a) => {
                        use li::event::pointer::PointerScrollEvent;
                        // Touchpads report pixels; ~15px per line is the usual
                        // convention, and a detent is 120 v120 units.
                        let dx = if a.has_axis(Axis::Horizontal) { a.scroll_value(Axis::Horizontal) } else { 0.0 };
                        let dy = if a.has_axis(Axis::Vertical)   { a.scroll_value(Axis::Vertical)   } else { 0.0 };
                        self.scroll(dx * 8.0, dy * 8.0);
                    }
                    li::event::PointerEvent::ScrollContinuous(a) => {
                        use li::event::pointer::PointerScrollEvent;
                        let dx = if a.has_axis(Axis::Horizontal) { a.scroll_value(Axis::Horizontal) } else { 0.0 };
                        let dy = if a.has_axis(Axis::Vertical)   { a.scroll_value(Axis::Vertical)   } else { 0.0 };
                        self.scroll(dx * 8.0, dy * 8.0);
                    }
                    li::event::PointerEvent::Button(b) => {
                        let down = b.button_state() == ButtonState::Pressed;
                        // evdev BTN_LEFT=272,RIGHT=273,MIDDLE=274 -> QEMU InputButton LEFT=0,MIDDLE=1,RIGHT=2
                        let q = match b.button() { 272 => Some(0u32), 273 => Some(2), 274 => Some(1), _ => None };
                        // Click inside the guest view GRABS, as in virt-manager
                        // and every other VM viewer. RightCtrl releases. A
                        // hidden-hotkey-only grab is undiscoverable.
                        // guest_size gates this as well as in_view: a tab can
                        // exist before its first scanout arrives, and grabbing
                        // into a guest with no image routes the pointer nowhere.
                        if self.focus == Focus::Gui && down && q == Some(0)
                            && self.in_view() {
                            self.focus = Focus::Guest;
                            // Nothing may be held from a previous grab, and
                            // the guest may still hold keys we never saw
                            // released. Tell it about both.
                            self.release_modifiers();
                            self.held.clear();
                            log::debug!("focus -> Guest (clicked in guest view)");
                            self.swallow_release = q;
                            continue;   // consume the grabbing click
                        }
                        // The press that grabbed was consumed, so its release
                        // must be too - otherwise the guest sees an unpaired
                        // button-up and drag tracking gets confused.
                        if !down && self.swallow_release == q && q.is_some() {
                            self.swallow_release = None;
                            continue;
                        }
                        match self.focus {
                            // A relative guest's host pointer is frozen and
                            // invisible, so it must not be hit-tested against
                            // the chrome: every click belongs to the guest.
                            Focus::Guest if q.is_some() && (self.relative || !self.in_chrome()) => {
                                self.guest.push(GuestAct::Btn(q.unwrap(), down))
                            }
                            _ => {
                                let eb = match b.button() {
                                    272 => egui::PointerButton::Primary,
                                    273 => egui::PointerButton::Secondary,
                                    _ => egui::PointerButton::Middle,
                                };
                                self.egui_events.push(egui::Event::PointerButton {
                                    pos: egui::pos2(self.x as f32 / ppp, self.y as f32 / ppp),
                                    button: eb, pressed: down,
                                    modifiers: self.mods(),
                                });
                            }
                        }
                    }
                    _ => {}
                },
                li::Event::Keyboard(k) => {
                    let code = k.key();
                    let down = k.key_state() == KeyState::Pressed;
                    log::debug!("KEY code={code} down={down} focus={:?}", self.focus);
                    // Modifier state (both sides). These ARE forwarded to the
                    // guest - it needs its own Ctrl/Alt, and Ctrl+Alt+Del must
                    // reach a Windows logon screen intact. vt::CtrlAltDelGuard
                    // stops the kernel rebooting on Ctrl+Alt+Del; we see the
                    // keys regardless, because libinput reads evdev and does
                    // not care what the VT layer does with its copy
                    // chords itself (it used to reboot the host on Ctrl+Alt+Del
                    // and VT-switch on Ctrl+Alt+Fn).
                    match code {
                        29 | 97 => self.ctrl = down,     // L/R CTRL
                        56 | 100 => self.alt = down,     // L/R ALT
                        _ => {}
                    }
                    // Ctrl+Alt+G releases/grabs, debounced on time, never
                    // latched. Ctrl+Alt+1..9 switches tab and works WHILE
                    // GRABBED - otherwise the tab bar is unreachable without
                    // releasing first. Everything else in the Ctrl+Alt space,
                    // Del included, is forwarded untouched.
                    if down && self.ctrl && self.alt && (2..=10).contains(&code) {
                        self.want_tab = Some((code - 2) as usize);
                        self.release_held();   // no stuck modifiers in the old VM
                        self.release_modifiers();
                        continue;
                    }
                    if code == 33 && down && self.ctrl && self.alt {
                        self.want_fullscreen = true;
                        self.release_held();
                        self.release_modifiers();
                        continue;
                    }
                    if code == 34 && down && self.ctrl && self.alt {
                        let now = std::time::Instant::now();
                        if self.last_toggle.map_or(true, |t| now.duration_since(t).as_millis() > 250) {
                            self.last_toggle = Some(now);
                            if self.focus == Focus::Guest { self.release_held(); }
                            self.release_modifiers();
                            self.focus = match self.focus { Focus::Gui => Focus::Guest, _ => Focus::Gui };
                            log::debug!("focus -> {:?} (ctrl+alt+g)", self.focus);
                        }
                        continue;   // never forwarded
                    }
                    if self.focus == Focus::Guest {
                        if down {
                            // A second press with no release in between means
                            // the release never reached us - seen with Meta
                            // from a KVM's HID, where the key-up is simply
                            // absent. Without this the guest holds the
                            // modifier for ever and the next letter becomes a
                            // chord: "powershell" typed after a Meta tap
                            // fired Win+E, Win+R and finally Win+L, locking
                            // the box.
                            if !self.held.insert(code) {
                                log::debug!("key {code}: pressed while still held; releasing first");
                                self.guest.push(GuestAct::Key(code, false));
                            }
                        } else {
                            self.held.remove(&code);
                        }
                        self.guest.push(GuestAct::Key(code, down));
                    }
                }
                _ => {}
            }
        }
    }

    /// Send key-up for every modifier, held or not, so the guest cannot be
    /// left with one latched by a release that never arrived. Cheap: eight
    /// key-ups, and a key-up for a key that is already up is a no-op in every
    /// guest OS.
    fn release_modifiers(&mut self) {
        // L/R: ctrl, shift, alt, meta.
        for code in [29u32, 97, 42, 54, 56, 100, 125, 126] {
            self.held.remove(&code);
            self.guest.push(GuestAct::Key(code, false));
        }
    }

    /// Send key-up for everything we told the guest was held. Without this the
    /// guest keeps Ctrl and Alt pressed after Ctrl+Alt+G.
    fn release_held(&mut self) {
        let keys: Vec<u32> = self.held.drain().collect();
        for k in keys { self.guest.push(GuestAct::Key(k, false)); }
    }

    /// Is the host pointer over the guest image?
    fn in_view(&self) -> bool {
        self.area_at(self.x as f32, self.y as f32).is_some()
    }

    /// Is the pointer over chrome we drew on top of the guest? That chrome
    /// wins over the guest's grab: the fullscreen exit button lives there,
    /// and a grab the operator cannot click their way out of is a trap.
    fn in_chrome(&self) -> bool {
        let Some((cx, cy, cw, ch)) = self.chrome else { return false };
        let (x, y) = (self.x as f32, self.y as f32);
        x >= cx && x < cx + cw && y >= cy && y < cy + ch
    }

    /// While grabbed, keep the pointer inside the guest image. Otherwise it can
    /// sit in the top bar or the letterbox margin, to_guest() returns None, and
    /// the guest cursor silently stops following - it looks like it vanished.
    fn clamp_to_view(&mut self) {
        if self.focus != Focus::Guest || self.areas.is_empty() {
            return;
        }
        // Already over one head's guest image: nothing to do, and in
        // particular do NOT pull it back to some other head's rect.
        if self.in_view() {
            return;
        }
        // Outside every one: clamp into the nearest, by centre distance.
        let (x, y) = (self.x as f32, self.y as f32);
        let nearest = self
            .areas
            .iter()
            .filter(|a| a.view.2 > 0.0 && a.view.3 > 0.0)
            .min_by(|a, b| {
                let d = |v: (f32, f32, f32, f32)| {
                    let (cx, cy) = (v.0 + v.2 / 2.0, v.1 + v.3 / 2.0);
                    (x - cx).powi(2) + (y - cy).powi(2)
                };
                d(a.view).total_cmp(&d(b.view))
            });
        let Some(a) = nearest else { return };
        let (vx, vy, vw, vh) = a.view;
        self.x = self.x.clamp(vx as f64, (vx + vw - 1.0) as f64);
        self.y = self.y.clamp(vy as f64, (vy + vh - 1.0) as f64);
    }

    fn on_move(&mut self, ppp: f32) {
        self.clamp_to_view();
        match self.focus {
            Focus::Guest => { if let Some((gx, gy)) = self.to_guest() {
                self.abs_n += 1;
                if self.abs_n % 30 == 1 {
                    let a = self.area_at(self.x as f32, self.y as f32);
                    log::info!(
                        "ABS host={:.0},{:.0} -> abs={gx},{gy}  view={:?} size={:?} off={:?} desktop={:?} c0={:?}",
                        self.x, self.y,
                        a.map(|a| a.view), a.map(|a| a.size), a.map(|a| a.off),
                        self.desktop,
                        self.areas.first().map(|c| c.size),
                    );
                }
                self.guest.push(GuestAct::AbsPos(gx, gy)); } }
            Focus::Gui => {
                self.egui_events.push(egui::Event::PointerMoved(
                    egui::pos2(self.x as f32 / ppp, self.y as f32 / ppp)));
                // Ungrabbed, we still forward POSITION (never buttons or keys)
                // while the pointer is over the guest. The guest has a USB
                // tablet, so its own cursor then tracks ours and we do not draw
                // a second one on top of it - previously the guest's cursor
                // froze wherever the last grab left it and we painted an arrow
                // somewhere else, so the screen showed two pointers.
                if self.in_view() {
                    if let Some((gx, gy)) = self.to_guest() {
                        self.guest.push(GuestAct::AbsPos(gx, gy));
                    }
                }
            }
        }
    }

    /// Feed scroll deltas in v120 units (120 = one wheel detent).
    ///
    /// QEMU has no scroll axis: the wheel is expressed as button clicks on
    /// InputButton WHEEL_UP=3 / WHEEL_DOWN=4 / WHEEL_LEFT=7 / WHEEL_RIGHT=8,
    /// each a press followed by a release. So we accumulate and emit one click
    /// per whole detent, keeping the remainder for hi-res wheels.
    fn scroll(&mut self, dx120: f64, dy120: f64) {
        if self.focus == Focus::Gui {
            // egui wants lines, and its Y is positive-up where libinput is
            // positive-down.
            self.egui_events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Line,
                delta: egui::vec2(-dx120 as f32 / 120.0, -dy120 as f32 / 120.0),
                modifiers: self.mods(),
            });
            return;
        }
        log::trace!("scroll v120 dx={dx120} dy={dy120} acc={:?}", self.scroll_acc);
        self.scroll_acc.0 += dx120;
        self.scroll_acc.1 += dy120;
        for _ in 0..(self.scroll_acc.1.abs() / 120.0) as i32 {
            let b = if self.scroll_acc.1 > 0.0 { 4 } else { 3 };   // down : up
            self.guest.push(GuestAct::Btn(b, true));
            self.guest.push(GuestAct::Btn(b, false));
            self.scroll_acc.1 -= 120.0 * self.scroll_acc.1.signum();
        }
        for _ in 0..(self.scroll_acc.0.abs() / 120.0) as i32 {
            let b = if self.scroll_acc.0 > 0.0 { 8 } else { 7 };   // right : left
            self.guest.push(GuestAct::Btn(b, true));
            self.guest.push(GuestAct::Btn(b, false));
            self.scroll_acc.0 -= 120.0 * self.scroll_acc.0.signum();
        }
    }

    fn mods(&self) -> egui::Modifiers {
        egui::Modifiers { alt: self.alt, ctrl: self.ctrl, shift: false,
                          mac_cmd: false, command: self.ctrl }
    }
}
