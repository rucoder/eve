// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! THROWAWAY SPIKE — libinput capture and routing (GUI <-> guest).
//! Opens /dev/input/event* directly as root: no udev, no logind, no seat.

use std::fs::{File, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

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
    AbsPos(u32, u32),
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
}

impl Stats {
    /// avg_us, count, max_us - and reset.
    pub fn take(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        let n = self.age_n.swap(0, Relaxed);
        (self.age_sum_us.swap(0, Relaxed), n, self.age_max_us.swap(0, Relaxed))
    }
}

#[derive(Default)]
pub struct State {
    pub x: f64,
    pub y: f64,
    pub focus_guest: bool,
    pub view: (f32, f32, f32, f32),
    pub guest_size: (u32, u32),
    pub egui_events: Vec<egui::Event>,
    pub want_tab: Option<usize>,
}

/// Handle held by the render loop. The input thread blocks on the libinput fd
/// and forwards guest input itself, so guest input latency is independent of
/// our frame rate - polling libinput once per frame added up to a frame of lag.
pub struct Handle {
    pub stats: std::sync::Arc<Stats>,
    pub state: std::sync::Arc<std::sync::Mutex<State>>,
    pub active_tx: std::sync::Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<GuestAct>>>>,
}

impl Handle {
    pub fn set_active(&self, tx: std::sync::mpsc::Sender<GuestAct>) {
        *self.active_tx.lock().unwrap() = Some(tx);
    }
}

/// Start the input thread. It owns libinput and never returns.
pub fn spawn(w: i32, h: i32, scale: f64) -> anyhow::Result<Handle> {
    let state = std::sync::Arc::new(std::sync::Mutex::new(State {
        x: w as f64 / 2.0, y: h as f64 / 2.0,
        view: (0.0, 0.0, w as f32, h as f32),
        ..Default::default()
    }));
    let active_tx: std::sync::Arc<std::sync::Mutex<Option<std::sync::mpsc::Sender<GuestAct>>>> =
        Default::default();
    let stats: std::sync::Arc<Stats> = Default::default();
    let st = state.clone();
    let tx = active_tx.clone();
    let sts = stats.clone();
    std::thread::Builder::new().name("input".into()).spawn(move || {
        // libinput's context holds raw pointers and an Rc, so it is not Send:
        // it must be CREATED on this thread, not moved in.
        let mut inp = match Input::new(w, h) {
            Ok(i) => i,
            Err(e) => { log::error!("input thread: {e}"); return; }
        };
        inp.scale = scale;
        inp.stats = sts;
        let fd = inp.fd();
        loop {
            // BLOCK until the kernel has something. No timeout, no polling:
            // the thread sleeps and wakes on the event itself.
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut pfd, 1, -1) } < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted { continue; }
                // Anything else is permanent (a bad fd after device teardown);
                // retrying would spin a core for the life of the process.
                log::error!("input: poll failed: {e}; input thread stopping");
                return;
            }
            inp.pump(crate::POINTS_PER_PIXEL);
            // forward to the guest IMMEDIATELY, at device rate
            if !inp.guest.is_empty() {
                if let Some(t) = tx.lock().unwrap().as_ref() {
                    for a in inp.guest.drain(..) { let _ = t.send(a); }
                } else { inp.guest.clear(); }
            }
            // publish what the render loop needs
            let mut s = st.lock().unwrap();
            s.x = inp.x; s.y = inp.y;
            s.focus_guest = inp.focus == Focus::Guest;
            s.egui_events.append(&mut inp.egui_events);
            if let Some(t) = inp.want_tab.take() { s.want_tab = Some(t); }
            inp.view = s.view;            // render loop publishes these back
            inp.guest_size = s.guest_size;
        }
    })?;
    Ok(Handle { stats, state, active_tx })
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
    scale: f64,
    stats: std::sync::Arc<Stats>,
    /// Keys currently held down IN THE GUEST, so we can release them on
    /// ungrab - otherwise Ctrl/Alt stay stuck down in the guest.
    held: std::collections::HashSet<u32>,
    pub egui_events: Vec<egui::Event>,
    pub guest: Vec<GuestAct>,
    /// viewport of the guest image on screen: x, y, w, h (physical px)
    pub view: (f32, f32, f32, f32),
    pub guest_size: (u32, u32),
    /// Tab the user asked for via Ctrl+Alt+N; consumed by the caller.
    pub want_tab: Option<usize>,
    abs_n: u64,
}

impl Input {
    pub fn new(w: i32, h: i32) -> anyhow::Result<Self> {
        let mut li = Libinput::new_from_path(Iface);
        let mut n = 0;
        for e in std::fs::read_dir("/dev/input")? {
            let p = e?.path();
            if p.file_name().and_then(|s| s.to_str()).map_or(false, |s| s.starts_with("event")) {
                if li.path_add_device(p.to_str().unwrap()).is_some() { n += 1; }
            }
        }
        log::info!("libinput: {n} device(s) opened directly (no udev/logind/seat)");
        log::info!("pointer: raw 1:1, scale {}",
                 std::env::var("GUI_PTR_SCALE").unwrap_or_else(|_| "1.0".into()));
        Ok(Self {
            li, focus: Focus::Gui, x: w as f64 / 2.0, y: h as f64 / 2.0,
            w: w as f64, h: h as f64, ctrl: false, alt: false, last_toggle: None, swallow_release: None, scroll_acc: (0.0, 0.0), abs_devices: Default::default(),
            scale: std::env::var("GUI_PTR_SCALE").ok()
                     .and_then(|v| v.parse().ok()).unwrap_or(1.0),
            stats: Default::default(),
            held: Default::default(),
            egui_events: Vec::new(), guest: Vec::new(),
            view: (0.0, 0.0, w as f32, h as f32), guest_size: (0, 0), abs_n: 0, want_tab: None,
        })
    }

    pub fn fd(&self) -> i32 { self.li.as_raw_fd() }

    /// Map host cursor -> guest framebuffer coordinates.
    fn to_guest(&self) -> Option<(u32, u32)> {
        let (vx, vy, vw, vh) = self.view;
        let (gw, gh) = self.guest_size;
        if gw == 0 || vw <= 0.0 || vh <= 0.0 { return None; }
        let rx = (self.x as f32 - vx) / vw;
        let ry = (self.y as f32 - vy) / vh;
        if !(0.0..=1.0).contains(&rx) || !(0.0..=1.0).contains(&ry) { return None; }
        // round, don't truncate: `as u32` floors, which biases every event
        // half a pixel toward the origin and makes the last row and column of
        // the guest unreachable.
        Some(((rx * (gw - 1) as f32).round() as u32,
              (ry * (gh - 1) as f32).round() as u32))
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
                        self.x = (self.x + rdx * self.scale).clamp(0.0, self.w - 1.0);
                        self.y = (self.y + rdy * self.scale).clamp(0.0, self.h - 1.0);
                        self.on_move(ppp);
                    }
                    li::event::PointerEvent::MotionAbsolute(m) => {
                        let id = dev_id(&m.device());
                        if self.abs_devices.insert(id.clone()) {
                            log::debug!("pointer: {id} reports absolute; ignoring ITS relative events");
                        }
                        self.x = m.absolute_x_transformed(self.w as u32);
                        self.y = m.absolute_y_transformed(self.h as u32);
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
                        if self.focus == Focus::Gui && down && q == Some(0)
                            && self.in_view() {
                            self.focus = Focus::Guest;
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
                            Focus::Guest if q.is_some() => self.guest.push(GuestAct::Btn(q.unwrap(), down)),
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
                    // reach a Windows logon screen intact. main::VtKeyboard puts
                    // the VT in K_OFF so the kernel no longer acts on those
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
                        continue;
                    }
                    if code == 34 && down && self.ctrl && self.alt {
                        let now = std::time::Instant::now();
                        if self.last_toggle.map_or(true, |t| now.duration_since(t).as_millis() > 250) {
                            self.last_toggle = Some(now);
                            if self.focus == Focus::Guest { self.release_held(); }
                            self.focus = match self.focus { Focus::Gui => Focus::Guest, _ => Focus::Gui };
                            log::debug!("focus -> {:?} (ctrl+alt+g)", self.focus);
                        }
                        continue;   // never forwarded
                    }
                    if self.focus == Focus::Guest {
                        if down { self.held.insert(code); } else { self.held.remove(&code); }
                        self.guest.push(GuestAct::Key(code, down));
                    }
                }
                _ => {}
            }
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
        let (vx, vy, vw, vh) = self.view;
        let (x, y) = (self.x as f32, self.y as f32);
        vw > 0.0 && vh > 0.0 && x >= vx && x < vx + vw && y >= vy && y < vy + vh
    }

    /// While grabbed, keep the pointer inside the guest image. Otherwise it can
    /// sit in the top bar or the letterbox margin, to_guest() returns None, and
    /// the guest cursor silently stops following - it looks like it vanished.
    fn clamp_to_view(&mut self) {
        if self.focus != Focus::Guest { return; }
        let (vx, vy, vw, vh) = self.view;
        if vw <= 0.0 || vh <= 0.0 { return; }
        self.x = self.x.clamp(vx as f64, (vx + vw - 1.0) as f64);
        self.y = self.y.clamp(vy as f64, (vy + vh - 1.0) as f64);
    }

    fn on_move(&mut self, ppp: f32) {
        self.clamp_to_view();
        match self.focus {
            Focus::Guest => { if let Some((gx, gy)) = self.to_guest() {
                self.abs_n += 1;
                if self.abs_n % 30 == 1 {
                    log::debug!("ABS host={:.0},{:.0} -> guest={gx},{gy} (view {:.0},{:.0} {:.0}x{:.0} gs={}x{})",
                             self.x, self.y, self.view.0, self.view.1, self.view.2, self.view.3,
                             self.guest_size.0, self.guest_size.1);
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
        log::debug!("scroll v120 dx={dx120} dy={dy120} acc={:?}", self.scroll_acc);
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
