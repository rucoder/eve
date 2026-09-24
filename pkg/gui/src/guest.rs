// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! THROWAWAY SPIKE — QEMU D-Bus display listener feeding a shared RGBA frame.

use std::os::fd::{AsFd, OwnedFd};
#[allow(unused_imports)]
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use zbus::interface;
use zvariant::Fd;

#[derive(Default)]
pub struct GuestFrame {
    pub w: u32,
    pub h: u32,
    pub rgba: Vec<u8>,
    pub seq: u64,
    /// Region changed since the consumer last looked: x, y, w, h.
    pub dirty: Option<(u32, u32, u32, u32)>,
    /// Zero-copy path: a scanout dmabuf handed over by QEMU (virgl / gl=on).
    pub dmabuf: Option<GuestDmabuf>,
    /// Hardware cursor from QEMU (Windows uses one; it never appears in the
    /// framebuffer, so we must draw it ourselves).
    pub cursor: Option<GuestCursor>,
    pub cursor_seq: u64,
    pub cursor_visible: bool,
    /// Updates that arrived while we have never been given a scanout. QEMU
    /// only sends Scanout/ScanoutDMABUF when it has a live surface, so if the
    /// guest's display is blanked at the moment our listener registers we get
    /// none - and every later Update refers to a buffer we never received.
    /// The screen then stays black forever while the update counter looks
    /// healthy. Surfaced in the UI so it is diagnosable instead of mystifying.
    pub orphan_updates: u64,
    /// Set when a plain Scanout arrives, meaning the guest has gone back to
    /// sending pixels. Without it the consumer keeps re-blitting the last
    /// imported dmabuf and the tab freezes - which is what a guest reboot into
    /// a dumb framebuffer looks like.
    pub copy_takeover: bool,
}

/// A scanout buffer QEMU rendered on the host GPU. Importing this avoids the
/// per-frame RGBA copy entirely.
pub struct GuestCursor {
    pub w: u32,
    pub h: u32,
    pub hot_x: i32,
    pub hot_y: i32,
    pub rgba: Vec<u8>,
}

pub struct GuestDmabuf {
    pub fd: std::os::fd::OwnedFd,
    /// inode of the underlying dma-buf. Each ScanoutDMABUF carries a freshly
    /// dup'd fd, but a compositor rotates a small set of buffers, so the inode
    /// identifies which one this is and lets the importer reuse its texture.
    pub ino: u64,
    pub w: u32,
    pub h: u32,
    pub stride: u32,
    pub fourcc: u32,
    pub modifier: u64,
    pub y0_top: bool,
}
pub type Shared = Arc<Mutex<GuestFrame>>;

struct Listener { f: Shared, stride: u32, raw: Vec<u8>, n: u64, t0: Option<std::time::Instant>, have_scanout: bool }

impl Listener {
    /// Repack only the damaged rectangle. Rebuilding all 1M pixels for a
    /// cursor-sized damage region was a large part of the input latency.
    fn tick(&mut self, w: u32, h: u32) {
        self.n += 1;
        let t0 = *self.t0.get_or_insert_with(std::time::Instant::now);
        if self.n % 120 == 0 {
            let secs = t0.elapsed().as_secs_f64();
            log::debug!("{} updates in {:.1}s = {:.1}/s (last damage {w}x{h})",
                      self.n, secs, self.n as f64 / secs);
        }
    }

    fn repack(&mut self, rx: u32, ry: u32, rw: u32, rh: u32) {
        let mut g = self.f.lock().unwrap();
        let (w, h) = (g.w as usize, g.h as usize);
        if w == 0 || h == 0 { return; }
        g.rgba.resize(w * h * 4, 0);
        let x0 = rx as usize;
        let y0 = ry as usize;
        let x1 = (rx + rw).min(g.w) as usize;
        let y1 = (ry + rh).min(g.h) as usize;
        for y in y0..y1 {
            for x in x0..x1 {
                let s = y * self.stride as usize + x * 4;
                let d = (y * w + x) * 4;
                if s + 3 < self.raw.len() {
                    // x8r8g8b8 little-endian => B,G,R,X in memory
                    g.rgba[d] = self.raw[s + 2];
                    g.rgba[d + 1] = self.raw[s + 1];
                    g.rgba[d + 2] = self.raw[s];
                    g.rgba[d + 3] = 255;
                }
            }
        }
        // union with any damage the consumer has not picked up yet
        g.dirty = Some(match g.dirty {
            None => (rx, ry, x1.saturating_sub(x0) as u32, y1.saturating_sub(y0) as u32),
            Some((ox, oy, ow, oh)) => {
                let nx = ox.min(rx); let ny = oy.min(ry);
                let ex = (ox + ow).max(x1 as u32); let ey = (oy + oh).max(y1 as u32);
                (nx, ny, ex.saturating_sub(nx), ey.saturating_sub(ny))
            }
        });
        g.seq += 1;
    }
}

#[interface(name = "org.qemu.Display1.Listener")]
impl Listener {
    async fn scanout(&mut self, width: u32, height: u32, stride: u32, _fmt: u32, data: Vec<u8>) {
        {
            let mut g = self.f.lock().unwrap();
            g.w = width; g.h = height; g.dirty = None; g.orphan_updates = 0;
            g.dmabuf = None;
            g.copy_takeover = true;
        }
        self.have_scanout = true;
        self.stride = stride;
        self.raw = data;
        self.tick(width, height);
        self.repack(0, 0, width, height);
    }
    async fn update(&mut self, x: i32, y: i32, w: i32, h: i32, stride: u32, _fmt: u32, data: Vec<u8>) {
        let bpp = 4usize;
        let (gw, gh) = { let g = self.f.lock().unwrap(); (g.w as usize, g.h as usize) };
        if self.raw.is_empty() || gw == 0 { return; }
        for row in 0..h.max(0) as usize {
            let dy = y as usize + row;
            if dy >= gh { break; }
            let s = row * stride as usize;
            let d = dy * self.stride as usize + x as usize * bpp;
            let len = (w.max(0) as usize * bpp).min(data.len().saturating_sub(s));
            if d + len <= self.raw.len() && s + len <= data.len() {
                self.raw[d..d + len].copy_from_slice(&data[s..s + len]);
            }
        }
        self.tick(w.max(0) as u32, h.max(0) as u32);
        self.repack(x.max(0) as u32, y.max(0) as u32, w.max(0) as u32, h.max(0) as u32);
    }
    #[zbus(name = "ScanoutDMABUF")]
    async fn scanout_dmabuf(&mut self, fd: Fd<'_>, w: u32, h: u32, stride: u32,
                            fourcc: u32, modifier: u64, y0_top: bool) {
        match fd.as_fd().try_clone_to_owned() {
            Ok(owned) => {
                let mut g = self.f.lock().unwrap();
                g.w = w; g.h = h;
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let ino = if unsafe { libc::fstat(owned.as_raw_fd(), &mut st) } == 0 { st.st_ino } else { 0 };
                g.dmabuf = Some(GuestDmabuf { fd: owned, ino, w, h, stride, fourcc, modifier, y0_top });
                g.orphan_updates = 0;
                self.have_scanout = true;
                g.seq += 1;
                log::debug!("ScanoutDMABUF {w}x{h} stride={stride} fourcc=0x{fourcc:08x} mod=0x{modifier:x} y0_top={y0_top}");
            }
            Err(e) => log::error!("dmabuf dup failed: {e}"),
        }
    }
    #[zbus(name = "UpdateDMABUF")]
    async fn update_dmabuf(&mut self, x: i32, y: i32, w: i32, h: i32) {
        // Same underlying buffer: nothing to copy, just note there is new content.
        let mut g = self.f.lock().unwrap();
        if !self.have_scanout {
            g.orphan_updates += 1;
            if g.orphan_updates == 1 {
                log::warn!("UpdateDMABUF with no scanout - the guest display was                             probably asleep when we attached; nothing to draw until                             it wakes (use the Wake button)");
            }
        }
        g.seq += 1;
        if g.seq % 60 == 0 {
            log::debug!("UpdateDMABUF #{} +{x}+{y} {w}x{h}", g.seq);
        }
    }
    async fn cursor_define(&mut self, width: i32, height: i32, hot_x: i32, hot_y: i32,
                           data: Vec<u8>) {
        if width <= 0 || height <= 0 { return; }
        let (w, h) = (width as u32, height as u32);
        let want = (w as usize) * (h as usize) * 4;
        // Guest-controlled: a length that disagrees with the declared size
        // would trip an assert in egui and take the whole console down.
        if data.len() != want {
            log::warn!("CursorDefine {w}x{h}: {} bytes, expected {want}; ignored", data.len());
            return;
        }
        let mut rgba = Vec::with_capacity(want);
        // QEMU sends ARGB32 little-endian => B,G,R,A in memory
        for px in data.chunks_exact(4) {
            rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
        let mut g = self.f.lock().unwrap();
        g.cursor = Some(GuestCursor { w, h, hot_x, hot_y, rgba });
        g.cursor_seq += 1;
        log::debug!("CursorDefine {w}x{h} hot={hot_x},{hot_y}");
    }

    async fn mouse_set(&mut self, _x: i32, _y: i32, on: i32) {
        self.f.lock().unwrap().cursor_visible = on != 0;
    }

    async fn disable(&mut self) {}
    #[zbus(property)] fn interfaces(&self) -> Vec<String> { vec![] }
}

#[zbus::proxy(interface = "org.qemu.Display1.Console", default_service = "org.qemu")]
trait Console {
    fn register_listener(&self, listener: Fd<'_>) -> zbus::Result<()>;
}


/// Linux evdev keycode -> QEMU "qnum", which is what the D-Bus Keyboard
/// interface actually wants (`qemu_input_key_number_to_qcode`).
///
/// A qnum is the **PS/2 set-1 scancode**, with extended (0xE0-prefixed) keys
/// encoded as `0x80 | low_byte`. For the main block the two numbering schemes
/// are identical, because Linux derived its base keycodes from set 1 - which is
/// why typing letters worked and hid this bug for a long time. Every extended
/// key was wrong: we sent Delete as 111 when QEMU wanted 0xD3 = 211, so
/// Ctrl+Alt+Del reached a Windows guest as Ctrl+Alt+nothing.
fn evdev_to_qnum(code: u32) -> Option<u32> {
    Some(match code {
        // Base block: identity. 1 (Esc) .. 88 (F12), which covers the
        // alphanumerics, both shifts, left ctrl/alt, the keypad and F1-F12.
        1..=88 => code,
        // Extended: 0xE0 <low>  ->  0x80 | low
        96  => 0x9C,  // KPENTER
        97  => 0x9D,  // RIGHTCTRL
        98  => 0xB5,  // KPSLASH
        99  => 0xB7,  // SYSRQ / PrintScreen
        100 => 0xB8,  // RIGHTALT
        102 => 0xC7,  // HOME
        103 => 0xC8,  // UP
        104 => 0xC9,  // PAGEUP
        105 => 0xCB,  // LEFT
        106 => 0xCD,  // RIGHT
        107 => 0xCF,  // END
        108 => 0xD0,  // DOWN
        109 => 0xD1,  // PAGEDOWN
        110 => 0xD2,  // INSERT
        111 => 0xD3,  // DELETE   <- the one that started this
        119 => 0xC6,  // PAUSE
        125 => 0xDB,  // LEFTMETA  (Windows key)
        126 => 0xDC,  // RIGHTMETA
        127 => 0xDD,  // COMPOSE / Menu
        113 => 0xA0,  // MUTE
        114 => 0xAE,  // VOLUMEDOWN
        115 => 0xB0,  // VOLUMEUP
        116 => 0xDE,  // POWER
        _ => return None,
    })
}

#[zbus::proxy(interface = "org.qemu.Display1.Keyboard", default_service = "org.qemu")]
trait Keyboard {
    #[zbus(no_reply)] fn press(&self, keycode: u32) -> zbus::Result<()>;
    #[zbus(no_reply)] fn release(&self, keycode: u32) -> zbus::Result<()>;
}

#[zbus::proxy(interface = "org.qemu.Display1.Mouse", default_service = "org.qemu")]
trait Mouse {
    #[zbus(no_reply)] fn press(&self, button: u32) -> zbus::Result<()>;
    #[zbus(no_reply)] fn release(&self, button: u32) -> zbus::Result<()>;
    #[zbus(no_reply)] fn set_abs_position(&self, x: u32, y: u32) -> zbus::Result<()>;
}

/// Spawn a background thread running the D-Bus listener for `console`.
pub fn spawn(vm: &str, bus: String, console: u32) -> (Shared, std::sync::mpsc::Sender<crate::input::GuestAct>) {
    let shared: Shared = Arc::new(Mutex::new(GuestFrame::default()));
    let out = shared.clone();
    let (tx, rx) = std::sync::mpsc::channel::<crate::input::GuestAct>();
    let vm = vm.to_string();
    let tname = format!("guest:{vm}");
    let _ = std::thread::Builder::new().name(tname).spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .thread_name(format!("guest:{vm}"))
            .enable_all().build().unwrap();
        rt.block_on(async move {
            let conn = match zbus::connection::Builder::address(bus.as_str())
                // The copy path carries whole framebuffers (8 MB at 1920x1080)
                // per guest frame; unbounded queueing of those is an OOM. We
                // only ever draw the newest frame, so dropping stale ones is
                // correct. The dmabuf path sends an fd, not pixels.
                .map(|b| b.max_queued(4))
            {
                Ok(b) => match b.build().await {
                    Ok(c) => c,
                    Err(e) => { log::error!("connect {bus}: {e}"); return; }
                },
                Err(e) => { log::error!("bad bus address {bus}: {e}"); return; }
            };
            let path = format!("/org/qemu/Display1/Console_{console}");
            let proxy = match ConsoleProxy::builder(&conn).path(path).unwrap().build().await {
                Ok(p) => p, Err(e) => { log::error!("no console: {e}"); return; }
            };
            let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
            ours.set_nonblocking(true).unwrap();
            let ours = tokio::net::UnixStream::from_std(ours).unwrap();
            let builder = zbus::connection::Builder::unix_stream(ours)
                .p2p()   // QEMU is the auth server on this socket
                .serve_at("/org/qemu/Display1/Listener",
                          Listener { f: out, stride: 0, raw: Vec::new(), n: 0, t0: None, have_scanout: false }).unwrap();
            let task = tokio::spawn(async move { builder.build().await });
            let ofd: OwnedFd = theirs.into();
            if let Err(e) = proxy.register_listener(Fd::from(ofd.as_fd())).await {
                log::error!("RegisterListener failed: {e}"); return;
            }
            match task.await {
                Ok(Ok(c)) => { log::info!("listener up"); std::mem::forget(c); }
                other => { log::error!("listener build failed: {other:?}"); return; }
            }
            // input pump: drain the channel and drive QEMU's Keyboard/Mouse
            let mut pending: Vec<crate::input::GuestAct> = Vec::new();
            let path = format!("/org/qemu/Display1/Console_{console}");
            let kbd = KeyboardProxy::builder(&conn).path(path.clone()).unwrap()
                .build().await.ok();
            let mouse = MouseProxy::builder(&conn).path(path).unwrap()
                .build().await.ok();
            if kbd.is_some() && mouse.is_some() { log::info!("input proxies ready"); }
            loop {
                use crate::input::GuestAct::*;
                // Collapse runs of motion into the last position; buttons and
                // keys keep their order. Awaiting a reply per motion lags.
                let mut batch: Vec<crate::input::GuestAct> = std::mem::take(&mut pending);
                while let Ok(a) = rx.try_recv() {
                    if let (AbsPos(..), Some(AbsPos(..))) = (&a, batch.last()) {
                        batch.pop();
                    }
                    batch.push(a);
                }
                let got = !batch.is_empty();
                for a in batch {
                    match a {
                        AbsPos(x, y) => { if let Some(m) = &mouse {
                            if let Err(e) = m.set_abs_position(x, y).await { log::error!("abs {e}"); } } }
                        Btn(b, d) => { if let Some(m) = &mouse {
                            let r = if d { m.press(b).await } else { m.release(b).await };
                            if let Err(e) = r { log::error!("btn {b} down={d} ERR {e}"); } } }
                        Key(k, d) => { match (evdev_to_qnum(k), &kbd) {
                            (Some(q), Some(kb)) => {
                                let r = if d { kb.press(q).await } else { kb.release(q).await };
                                if let Err(e) = r { log::error!("key {k}->{q} down={d} ERR {e}"); }
                            }
                            (None, _) => log::debug!("key {k}: no qnum mapping, dropped"),
                            _ => {}
                        } }
                    }
                }
                // Block rather than poll: D-Bus costs 24us/event, so a
                // poll+sleep here dominated the transport by >100x.
                if !got {
                    match tokio::task::block_in_place(|| {
                        rx.recv_timeout(std::time::Duration::from_millis(100))
                    }) {
                        Ok(a) => pending.push(a),
                        Err(_) => {}
                    }
                }
            }
        });
    });
    (shared, tx)
}
