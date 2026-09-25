// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The graphical frontend: egui on bare DRM/KMS. Selected at runtime when the
//! device has a usable GPU; see crate::frontend.
//!
//! An egui interface drawn straight onto the console through DRM/KMS, with each
//! VM's framebuffer rendered into a tab. There is no Wayland, no X and no seat
//! manager: EVE has none of them, and this runs as plain root on a VT.
//!
//! The point of it is to stop passing the iGPU through to guests. A guest gets
//! a virtual GPU instead, and its framebuffer is composited here.

pub mod drm;
pub mod guest;
pub mod input;
pub mod logger;
pub mod qmp;
pub mod scanout;
pub mod ui;
pub mod vt;

use std::sync::Arc;

use smithay::backend::renderer::{Bind, Color32F, Frame as _, Renderer};
use smithay::utils::{Rectangle, Transform};

use scanout::Vm;

/// egui points-per-pixel. The console is small and far away; 1.0 is unreadable.
/// Shared with the input thread, which converts the same coordinates.
pub const POINTS_PER_PIXEL: f32 = 2.0;

struct Config {
    card: Option<String>,
    /// 0 means run until signalled.
    frames: u32,
    orient: u8,
    ptr_scale: f64,
    probe: bool,
    vms: String,
}

impl Config {
    fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).ok();
        Self {
            // A positional argument still wins, which keeps ad-hoc runs easy.
            // None means "probe"; see drm::pick_card.
            card: std::env::args().nth(1).or_else(|| env("GUI_CARD")),
            frames: env("GUI_FRAMES").and_then(|v| v.parse().ok()).unwrap_or(0),
            orient: env("GUI_ORIENT").and_then(|v| v.parse().ok()).unwrap_or(1),
            ptr_scale: env("GUI_PTR_SCALE").and_then(|v| v.parse().ok()).unwrap_or(1.0),
            probe: env("GUI_PROBE").is_some(),
            vms: env("GUI_VMS").unwrap_or_default(),
        }
    }
}

/// `GUI_VMS="linux=<busaddr>;windows=<busaddr>"`
///
/// Semicolon separated, because a D-Bus address itself contains a comma
/// (`unix:path=...,guid=...`).
fn spawn_vms(spec: &str) -> Vec<Vm> {
    let mut vms = Vec::new();
    for entry in spec.split(';').filter(|e| !e.trim().is_empty()) {
        let Some((name, bus)) = entry.split_once('=') else { continue };
        let (name, bus) = (name.trim().to_string(), bus.trim().to_string());
        let (shared, tx) = guest::spawn(&name, guest::Transport::Address(bus), 0);
        log::info!("tab {}: {}", vms.len(), name);
        vms.push(Vm::new(name, shared, tx));
    }
    vms
}

/// Run the graphical console until it is asked to stop, the VT goes away, or
/// `switch` is set. `pillar` is the shared state the IPC client fills; this
/// frontend only reads it. `switch` lets `main` ask this to hand back the
/// console (e.g. pillar took the GPU for an app) without a real process
/// shutdown - checked once per frame, next to `vt::running()`, which keeps
/// meaning "the process itself is shutting down" and is untouched by a
/// switch request.
pub fn run(pillar: crate::ipc::Shared, switch: std::sync::Arc<std::sync::atomic::AtomicBool>) -> anyhow::Result<()> {
    let cfg = Config::from_env();
    // Held for the whole run; Drop puts the VT keyboard back.
    let _cad = vt::CtrlAltDelGuard::take();
    vt::install_signal_handlers();
    log::info!("orientation mode = {} (0=none 1=flipY 2=flipX 3=rot180)", cfg.orient);

    let card = drm::pick_card(cfg.card.as_deref())?;
    let mut gpu = drm::open(&card)?;
    let mut heads = drm::discover_heads(&mut gpu)?;

    // egui_glow painter sharing smithay's GL context.
    let gl: Arc<glow::Context> = gpu.renderer.with_context(|gl| gl.clone())?;
    let mut painter = egui_glow::Painter::new(gl, "", None, false)
        .map_err(|e| anyhow::anyhow!("egui_glow painter: {e}"))?;
    let egui_ctx = egui::Context::default();
    log::info!("egui_glow painter created on smithay's GL context");

    let mut vms = spawn_vms(&cfg.vms);
    let mut active = 0usize;
    let mut backoff = Backoff::default();
    // Tab 0 is the node page; guests are tabs 1..n.
    let mut show_node = true;

    let inp = input::spawn(heads[0].w, heads[0].h, cfg.ptr_scale)?;
    if let Some(vm) = vms.get(active) {
        inp.set_active(vm.tx.clone());
    }
    log::info!("input: click in the guest view to grab, ctrl+alt+g to release, ctrl+alt+N for tab N");

    // Guest hardware cursor, reloaded whenever the active guest republishes it.
    let mut cur_tex: Option<egui::TextureHandle> = None;
    let mut cur_seq = u64::MAX;
    let mut cur_hot = (0.0f32, 0.0f32);

    // Live rates for the status bar, over a short window so it reacts; the
    // periodic log line keeps the long-run average.
    let start = std::time::Instant::now();
    let mut win_t = std::time::Instant::now();
    let mut win_frames = 0u32;
    let mut win_gseq = 0u64;
    let (mut fps_now, mut gfps_now) = (0.0f32, 0.0f32);
    let mut n_done = 0u32;

    let limit = if cfg.frames == 0 { u32::MAX } else { cfg.frames };
    // The loop is wrapped so that an error still reaches shutdown(): DRM
    // master, GL objects and scanout surfaces must be released in order
    // even when a flip times out because a VT switch took master away.
    let loop_result = (|| -> anyhow::Result<()> {
        for n in 0..limit {
            if !vt::running() {
                log::info!("signal received at frame {n}, shutting down cleanly");
                break;
            }
            if switch.load(std::sync::atomic::Ordering::SeqCst) {
                log::info!("switch requested at frame {n}, handing back the console");
                break;
            }

            // Input routing names a specific VM. When reconcile changes who
            // holds the active slot - an app removed, a guest that died and
            // came back - it has to be re-pointed in the same breath, or
            // every keystroke goes to a channel nobody is reading.
            if reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff) {
                match vms.get(active) {
                    Some(vm) => {
                        inp.set_active(vm.tx.clone());
                        win_gseq = vm.seq;
                        log::info!("active tab is now {}", vm.name);
                    }
                    None => {
                        inp.clear_active();
                        show_node = true;
                    }
                }
                cur_seq = u64::MAX; // reload this guest's cursor
            }

            // Guest framebuffer: once per frame, not once per head.
            if let Some(vm) = vms.get_mut(active) {
                vm.update(&mut gpu.renderer, &mut painter, &egui_ctx, cfg.probe, n);
            }

            // Guest hardware cursor.
            if let Some(vm) = vms.get(active) {
                let g = guest::frame(&vm.shared);
                if g.cursor_seq != cur_seq {
                    if let Some(c) = &g.cursor {
                        cur_seq = g.cursor_seq;
                        cur_hot = (c.hot_x as f32, c.hot_y as f32);
                        let img =
                            egui::ColorImage::from_rgba_unmultiplied([c.w as usize, c.h as usize], &c.rgba);
                        match &mut cur_tex {
                            Some(t) => t.set(img, egui::TextureOptions::NEAREST),
                            None => {
                                cur_tex =
                                    Some(egui_ctx.load_texture("cursor", img, egui::TextureOptions::NEAREST))
                            }
                        }
                    }
                }
            }

            // What the input thread has published. It forwards to the guest itself,
            // so guest latency does not depend on our frame rate.
            let (ui_events, focus, cx, cy, hot_tab) = {
                let mut s = inp.state.lock().unwrap();
                (
                    std::mem::take(&mut s.egui_events),
                    if s.focus_guest { input::Focus::Guest } else { input::Focus::Gui },
                    s.x as f32,
                    s.y as f32,
                    s.want_tab.take(),
                )
            };

            win_frames += 1;
            let wdt = win_t.elapsed().as_secs_f32();
            if wdt >= 0.5 {
                fps_now = win_frames as f32 / wdt;
                let seq = vms.get(active).map_or(0, |v| v.seq);
                gfps_now = seq.saturating_sub(win_gseq) as f32 / wdt;
                win_t = std::time::Instant::now();
                win_frames = 0;
                win_gseq = seq;
            }

            let mut act = ui::Actions::default();
            for head in heads.iter_mut() {
                let head_name = head.name.clone();
                let (mut dmabuf, _age) = head.surface.next_buffer()?;
                let size = (head.w, head.h).into();
                let raw_input = egui::RawInput {
                    events: ui_events.clone(),
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(head.w as f32 / POINTS_PER_PIXEL, head.h as f32 / POINTS_PER_PIXEL),
                    )),
                    ..Default::default()
                };

                let mut tabs: Vec<String> = vec!["Node".into()];
                tabs.extend(vms.iter().map(|v| v.name.clone()));
                let (orphans, cursor_visible, has_cursor) = match vms.get(active) {
                    Some(vm) => {
                        let g = guest::frame(&vm.shared);
                        (g.orphan_updates, g.cursor_visible, g.cursor.is_some())
                    }
                    None => (0, false, false),
                };
                let node = {
                    let p = pillar.lock().unwrap();
                    let d = p.device.clone();
                    (
                        d.as_ref().map_or(String::new(), |d| d.node_name.clone()),
                        d.as_ref().map_or(String::new(), |d| d.serial.clone()),
                        d.as_ref().map_or(String::new(), |d| d.server.clone()),
                        d.as_ref().map_or(String::new(), |d| d.hardware_model.clone()),
                        interfaces_of(&p),
                        p.connected,
                    )
                };
                let view = ui::Frame {
                    node_tab: show_node,
                    node: ui::NodeView {
                        name: &node.0,
                        serial: &node.1,
                        server: &node.2,
                        model: &node.3,
                        interfaces: &node.4,
                        connected: node.5,
                    },
                    head: &head_name,
                    fps: fps_now,
                    guest_fps: gfps_now,
                    frame: n,
                    elapsed: start.elapsed().as_secs_f32(),
                    tabs: &tabs,
                    active: if show_node { 0 } else { active + 1 },
                    focus,
                    pointer: egui::pos2(cx / POINTS_PER_PIXEL, cy / POINTS_PER_PIXEL),
                    guest: match vms.get(active) {
                        Some(vm) => ui::GuestView {
                            dma_id: vm.dma_id,
                            dma_size: vm.dma_size,
                            dma_flip: vm.dma_flip,
                            tex: vm.tex.as_ref(),
                            seq: vm.seq,
                            orphan_updates: orphans,
                        },
                        None => ui::GuestView {
                            dma_id: None,
                            dma_size: egui::vec2(1.0, 1.0),
                            dma_flip: false,
                            tex: None,
                            seq: 0,
                            orphan_updates: 0,
                        },
                    },
                    // Only when the ACTIVE guest published one: a guest that
                    // composites its own would end up with two pointers.
                    cursor: (has_cursor && cursor_visible)
                        .then_some(cur_tex.as_ref())
                        .flatten()
                        .map(|t| ui::CursorView { tex: t, hotspot: cur_hot }),
                };

                let out = egui_ctx.run(raw_input, |ctx| act = ui::draw(ctx, &view));

                let mut prims = egui_ctx.tessellate(out.shapes, out.pixels_per_point);
                ui::fix_orientation(
                    &mut prims,
                    head.w as f32 / POINTS_PER_PIXEL,
                    head.h as f32 / POINTS_PER_PIXEL,
                    cfg.orient,
                );

                // Bind the scanout dmabuf and let egui draw into it.
                let sync = {
                    let mut fb = gpu.renderer.bind(&mut dmabuf)?;
                    let mut frame = gpu.renderer.render(&mut fb, size, Transform::Normal)?;
                    frame.clear(Color32F::new(0.05, 0.06, 0.09, 1.0), &[Rectangle::from_size(size)])?;
                    frame.with_context(|_gl| {
                        painter.paint_and_update_textures(
                            [head.w as u32, head.h as u32],
                            POINTS_PER_PIXEL,
                            &prims,
                            &out.textures_delta,
                        );
                    })?;
                    Some(frame.finish()?)
                };
                drop(dmabuf);
                // Hand the GPU fence to the flip so scanout waits for rendering. A
                // VT switch steals DRM master; skip the frame rather than dying.
                if let Err(e) = head.surface.queue_buffer(sync, None, ()) {
                    log::error!("queue_buffer({}) failed: {e}", head.name);
                    continue;
                }
            }

            // The hotkey wins over a tab-bar click.
            // Tab 0 is the node page, so Ctrl+Alt+1 and a click on the first
            // tab mean the same thing.
            let want = hot_tab.filter(|t| *t <= vms.len()).or(act.tab);
            if let Some(t) = want {
                let (node, idx) = if t == 0 { (true, active) } else { (false, t - 1) };
                if node != show_node || idx != active {
                    show_node = node;
                    if !node {
                        active = idx;
                        if let Some(vm) = vms.get(active) {
                            inp.set_active(vm.tx.clone());
                            win_gseq = vm.seq; // not a real rate jump
                        }
                        cur_seq = u64::MAX; // reload this guest's cursor
                    }
                    log::info!(
                        "tab -> {}",
                        if node { "Node" } else { vms.get(active).map_or("?", |v| v.name.as_str()) }
                    );
                }
            }
            if act.send_wake {
                if let Some(vm) = vms.get(active) {
                    send_keys(vm, &[(input::KEY_LEFTSHIFT, true), (input::KEY_LEFTSHIFT, false)]);
                    log::info!("sent wake keystroke to {}", vm.name);
                }
            }
            if act.send_cad {
                if let Some(vm) = vms.get(active) {
                    send_keys(vm, input::CTRL_ALT_DEL);
                    log::info!("sent Ctrl+Alt+Del to {}", vm.name);
                }
            }
            if let Some(r) = act.viewport {
                let mut st = inp.state.lock().unwrap();
                st.view = (
                    r.min.x * POINTS_PER_PIXEL,
                    r.min.y * POINTS_PER_PIXEL,
                    r.width() * POINTS_PER_PIXEL,
                    r.height() * POINTS_PER_PIXEL,
                );
                // Every frame, from the VM that owns it - never inferred from
                // whether a scanout message happened to arrive.
                st.guest_size = vms.get(active).map_or((0, 0), |v| v.size);
            }

            drm::wait_for_flips(&mut gpu.drm, gpu.raw_fd, &heads, n)?;
            for head in heads.iter_mut() {
                let _: Option<()> = head.surface.frame_submitted()?;
            }
            n_done = n + 1;

            if n > 0 && n % 120 == 0 {
                // Report input latency from here, where a syscall is free.
                let (sum, cnt, mx) = inp.stats.take();
                let lat = if cnt > 0 {
                    format!(
                        "  input staleness avg {:.2}ms max {:.2}ms over {cnt}",
                        sum as f64 / cnt as f64 / 1000.0,
                        mx as f64 / 1000.0
                    )
                } else {
                    String::new()
                };
                log::info!(
                    "frame {n}: {:.1} fps avg  guest {gfps_now:.1} fps{lat}",
                    n as f64 / start.elapsed().as_secs_f64()
                );
            }
        }
        Ok(())
    })();
    if let Err(e) = &loop_result {
        log::error!("frame loop stopped: {e}");
    }

    let el = start.elapsed();
    log::info!(
        "rendered on {} head(s), {n_done} frames in {:.2?} ({:.1} fps)",
        heads.len(),
        el,
        n_done as f64 / el.as_secs_f64()
    );
    shutdown(gpu, heads, vms, painter, inp);
    loop_result
}

/// Per-socket attach back-off. Reconcile runs once per frame, so an app that
/// is listed but whose QEMU is not answering would otherwise be dialled at the
/// frame rate forever - 60 blocking handshakes a second against a guest that
/// is merely still booting.
#[derive(Default)]
pub struct Backoff(std::collections::HashMap<String, (u32, std::time::Instant)>);

impl Backoff {
    const FIRST: std::time::Duration = std::time::Duration::from_millis(250);
    const MAX: std::time::Duration = std::time::Duration::from_secs(8);

    fn ready(&self, sock: &str) -> bool {
        self.0.get(sock).is_none_or(|(_, next)| std::time::Instant::now() >= *next)
    }

    fn failed(&mut self, sock: &str) {
        let e = self.0.entry(sock.to_string()).or_insert((0, std::time::Instant::now()));
        e.0 = e.0.saturating_add(1);
        let wait = Self::FIRST.saturating_mul(1u32 << e.0.min(5)).min(Self::MAX);
        e.1 = std::time::Instant::now() + wait;
    }

    fn succeeded(&mut self, sock: &str) {
        self.0.remove(sock);
    }

    /// Forget sockets pillar no longer lists, so the map cannot grow for the
    /// life of the process on a device that cycles through many apps.
    fn retain_listed(&mut self, wanted: &[(String, String)]) {
        self.0.retain(|sock, _| wanted.iter().any(|(_, s)| s == sock));
    }
}

/// Add a tab for each app pillar reports with a display, and drop tabs whose
/// app has gone or whose guest has died. An app without a QMP socket has no
/// virtual GPU and simply gets no tab.
///
/// Returns true if the VM sitting at `active` changed identity, which the
/// caller must act on: the input routing and the published guest size both
/// name a specific VM, and leaving them pointing at the previous occupant of
/// an index sends every keystroke into a dropped channel.
#[must_use]
fn reconcile_tabs(
    vms: &mut Vec<Vm>,
    pillar: &crate::ipc::Shared,
    active: &mut usize,
    backoff: &mut Backoff,
) -> bool {
    let wanted: Vec<(String, String)> = {
        let p = pillar.lock().unwrap();
        p.apps
            .iter()
            .filter(|a| !a.qmp_socket.is_empty())
            .map(|a| (a.name.clone(), a.qmp_socket.clone()))
            .collect()
    };
    if wanted.is_empty() && vms.is_empty() {
        return false;
    }
    backoff.retain_listed(&wanted);

    // Identity of whoever holds the active slot right now, so we can tell
    // afterwards whether that slot changed hands.
    let was: Option<(String, u64)> = vms.get(*active).map(|v| (v.source.clone(), v.id));

    vms.retain_mut(|vm| {
        // Tabs from GUI_VMS have no source: they are the developer's, not
        // pillar's, and removing them because pillar has not heard of them
        // would delete the only tab on a rig with no pillar at all.
        let listed = vm.source.is_empty()
            || wanted.iter().any(|(_, sock)| *sock == vm.source);
        // A guest whose QEMU has gone keeps its last frame on screen and its
        // counters ticking, so it looks alive. Drop it; the loop below
        // re-attaches when the guest comes back. A hand-configured tab is
        // exempt: nothing would ever re-create it, so dropping it would strip
        // the rig of its only tab permanently rather than for one reconnect.
        let alive = vm.source.is_empty() || !guest::frame(&vm.shared).gone;
        let keep = listed && alive;
        if !keep {
            log::info!("tab gone: {} ({})", vm.name, if listed { "guest died" } else { "app removed" });
            vm.release_gl();
        }
        keep
    });

    for (name, sock) in &wanted {
        if vms.iter().any(|v| v.source == *sock) || !backoff.ready(sock) {
            continue;
        }
        match qmp::connect_display(std::path::Path::new(sock)) {
            Ok(fd) => {
                let (shared, tx) = guest::spawn(name, guest::Transport::Fd(fd), 0);
                log::info!("tab added: {name} via {sock}");
                backoff.succeeded(sock);
                vms.push(Vm::new(name.clone(), shared, tx).with_source(sock.clone()));
            }
            // Routine while a guest is starting: QEMU may not be listening yet.
            Err(e) => {
                log::debug!("{name}: display not ready ({e})");
                backoff.failed(sock);
            }
        }
    }
    if *active >= vms.len() {
        *active = vms.len().saturating_sub(1);
    }
    let now: Option<(String, u64)> = vms.get(*active).map(|v| (v.source.clone(), v.id));
    was != now
}

/// Flatten pillar's network status into (interface, address) rows.
fn interfaces_of(p: &crate::ipc::PillarState) -> Vec<(String, String)> {
    let Some(n) = p.network.as_ref() else {
        return Vec::new();
    };
    n.interfaces
        .iter()
        .map(|i| {
            // v4 first, then v6; a port with neither is still worth showing,
            // because "up with no address" is exactly what you want to see.
            let addr = i
                .network
                .ipv4
                .iter()
                .chain(i.network.ipv6.iter())
                .map(|a| a.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let name = if i.label.is_empty() { i.name.clone() } else { i.label.clone() };
            (name, addr)
        })
        .collect()
}

fn send_keys(vm: &Vm, keys: &[(u32, bool)]) {
    for (k, down) in keys {
        let _ = vm.tx.send(input::GuestAct::Key(*k, *down));
    }
}

/// Release everything in dependency order.
///
/// Getting this wrong is what left stale DRM/GL state behind and made later
/// runs render black until the host was rebooted.
fn shutdown(
    mut gpu: drm::Gpu,
    mut heads: Vec<drm::Head>,
    mut vms: Vec<Vm>,
    mut painter: egui_glow::Painter,
    inp: input::Handle,
) {
    log::info!("cleanup: stopping input thread");
    // Independent of DRM/GL; do it first so a slow join doesn't sit between
    // the frame loop stopping and the GL/DRM cleanup below.
    inp.shutdown();

    log::info!("cleanup: draining in-flight page flips");
    for head in heads.iter_mut() {
        let _ = head.surface.frame_submitted();
        head.surface.reset_buffers();
    }
    log::info!("cleanup: dropping GL objects");
    for vm in vms.iter_mut() {
        vm.release_gl();
    }
    let _ = gpu.renderer.with_context(|gl| {
        use glow::HasContext as _;
        unsafe { gl.finish() };
    });
    painter.destroy();

    log::info!("cleanup: releasing scanout surfaces");
    drop(heads); // GBM BOs and DRM framebuffers
    let raw_fd = gpu.raw_fd;
    drop(gpu.renderer); // EGL context
    drop(gpu.gbm);
    log::info!("cleanup: dropping DRM master");
    drm::drop_master(raw_fd);
    drop(gpu.drm);
    log::info!("cleanup: done");
    logger::drain(); // do not lose the tail on exit
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_vm(name: &str, source: &str) -> Vm {
        let (shared, tx) = (
            std::sync::Arc::new(std::sync::Mutex::new(guest::GuestFrame::default())),
            std::sync::mpsc::sync_channel(1).0,
        );
        let vm = Vm::new(name.into(), shared, tx);
        if source.is_empty() { vm } else { vm.with_source(source.into()) }
    }

    fn pillar_listing(socks: &[(&str, &str)]) -> crate::ipc::Shared {
        let st = crate::ipc::PillarState {
            // Built through the wire format rather than field by field: the
            // contract type is generated, so this also keeps the fixture
            // honest if a field is added.
            apps: socks
                .iter()
                .map(|(name, sock)| {
                    serde_json::from_value(serde_json::json!({
                        "uuid": "9c1f2e3a-4b5c-6d7e-8f90-a1b2c3d4e5f6",
                        "name": name,
                        "version": "1",
                        "state": "running",
                        "error": "",
                        "qmpSocket": sock,
                    }))
                    .expect("fixture decodes")
                })
                .collect(),
            connected: true,
            ..Default::default()
        };
        std::sync::Arc::new(std::sync::Mutex::new(st))
    }

    /// A panic in one guest's listener must not take the console with it.
    /// `.unwrap()` on a poisoned mutex from the render thread skips shutdown(),
    /// which leaves DRM master and the GL objects behind and the panel black
    /// until the box is rebooted.
    #[test]
    fn a_poisoned_guest_mutex_does_not_kill_the_render_thread() {
        let vm = a_vm("vm1", "/nonexistent/eve-gui-test/qmp");
        let shared = vm.shared.clone();
        let _ = std::thread::spawn(move || {
            let _g = shared.lock().unwrap();
            panic!("a guest listener died");
        })
        .join();
        assert!(vm.shared.is_poisoned(), "the test needs a poisoned mutex");

        // The render thread's accessor must still hand back the frame.
        let f = guest::frame(&vm.shared);
        assert!(!f.gone);
    }

    /// A guest that reboots keeps its QMP socket path, so pillar keeps listing
    /// it and the tab was never rebuilt: the screen froze on the last frame
    /// while the frame counter kept looking healthy.
    #[test]
    fn drops_a_tab_whose_guest_died() {
        let pillar = pillar_listing(&[("vm1", "/nonexistent/eve-gui-test/qmp")]);
        let mut vms = vec![a_vm("vm1", "/nonexistent/eve-gui-test/qmp")];
        let mut active = 0usize;
        let mut backoff = Backoff::default();

        // Still alive: kept.
        assert!(!reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff));
        assert_eq!(vms.len(), 1);

        vms[0].shared.lock().unwrap().gone = true;
        let changed = reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff);
        assert!(vms.is_empty(), "a dead guest must not keep its tab");
        assert!(changed, "the active slot changed hands and input must be re-pointed");
    }

    /// The hand-configured tab from GUI_VMS has no socket to re-attach to, so
    /// dropping it on death would remove it for good. See the Task 8 ruling.
    #[test]
    fn keeps_a_hand_configured_tab_whose_guest_died() {
        let pillar = pillar_listing(&[]);
        let mut vms = vec![a_vm("manual", "")];
        vms[0].shared.lock().unwrap().gone = true;
        let mut active = 0usize;
        let mut backoff = Backoff::default();

        assert!(!reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff));
        assert_eq!(vms.len(), 1);
    }

    /// Reconcile runs once per frame. Without a back-off, an app whose QEMU is
    /// not answering yet is dialled 60 times a second, each one a blocking
    /// handshake on the render thread.
    #[test]
    fn backs_off_after_a_failed_attach() {
        let sock = "/nonexistent/eve-gui-test/qmp";
        let mut b = Backoff::default();
        assert!(b.ready(sock), "first attempt must go straight through");
        b.failed(sock);
        assert!(!b.ready(sock), "a failed attach must not be retried on the next frame");
        b.succeeded(sock);
        assert!(b.ready(sock), "success clears the back-off");
    }

    /// The map is keyed by socket path; a device that cycles through apps
    /// would otherwise grow it for the life of the process.
    #[test]
    fn forgets_backoff_for_apps_pillar_no_longer_lists() {
        let mut b = Backoff::default();
        b.failed("/run/a/qmp");
        b.failed("/run/b/qmp");
        b.retain_listed(&[("b".into(), "/run/b/qmp".into())]);
        assert!(b.ready("/run/a/qmp"), "the delisted app's entry should be gone");
        assert!(!b.ready("/run/b/qmp"));
    }

    /// An app with no virtual GPU reports no socket and must not get a tab.
    #[test]
    fn ignores_apps_without_a_qmp_socket() {
        let pillar = pillar_listing(&[("container-app", "")]);
        let mut vms: Vec<Vm> = Vec::new();
        let mut active = 0usize;
        let mut backoff = Backoff::default();
        assert!(!reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff));
        assert!(vms.is_empty());
    }
}
