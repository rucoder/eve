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
pub mod stats;
pub mod typist;
pub mod ui;
pub mod vmstat;
pub mod vt;
pub mod wake;

use std::hash::{Hash, Hasher};
use std::sync::Arc;

use smithay::backend::renderer::{Bind, Color32F, Frame as _, Renderer};
use smithay::utils::{Rectangle, Transform};

use scanout::Vm;

/// egui points-per-pixel, shared with the input thread so both convert
/// coordinates the same way.
///
/// This was a hardcoded 2.0, which is right for a dense panel and badly wrong
/// anywhere else: at 2.0 a 1188x765 display gives egui 594x382 points to work
/// with and every widget is drawn at double size, which looks like a tiny
/// resolution rather than a magnified one. Derive it from the display's real
/// DPI instead, and fall back to 1.0 - not 2.0 - when the display does not say.
static PPP: std::sync::OnceLock<f32> = std::sync::OnceLock::new();

pub fn points_per_pixel() -> f32 {
    *PPP.get().unwrap_or(&1.0)
}

/// Pick a scale from the panel's physical size. 96 DPI is the 1.0 reference;
/// the result is clamped and rounded to quarter steps so the UI lands on a
/// predictable size rather than an arbitrary fraction.
fn scale_for(w: i32, mm: Option<(u32, u32)>, override_: Option<f32>) -> f32 {
    if let Some(s) = override_ {
        log::info!("ui scale {s} (configured)");
        return s;
    }
    let Some((mm_w, _)) = mm.filter(|(mw, _)| *mw > 0) else {
        log::info!("ui scale 1.0 (no EDID, so no physical size to derive DPI from)");
        return 1.0;
    };
    let dpi = w as f32 / (mm_w as f32 / 25.4);
    let s = ((dpi / 96.0) * 4.0).round() / 4.0;
    let s = s.clamp(1.0, 3.0);
    log::info!("ui scale {s} ({dpi:.0} dpi from {w}px / {mm_w}mm)");
    s
}

struct Config {
    card: Option<String>,
    /// 0 means run until signalled.
    frames: u32,
    orient: u8,
    ptr_scale: f64,
    /// Override the DPI-derived ui scale; GUI_SCALE, or gui.scale in
    /// config.json.
    scale: Option<f32>,
    /// The connector that takes input; GUI_INPUT_HEAD, or gui.input_head in
    /// config.json.
    input_head: Option<String>,
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
            scale: env("GUI_SCALE").and_then(|v| v.parse().ok()),
            input_head: env("GUI_INPUT_HEAD"),
            probe: env("GUI_PROBE").is_some(),
            vms: env("GUI_VMS").unwrap_or_default(),
        }
    }
}

/// `GUI_VMS="linux=<busaddr>;windows=<busaddr>"`
///
/// Semicolon separated, because a D-Bus address itself contains a comma
/// (`unix:path=...,guid=...`).
fn spawn_vms(spec: &str, heads: &[drm::Head]) -> Vec<Vm> {
    let mut vms = Vec::new();
    for entry in spec.split(';').filter(|e| !e.trim().is_empty()) {
        let Some((name, bus)) = entry.split_once('=') else { continue };
        let (name, bus) = (name.trim().to_string(), bus.trim().to_string());
        let (shared, tx) =
            guest::spawn(&name, guest::Transport::Address(bus), head_geometries(heads));
        log::info!("tab {}: {}", vms.len(), name);
        vms.push(Vm::new(name, shared, tx));
    }
    vms
}

/// Which head takes input: the configured connector while it is connected,
/// otherwise the first head.
///
/// Only one head does. The guest still gets a scanout on every head, but its
/// single absolute pointer cannot be steered across several of them from one
/// host pointer without the two disagreeing about where the edges are, and an
/// absolute device such as a PiKVM's has no way to say which monitor it means.
struct InputHead {
    want: Option<String>,
    /// The head picked last time, so only a change is logged.
    picked: String,
    /// The configured connector was missing last time: said once, not on
    /// every hotplug.
    missing: bool,
}

impl InputHead {
    fn new(want: Option<String>) -> Self {
        let want = want.map(|w| w.trim().to_string()).filter(|w| !w.is_empty());
        Self { want, picked: String::new(), missing: false }
    }

    fn resolve(&mut self, heads: &[drm::Head]) -> usize {
        let found = self
            .want
            .as_deref()
            .and_then(|w| heads.iter().position(|h| h.name.eq_ignore_ascii_case(w)));
        if let Some(w) = self.want.as_deref() {
            if found.is_none() && !self.missing {
                log::warn!("input head {w} is not connected; using the first head");
            }
            self.missing = found.is_none();
        }
        let i = found.unwrap_or(0);
        if let Some(h) = heads.get(i).filter(|h| h.name != self.picked) {
            log::info!("input head: {}{}", h.name, if found.is_some() { " (configured)" } else { "" });
            self.picked = h.name.clone();
        }
        i
    }
}

/// Run the graphical console until it is asked to stop, the VT goes away, or
/// `switch` is set. `pillar` is the shared state the IPC client fills; this
/// frontend only reads it. `switch` lets `main` ask this to hand back the
/// console (e.g. pillar took the GPU for an app) without a real process
/// shutdown - checked once per frame, next to `vt::running()`, which keeps
/// meaning "the process itself is shutting down" and is untouched by a
/// switch request.
pub fn run(
    pillar: crate::ipc::Shared,
    outbox: tokio::sync::mpsc::UnboundedSender<crate::ipc::message::IpcMessage>,
    switch: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mode: Option<&str>,
    gui_cfg: crate::application::GuiConfig,
) -> anyhow::Result<()> {
    let cfg = Config::from_env();
    // Until pillar's console.probe arrives; from then on, pillar's value.
    let mut probe = cfg.probe || gui_cfg.probe;
    let mut debug_rev = 0u64;
    // Held for the whole run; Drop puts the VT keyboard back.
    let _cad = vt::CtrlAltDelGuard::take();
    vt::install_signal_handlers();
    log::info!("orientation mode = {} (0=none 1=flipY 2=flipX 3=rot180)", cfg.orient);

    let card = drm::pick_card(cfg.card.as_deref())?;
    let mut gpu = drm::open(&card)?;
    let mut heads = drm::discover_heads(&mut gpu, mode)?;
    // The environment first, so a one-off run can move it without editing
    // config.json.
    let mut input_head = InputHead::new(cfg.input_head.clone().or(gui_cfg.input_head));
    let mut ih = input_head.resolve(&heads);
    // Monitors come and go while this runs; without this the head set is
    // whatever was plugged in at startup, for ever.
    let hotplug = match drm::HotplugWatch::new() {
        Ok(w) => Some(w),
        Err(e) => {
            log::warn!("no hotplug watch ({e}); the head set is fixed for this run");
            None
        }
    };

    // egui_glow painter sharing smithay's GL context.
    let gl: Arc<glow::Context> = gpu.renderer.with_context(|gl| gl.clone())?;
    let mut painter = egui_glow::Painter::new(gl, "", None, false)
        .map_err(|e| anyhow::anyhow!("egui_glow painter: {e}"))?;
    let egui_ctx = egui::Context::default();
    log::info!("egui_glow painter created on smithay's GL context");

    // What we tell guests about the monitors, rebuilt whenever the head set
    // changes. Cached because it is handed to every attach.
    let mut head_geoms = head_geometries(&heads);
    let mut vms = spawn_vms(&cfg.vms, &heads);
    // Host-side guest memory, sampled off the render thread.
    let vmstat = vmstat::spawn();
    let mut active = 0usize;
    let mut backoff = Backoff::default();
    // Tab 0 is the node page; guests are tabs 1..n.
    let mut show_node = true;
    // GUI_START_ON_GUEST: open on the first guest tab instead, at startup and
    // after a re-attach, so a rig that restarts the console unattended (the
    // perf bench) measures the guest view and not the Node page.
    let start_on_guest = std::env::var_os("GUI_START_ON_GUEST").is_some();
    let mut pending_tab: Option<usize> = start_on_guest.then_some(1);
    // Chrome hidden, guest filling the head; Ctrl+Alt+F toggles it.
    let mut fullscreen = false;
    // Which page of the node tab is showing.
    let mut node_page = ui::NodePage::Summary;
    // The viewport size last reported to the active guest. A guest renders at
    // the size we tell it, so this is what keeps the blit 1:1 rather than
    // scaled - and it changes when fullscreen is toggled.
    // Per head, because each one shows a different scanout at its own size.
    let mut told_viewport: Vec<Option<Told>> = vec![None; heads.len()];
    // Whether a remote session currently owns the guest's display.
    let mut remote = false;
    // The open port editor, if any, and what each port looked like before the
    // last Apply so Undo has somewhere to go.
    let mut edit: Option<ui::PortEdit> = None;
    let mut previous: std::collections::HashMap<String, ui::PortEdit> = Default::default();
    // Derived node-page data, rebuilt only when pillar's state moves. The
    // strings cannot be borrowed from PillarState: it lives behind a mutex the
    // IPC thread writes to, and holding that across a frame would stall it.
    let mut node_rev = u64::MAX;
    let mut ports: Vec<ui::PortView> = Vec::new();
    let mut apps: Vec<ui::AppView> = Vec::new();
    let mut debug_opts: Vec<crate::ipc::monitorapi::DebugOption> = Vec::new();

    // Before anything converts coordinates or lays out a frame. The input
    // head's, because that is where the controls are.
    let _ = PPP.set(scale_for(heads[ih].w, heads[ih].mm, cfg.scale));
    let inp = input::spawn(heads[ih].w, heads[ih].h, cfg.ptr_scale)?;
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
    // Per head: a guest can draw on one monitor while the others stay idle.
    let mut win_gseq = [0u64; stats::MAX_HEADS];
    let mut fps_now = 0.0f32;
    let mut gfps_now = [0.0f32; stats::MAX_HEADS];
    let mut n_done = 0u32;
    // The guest frame each head last put on screen, for stats::Head::shown.
    let mut last_shown = [u64::MAX; stats::MAX_HEADS];
    // Per head: a fingerprint of what it showed when last drawn, so a head
    // nothing changed on is neither redrawn nor flipped. Redrawing a 4K and a
    // 1080p head at 60 Hz regardless was most of the console's GPU time.
    let mut drawn_key: Vec<Option<u64>> = Vec::new();
    // egui asked to be run again for this head by then (hover, animation).
    let mut repaint_at: Vec<Option<std::time::Instant>> = Vec::new();
    // What a head's last draw reported, reused for input while it is not
    // redrawn: viewport, chrome, area.
    let mut head_rects: Vec<(Option<egui::Rect>, Option<egui::Rect>, Option<egui::Rect>)> =
        Vec::new();
    // The head set changed: every head draws once.
    let mut redraw_all = true;
    let mut last_log = std::time::Instant::now();
    stats::set_heads(&heads);
    stats::spawn();

    let limit = if cfg.frames == 0 { u32::MAX } else { cfg.frames };
    // The loop is wrapped so that an error still reaches shutdown(): DRM
    // master, GL objects and scanout surfaces must be released in order
    // even when a flip times out because a VT switch took master away.
    let loop_result = (|| -> anyhow::Result<()> {
        for n in 0..limit {
            let frame_t0 = std::time::Instant::now();
            // Set by a tab switch: this frame's work is finished before the next
            // guest is drawn, so nothing in flight still reads the one we left.
            let mut quiesce = false;
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
            if reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff, &head_geoms) {
                match vms.get(active) {
                    Some(vm) => {
                        inp.set_active(vm.tx.clone());
                        win_gseq = std::array::from_fn(|h| vm.head(h).seq);
                        log::info!("active tab is now {}", vm.name);
                    }
                    None => {
                        inp.clear_active();
                        show_node = true;
                    }
                }
                cur_seq = u64::MAX; // reload this guest's cursor
            }

            {
                let p = pillar.lock().unwrap();
                if p.debug_rev != debug_rev {
                    debug_rev = p.debug_rev;
                    if let Some(on) = p.debug_value(crate::ipc::DEBUG_PROBE).map(|v| v == "true") {
                        if on != probe {
                            probe = on;
                            log::info!("readback probe {}", if on { "on" } else { "off" });
                        }
                    }
                }
            }

            // Guest framebuffer: once per frame, not once per head.
            if let Some(vm) = vms.get_mut(active) {
                vm.update(&mut gpu.renderer, &mut painter, &egui_ctx, probe, n);
            }

            // Guest hardware cursor.
            if let Some(vm) = vms.get(active) {
                let g = guest::frame(&vm.head(0).shared);
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
            // The pointer is in the input head's pixels.
            let (mut ui_events, focus, cx, cy, hot_tab, hot_fs) = {
                let mut s = inp.state.lock().unwrap();
                (
                    std::mem::take(&mut s.egui_events),
                    if s.focus_guest { input::Focus::Guest } else { input::Focus::Gui },
                    s.x as f32,
                    s.y as f32,
                    s.want_tab.take(),
                    std::mem::take(&mut s.want_fullscreen),
                )
            };

            let wdt = win_t.elapsed().as_secs_f32();
            if wdt >= 0.5 {
                fps_now = win_frames as f32 / wdt;
                for h in 0..stats::MAX_HEADS {
                    let seq = vms.get(active).map_or(0, |v| v.head(h).seq);
                    gfps_now[h] = seq.saturating_sub(win_gseq[h]) as f32 / wdt;
                    win_gseq[h] = seq;
                }
                win_t = std::time::Instant::now();
                win_frames = 0;
            }

            // Hold the sampler's lock for the whole paint: the alternative
            // is cloning a 1200-sample history per head per frame.
            let vmstat_all = vmstat.lock().unwrap();
            let vmstat_now = vms.get(active).and_then(|vm| {
                std::path::Path::new(&vm.source)
                    .parent()
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    .and_then(|dom| vmstat_all.get(dom))
            });
            // Hand the display over, or take it back. One consumer at a
            // time: with heads enabled for both, the guest spreads its one
            // absolute pointer across the union of them and neither side can
            // place a cursor.
            let want_remote = vmstat_now.is_some_and(|v| v.vnc_clients > 0);
            if want_remote != remote {
                remote = want_remote;
                if let Some(vm) = vms.get(active) {
                    let _ = vm.tx.try_send(input::GuestAct::Remote(remote));
                }
                // Our geometry is meaningless while we do not own the head,
                // and must be re-sent from scratch when we get it back.
                told_viewport = vec![None; heads.len()];
                log::info!(
                    "display {} a remote session",
                    if remote { "handed to" } else { "taken back from" }
                );
            }
            let mut act = ui::Actions::default();
            // `act` holds only the head being drawn - the next head's
            // frame overwrites it - so what the user asked for is folded
            // into this as each head is drawn. Reading the intents off
            // `act` after the loop saw the LAST head only, which meant a
            // tab clicked on any other monitor did nothing at all.
            let mut intents = ui::Actions::default();
            let input_name = heads[ih].name.clone();
            // Where each head wants the guest drawn, collected here because
            // `act` is overwritten by the next head's frame.
            let mut viewports: Vec<Option<egui::Rect>> = Vec::with_capacity(heads.len());
            // Same reason, for the chrome hot zone. Only the input head has
            // one.
            let mut chromes: Vec<Option<egui::Rect>> = Vec::with_capacity(heads.len());
            // The container, not the letterboxed image: see `Actions::area`.
            let mut areas_avail: Vec<Option<egui::Rect>> = Vec::with_capacity(heads.len());
            // CRTCs that queued a flip this frame. A hotplug below can hand
            // over a head set with a new head in it, and waiting for a flip
            // that head never queued is a 3s timeout and a dead console.
            let mut flipped: Vec<u32> = Vec::new();
            if drawn_key.len() != heads.len() || std::mem::take(&mut redraw_all) {
                drawn_key = vec![None; heads.len()];
                repaint_at = vec![None; heads.len()];
                head_rects = vec![(None, None, None); heads.len()];
            }
            // UI input reaches the input head only. Motion is in its key; any
            // other event redraws it.
            let ui_input = ui_events.iter().any(|e| !matches!(e, egui::Event::PointerMoved(_)));
            // Status text (rates, uptime) moves twice a second.
            let status_tick = start.elapsed().as_millis() as u64 / 500;
            let now = std::time::Instant::now();
            let ui_key = {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                (show_node, active, vms.get(active).map(|v| v.id), fullscreen, node_page as u8).hash(&mut h);
                (remote, focus == input::Focus::Guest, edit.is_some(), probe, vms.len(), cur_seq).hash(&mut h);
                show_node.then(|| pillar.lock().unwrap().rev).hash(&mut h);
                // Only where it is on screen: chrome hidden over a guest, it is not.
                if !fullscreen || show_node {
                    status_tick.hash(&mut h);
                }
                h.finish()
            };
            for (hi, head) in heads.iter_mut().enumerate() {
                let head_name = head.name.clone();
                let input = hi == ih;
                let (orphans, cursor_visible, has_cursor, relative) = match vms.get(active) {
                    Some(vm) => {
                        // Pointer mode is per guest, recorded on head 0.
                        let relative = guest::frame(&vm.head(0).shared).pointer_relative;
                        let g = guest::frame(&vm.head(hi).shared);
                        (g.orphan_updates, g.cursor_visible, g.cursor.is_some(), relative)
                    }
                    None => (0, false, false, false),
                };
                let key = {
                    let mut h = std::collections::hash_map::DefaultHasher::new();
                    ui_key.hash(&mut h);
                    vms.get(active)
                        .filter(|_| !show_node && !remote)
                        .map(|vm| {
                            let s = vm.head(hi);
                            (s.seq, s.dma_id.is_some(), s.tex.is_some(), s.asleep)
                        })
                        .hash(&mut h);
                    (orphans > 0, cursor_visible, has_cursor, relative).hash(&mut h);
                    input.then(|| (cx.to_bits(), cy.to_bits())).hash(&mut h);
                    h.finish()
                };
                let due = repaint_at[hi].is_some_and(|t| now >= t);
                if !(input && ui_input) && !due && drawn_key[hi] == Some(key) {
                    let (v, c, a) = head_rects[hi];
                    viewports.push(v);
                    chromes.push(c);
                    areas_avail.push(a);
                    continue;
                }
                let (mut dmabuf, _age) = head.surface.next_buffer()?;
                let size = (head.w, head.h).into();
                // A viewport per head and role. egui keeps hover, presses and
                // the previous pass's widgets per viewport; in a shared one,
                // another head's pass between a press and its release would
                // drop the control pressed, which only the input head has.
                let vid = egui::ViewportId::from_hash_of((&head_name, input));
                let raw_input = egui::RawInput {
                    viewport_id: vid,
                    viewports: std::iter::once((vid, egui::ViewportInfo::default())).collect(),
                    events: if input { std::mem::take(&mut ui_events) } else { Vec::new() },
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::pos2(0.0, 0.0),
                        egui::vec2(head.w as f32 / points_per_pixel(), head.h as f32 / points_per_pixel()),
                    )),
                    ..Default::default()
                };

                let mut tabs: Vec<String> = vec!["Node".into()];
                tabs.extend(vms.iter().map(|v| v.name.clone()));
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
                        p.rev,
                    )
                };
                if show_node && node_rev != node.6 {
                    let p = pillar.lock().unwrap();
                    ports = ports_of(&p);
                    apps = apps_of(&p);
                    debug_opts = p.debug.clone();
                    node_rev = node.6;
                }
                let view = ui::Frame {
                    node_tab: show_node,
                    fullscreen,
                    page: node_page,
                    ports: &ports,
                    apps: &apps,
                    debug: &debug_opts,
                    edit: edit.as_ref(),
                    probe,
                    remote,
                    relative,
                    vmstat: vmstat_now,
                    node: ui::NodeView {
                        name: &node.0,
                        serial: &node.1,
                        server: &node.2,
                        model: &node.3,
                        interfaces: &node.4,
                        connected: node.5,
                    },
                    display: ui::DisplayView {
                        card: &card,
                        connector: &head_name,
                        w: head.w,
                        h: head.h,
                        refresh: head.refresh,
                        edid: head.edid,
                        pinned: mode,
                        scale: points_per_pixel(),
                    },
                    head: &head_name,
                    input,
                    input_head: &input_name,
                    fps: fps_now,
                    guest_fps: gfps_now[hi.min(stats::MAX_HEADS - 1)],
                    frame: n,
                    elapsed: start.elapsed().as_secs_f32(),
                    tabs: &tabs,
                    active: if show_node { 0 } else { active + 1 },
                    focus,
                    pointer: egui::pos2(cx / points_per_pixel(), cy / points_per_pixel()),
                    guest: match vms.get(active).map(|vm| vm.head(hi)) {
                        Some(s) => ui::GuestView {
                            dma_id: s.dma_id,
                            dma_size: s.dma_size,
                            dma_flip: s.dma_flip,
                            tex: s.tex.as_ref(),
                            seq: s.seq,
                            orphan_updates: orphans,
                            desc: s.desc,
                            probe_nonblack: s.probe_nonblack,
                            asleep: s.asleep,
                        },
                        None => ui::GuestView {
                            dma_id: None,
                            dma_size: egui::vec2(1.0, 1.0),
                            dma_flip: false,
                            tex: None,
                            seq: 0,
                            orphan_updates: 0,
                            desc: None,
                            probe_nonblack: None,
                            asleep: false,
                        },
                    },
                    // Only when the ACTIVE guest published one: a guest that
                    // composites its own would end up with two pointers. And
                    // only where the pointer is.
                    cursor: (input && has_cursor && cursor_visible)
                        .then_some(cur_tex.as_ref())
                        .flatten()
                        .map(|t| ui::CursorView { tex: t, hotspot: cur_hot }),
                };

                let out = egui_ctx.run(raw_input, |ctx| act = ui::draw(ctx, &view));
                let delay = out
                    .viewport_output
                    .get(&vid)
                    .map_or(std::time::Duration::MAX, |v| v.repaint_delay);
                repaint_at[hi] = (delay < std::time::Duration::from_secs(1)).then(|| now + delay);
                intents.absorb(&act);
                viewports.push(act.viewport);
                chromes.push(act.chrome);
                areas_avail.push(act.area);

                let mut prims = egui_ctx.tessellate(out.shapes, out.pixels_per_point);
                ui::fix_orientation(
                    &mut prims,
                    head.w as f32 / points_per_pixel(),
                    head.h as f32 / points_per_pixel(),
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
                            points_per_pixel(),
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
                flipped.push(head.crtc.into());
                drawn_key[hi] = Some(key);
                head_rects[hi] = (act.viewport, act.chrome, act.area);
                let hs = stats::head(hi);
                hs.flips.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if let Some(vm) = vms.get(active).filter(|_| !show_node && !remote) {
                    let seq = vm.head(hi).seq;
                    if last_shown[hi.min(stats::MAX_HEADS - 1)] != seq {
                        last_shown[hi.min(stats::MAX_HEADS - 1)] = seq;
                        hs.shown.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }

            // The hotkey wins over a tab-bar click.
            // Tab 0 is the node page, so Ctrl+Alt+1 and a click on the first
            // tab mean the same thing.
            // Cheap: one non-blocking recv that almost always says EAGAIN.
            if hotplug.as_ref().is_some_and(|w| w.drained_hotplug()) {
                redraw_all = true;
                let before: Vec<String> = heads.iter().map(|h| h.name.clone()).collect();
                // Heads that stayed put hand their surfaces to the new set, so
                // `heads` has to be surrendered for the call - which leaves
                // nothing to draw on if it fails. Retry from scratch once:
                // every old surface is gone by then, so the CRTCs that the
                // reconciling pass could not place are free.
                let found = drm::rediscover_heads(&mut gpu, mode, std::mem::take(&mut heads))
                    .or_else(|e| {
                        log::error!("re-discovering heads after hotplug failed: {e}");
                        drm::discover_heads(&mut gpu, mode)
                    })?;
                let after: Vec<String> = found.iter().map(|h| h.name.clone()).collect();
                heads = found;
                // On every hotplug, not only when the set changed: a head
                // that changed mode keeps its name. The configured head takes
                // input back when it returns, and the first head takes it
                // over when the input head is gone; the pointer is clamped
                // into whichever it is.
                ih = input_head.resolve(&heads);
                inp.set_bounds(heads[ih].w, heads[ih].h);
                if before != after {
                    log::info!("heads changed: {before:?} -> {after:?}");
                    head_geoms = head_geometries(&heads);
                    stats::set_heads(&heads);
                    // Each guest must be told its new geometry, and it only
                    // speaks when the viewport moves.
                    told_viewport = vec![None; heads.len()];
                    // A guest's scanout count is fixed when its listeners are
                    // registered, so a head appearing or going away needs the
                    // whole attach redone. reconcile_tabs rebuilds every tab
                    // it still finds an app for; GUI_VMS tabs are not
                    // pillar's, so they are rebuilt here.
                    if before.len() != after.len() {
                        log::info!("head count changed; re-attaching guests");
                        for vm in vms.iter_mut() {
                            vm.release_gl();
                        }
                        vms.clear();
                        vms = spawn_vms(&cfg.vms, &heads);
                        inp.clear_active();
                        show_node = true;
                        pending_tab = start_on_guest.then_some(1);
                    }
                }
            }
            if hot_fs || intents.toggle_fullscreen {
                fullscreen = !fullscreen;
                log::info!("fullscreen -> {fullscreen}");
            }
            // The guest should render at exactly the size it is shown at.
            // The viewports are in points; the guest wants pixels. One per
            // head: the guest's scanout for head N renders at exactly the
            // area head N gives it, so nothing is ever scaled.
            //
            // Nothing at all while the Node page is up. A guest we are not
            // drawing has no business being resized: its size is a property
            // of the area we give it, and we are giving it none. Running
            // this anyway is how a tab switch turned into a mode change, and
            // how a guest nobody was looking at got nagged to resize.
            if let Some(vm) = vms.get(active).filter(|_| !show_node && !remote) {
                let ppp = points_per_pixel();
                let mut xoff = 0i32;
                for (hi, head) in heads.iter().enumerate() {
                    let near = |a: u32, b: u32| (a as i64 - b as i64).abs() <= 8;
                    let told = told_viewport.get(hi).copied().flatten();
                    // Ask for the CONTAINER, never the letterboxed image.
                    // The image's size is computed from the guest's current
                    // size, so asking for it feeds the guest's own answer
                    // back in: if the guest snaps to the nearest mode it has
                    // rather than the one we asked for, the two never agree
                    // and the guest re-allocates its framebuffer about twice
                    // a second for ever.
                    let want = match areas_avail.get(hi).copied().flatten() {
                        Some(r) => (
                            (r.width() * ppp).round().max(64.0) as u32,
                            (r.height() * ppp).round().max(64.0) as u32,
                        ),
                        // Drawn, but this head has no guest area yet: the
                        // first frame after a tab opens. Say nothing rather
                        // than guess.
                        None => continue,
                    };
                    // Ask only for a STANDARD mode, and scale into the
                    // area we actually have.
                    //
                    // Asking for the exact container kept the guest 1:1, but
                    // every distinct size is a mode change, and a guest that
                    // does not repaint after one is black until something
                    // makes it draw. A Linux framebuffer console is exactly
                    // that: fbcon clears on the mode set and only redraws on
                    // new output, so an idle server VM - no compositor, no
                    // getty echoing - stays black for ever. Measured here:
                    // 3840x2160 had content, the 3812x2088 we asked for to
                    // fit a 28-point bar had 0 of 7959456 non-black pixels,
                    // and fullscreen (no chrome, native mode) brought it
                    // straight back.
                    //
                    // A standard mode is also one the guest is far more
                    // likely to accept outright instead of snapping to its
                    // own nearest, which is what the CHASE loop exists to
                    // survive. And chrome appearing or going no longer
                    // resizes anything: both layouts pick the same mode.
                    let want = standard_mode(want, (head.w as u32, head.h as u32));
                    // Hysteresis: egui's layout wobbles by a point during a
                    // transition, and a resolution change per frame would
                    // have the guest re-allocating for ever.
                    let moved =
                        told.map_or(true, |t: Told| !near(t.want.0, want.0) || !near(t.want.1, want.1));
                    // We asked recently and the guest has not caught up.
                    // SetUIInfo only makes a mode PREFERRED, so a guest may
                    // take a moment - or never. Chase only inside the window
                    // after OUR change: outside it, a size the guest is
                    // running is a size the guest chose, and it is not ours
                    // to overrule.
                    let got = vm.head(hi).size;
                    let ignored = told.is_some_and(|t| {
                        got != (0, 0)
                            && (!near(got.0, t.want.0) || !near(got.1, t.want.1))
                            && t.asked.elapsed() < CHASE
                            && t.said.elapsed() > CHASE_GAP
                    });
                    if moved || ignored {
                        let (mm_w, mm_h) = head.mm.unwrap_or((0, 0));
                        // Scale the millimetres with the area, so the DPI
                        // the guest computes stays the panel's real one.
                        let mm = |full_mm: u32, part: u32, full: u32| -> u16 {
                            if full == 0 { 0 } else { ((full_mm * part) / full) as u16 }
                        };
                        let g = guest::HeadGeometry {
                            w: want.0,
                            h: want.1,
                            mm_w: mm(mm_w as u32, want.0, head.w as u32),
                            mm_h: mm(mm_h as u32, want.1, head.h as u32),
                            // Side by side in head order, using the area
                            // the guest actually gets rather than the
                            // panel width: a guest laying its desktop out
                            // across two heads must not leave a gap where
                            // our chrome is.
                            xoff,
                            yoff: 0,
                        };
                        if vm.tx.try_send(input::GuestAct::Ui(hi, g)).is_ok() {
                            let now = std::time::Instant::now();
                            if ignored {
                                log::info!(
                                    "head {hi}: guest is {}x{}, asked for {}x{} {:.0}s ago; re-asking",
                                    got.0, got.1, want.0, want.1,
                                    told.map_or(0.0, |t| t.asked.elapsed().as_secs_f32()),
                                );
                            }
                            if let Some(slot) = told_viewport.get_mut(hi) {
                                *slot = Some(Told {
                                    want,
                                    // Only OUR change restarts the window.
                                    asked: if moved { now } else { told.map_or(now, |t| t.asked) },
                                    said: now,
                                });
                            }
                        }
                    }
                    xoff += want.0 as i32;
                }
            }
            if let Some((key, value)) = intents.set_debug.take() {
                use crate::ipc::message::{IpcMessage, Request};
                use crate::ipc::monitorapi::SetDebugOption;
                log::info!("debug option {key}={value:?}: asking pillar");
                let req = Request::SetDebugOption(SetDebugOption { key, value });
                if outbox.send(IpcMessage::new_request(req)).is_err() {
                    log::error!("debug option: pillar connection is gone");
                }
            }
            if let Some(p) = intents.page {
                node_page = p;
            }
            if let Some(name) = intents.edit_port.take() {
                // Copy the port's current values into the dialog, and carry
                // whatever it looked like before its last Apply so Undo works
                // even across a reopen.
                if let Some(p) = ports.iter().find(|p| p.name == name) {
                    edit = Some(ui::PortEdit {
                        iface: p.name.clone(),
                        dhcp: p.dhcp,
                        addr: p.ipv4.first().cloned().unwrap_or_default(),
                        subnet: p.subnet.clone(),
                        gateway: p.routes.first().cloned().unwrap_or_default(),
                        dns: p.dns.join(", "),
                        ntp: p.ntp.join(", "),
                        previous: previous.get(&name).cloned().map(Box::new),
                    });
                }
            } else if let Some(e) = intents.edit_update.take() {
                edit = Some(e);
            }
            if intents.edit_cancel {
                edit = None;
            }
            if let Some(mut want) = intents.apply_port.take() {
                // What it was, for Undo, taken from the live port rather than
                // from the dialog - the dialog already holds the new values.
                if let Some(p) = ports.iter().find(|p| p.name == want.iface) {
                    previous.insert(
                        want.iface.clone(),
                        ui::PortEdit {
                            iface: p.name.clone(),
                            dhcp: p.dhcp,
                            addr: p.ipv4.first().cloned().unwrap_or_default(),
                            subnet: p.subnet.clone(),
                            gateway: p.routes.first().cloned().unwrap_or_default(),
                            dns: p.dns.join(", "),
                            ntp: p.ntp.join(", "),
                            previous: None,
                        },
                    );
                }
                want.previous = None;
                let live_ntp = ports
                    .iter()
                    .find(|p| p.name == want.iface)
                    .map(|p| p.ntp.join(", "))
                    .unwrap_or_default();
                match interface_request(&want, &live_ntp) {
                    Ok(msg) => {
                        log::info!("net: applying {} ({})", want.iface,
                                   if want.dhcp { "dhcp" } else { "static" });
                        if outbox.send(msg).is_err() {
                            log::error!("net: pillar connection is gone; {} unchanged", want.iface);
                        }
                    }
                    Err(e) => log::error!("net: refusing to send {}: {e}", want.iface),
                }
                edit = None;
            }
            let pending = pending_tab.filter(|t| *t <= vms.len());
            if pending.is_some() {
                pending_tab = None;
            }
            let want = hot_tab.filter(|t| *t <= vms.len()).or(intents.tab).or(pending);
            if let Some(t) = want {
                let (node, idx) = if t == 0 { (true, active) } else { (false, t - 1) };
                if node != show_node || idx != active {
                    quiesce = true;
                    show_node = node;
                    if !node {
                        active = idx;
                        if let Some(vm) = vms.get(active) {
                            inp.set_active(vm.tx.clone());
                            win_gseq = std::array::from_fn(|h| vm.head(h).seq); // not a real rate jump
                        }
                        cur_seq = u64::MAX; // reload this guest's cursor
                    }
                    log::info!(
                        "tab -> {}",
                        if node { "Node" } else { vms.get(active).map_or("?", |v| v.name.as_str()) }
                    );
                }
            }
            if intents.send_wake {
                if let Some(vm) = vms.get(active) {
                    send_keys(vm, &[(input::KEY_LEFTSHIFT, true), (input::KEY_LEFTSHIFT, false)]);
                    log::info!("sent wake keystroke to {}", vm.name);
                }
            }
            if intents.send_cad {
                if let Some(vm) = vms.get(active) {
                    send_keys(vm, input::CTRL_ALT_DEL);
                    log::info!("sent Ctrl+Alt+Del to {}", vm.name);
                }
            }
            {
                // The guest image on the input head, in that head's pixels,
                // and where its scanout sits in the guest's desktop. The
                // other heads' scanouts still make up that desktop, so they
                // are walked for its extent and the input head's offset.
                let ppp = points_per_pixel();
                let px = |r: egui::Rect| (r.min.x * ppp, r.min.y * ppp, r.width() * ppp, r.height() * ppp);
                let mut area = None;
                // Whatever the guest still keeps on heads we cannot see
                // belongs in the desktop too: its single absolute pointer is
                // spread across the lot, so leaving those out makes the
                // pointer run off the visible screen.
                //
                // Assumed to sit BEFORE ours, because a guest that kept a
                // head we disabled kept the one it had made primary, and a
                // primary is placed at the origin. Ours are the ones after
                // it. Nothing reports the guest's layout back, so this is an
                // assumption, not a reading. It is the one that matches a
                // Windows guest whose VNC head is primary: with ours assumed
                // first we address the primary and every click lands on the
                // screen nobody can see.
                //
                // It is ONE prefix for the whole desktop, so it shifts where
                // our first head starts and nothing else. Adding it to every
                // head instead gave every head the same origin - it is only
                // ever written to head 0's slot (see guest.rs), so head 1
                // read (0,0) and landed exactly where head 0 already was,
                // and the pointer moved identically on both monitors.
                let unseen = vms
                    .get(active)
                    .map_or((0, 0), |v| guest::frame(&v.head(0).shared).unseen);
                let mut gx = unseen.0;
                let mut desktop = (unseen.0, unseen.1);
                for hi in 0..heads.len() {
                    let size = vms.get(active).map_or((0, 0), |v| v.head(hi).size);
                    // The guest's own layout, which is the one we dictated:
                    // scanouts left to right in head order. Summed from the
                    // sizes the guest actually produced rather than from the
                    // head widths, because a scanout is the drawing area we
                    // gave it, not the whole panel.
                    let off = (gx, 0u32);
                    gx += size.0;
                    desktop.0 = desktop.0.max(off.0 + size.0);
                    desktop.1 = desktop.1.max(off.1 + size.1);
                    if hi == ih {
                        area = viewports
                            .get(hi)
                            .copied()
                            .flatten()
                            .map(|r| input::GuestArea { view: px(r), size, off });
                    }
                }
                let mut st = inp.state.lock().unwrap();
                st.area = area;
                st.desktop = desktop;
                // Console 0's scanout is the range SetAbsPosition accepts,
                // whichever head takes input.
                st.range = vms.get(active).map_or((0, 0), |v| v.head(0).size);
                st.relative = vms
                    .get(active)
                    .is_some_and(|v| guest::frame(&v.head(0).shared).pointer_relative);
                st.chrome = chromes.get(ih).copied().flatten().map(px);
            }

            // Only heads still in the set that queued a flip this frame.
            let wait: Vec<u32> =
                heads.iter().map(|h| h.crtc.into()).filter(|c| flipped.contains(c)).collect();
            if !wait.is_empty() {
                win_frames += 1;
                stats::BUSY_NS.fetch_add(
                    frame_t0.elapsed().as_nanos() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                stats::FRAMES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            match drm::wait_for_flips(&mut gpu.drm, gpu.raw_fd, &wait, n) {
                Ok(()) => {
                    for head in heads.iter_mut().filter(|h| wait.contains(&h.crtc.into())) {
                        if let Err(e) = head.surface.frame_submitted() {
                            log::warn!("{}: frame_submitted: {e}; resetting its buffers", head.name);
                            head.surface.reset_buffers();
                            redraw_all = true;
                        }
                    }
                }
                Err(e) => {
                    // A flip that never arrives - DRM master taken away, or the
                    // GPU stalled behind a hung VF - must not take the console
                    // down. Forget the queued flips and draw every head afresh.
                    let master = drm::acquire_master(gpu.raw_fd);
                    log::warn!(
                        "{e}; dropping the queued flips and redrawing every head (DRM master {})",
                        if master { "held" } else { "NOT held" }
                    );
                    for head in heads.iter_mut() {
                        head.surface.reset_buffers();
                    }
                    redraw_all = true;
                }
            }
            if quiesce {
                let _ = gpu.renderer.with_context(|gl| unsafe {
                    use glow::HasContext as _;
                    gl.finish();
                });
            }
            n_done = n + 1;
            if wait.is_empty() {
                // Nothing changed anywhere: sleep until something does, or
                // the status text or an egui animation is due. Bounded, so a
                // hotplug or a pillar update is never more than 0.5s late.
                let tick = start + std::time::Duration::from_millis((status_tick + 1) * 500);
                let until = repaint_at.iter().flatten().fold(tick, |a, t| a.min(*t));
                wake::wait(until.saturating_duration_since(std::time::Instant::now()));
            }

            // Every 30s, not every 2s. At 60fps a two-second heartbeat is
            // 43k lines a day, which pushed anything worth reading out of the
            // rotation long before anyone came to look for it.
            if last_log.elapsed() >= std::time::Duration::from_secs(30) {
                last_log = std::time::Instant::now();
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
                let guest = gfps_now[..heads.len().min(stats::MAX_HEADS)]
                    .iter()
                    .map(|g| format!("{g:.1}"))
                    .collect::<Vec<_>>()
                    .join("/");
                log::info!(
                    "frame {n}: {:.1} fps drawn avg  guest {guest} fps{lat}",
                    stats::FRAMES.load(std::sync::atomic::Ordering::Relaxed) as f64
                        / start.elapsed().as_secs_f64()
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
    geom: &[Option<guest::HeadGeometry>],
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
        let alive = vm.source.is_empty() || !guest::frame(&vm.head(0).shared).gone;
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
                let (shared, tx) = guest::spawn(name, guest::Transport::Fd(fd), geom.to_vec());
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

/// Turn a filled-in dialog into the request pillar already understands. Parse
/// failures are an error rather than a default: a silently-dropped field here
/// is a node that answers on an address nobody expects.
fn interface_request(
    e: &ui::PortEdit,
    live_ntp: &str,
) -> anyhow::Result<crate::ipc::message::IpcMessage> {
    use crate::ipc::monitorapi::{IpMode, ProxySettings, SetInterfaceConfig, StaticIpConfig};
    let ip = if e.dhcp {
        IpMode::Dhcp
    } else {
        let dns = e
            .dns
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<std::net::IpAddr>())
            .collect::<Result<Vec<_>, _>>()?;
        let gateway = match e.gateway.trim() {
            "" => None,
            g => Some(g.parse::<std::net::IpAddr>()?),
        };
        IpMode::Static {
            config: StaticIpConfig {
                ip: e.addr.trim().parse()?,
                subnet: e.subnet.trim().parse()?,
                gateway,
                dns_servers: dns,
            },
        }
    };
    // Only send NTP when the operator actually changed it. What the page
    // shows is what pillar reports, which already includes whatever DHCP
    // supplied; sending that back makes it a manual override that pillar then
    // adds to the DHCP list again, so the field grew by one copy of itself on
    // every apply. Unchanged means "no opinion", which is an empty list.
    let edited = e.ntp.trim() != live_ntp.trim();
    let mut ntp: Vec<String> = Vec::new();
    if edited {
        for host in e.ntp.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            // Defensive: the operator may paste a list that already repeats.
            if !ntp.iter().any(|h| h == host) {
                ntp.push(host.to_string());
            }
        }
    }
    Ok(crate::ipc::message::IpcMessage::new_request(
        crate::ipc::message::Request::SetInterfaceConfig(SetInterfaceConfig {
            iface: e.iface.clone(),
            ip,
            // The dialog does not touch proxy settings; None is the contract's
            // "no proxy", not a placeholder.
            proxy: ProxySettings::None,
            ntp,
            domain: String::new(),
        }),
    ))
}

/// The physical monitor a guest scanout is shown on, as the guest should see
/// it. Index is the scanout: scanout 0 goes on the first head, and so on, so
/// the guest's displays line up with the operator's.
fn head_geometry(heads: &[drm::Head], idx: usize) -> Option<guest::HeadGeometry> {
    let h = heads.get(idx)?;
    let (mm_w, mm_h) = h.mm.unwrap_or((0, 0));
    Some(guest::HeadGeometry {
        w: h.w as u32,
        h: h.h as u32,
        mm_w: mm_w as u16,
        mm_h: mm_h as u16,
        // Left to right in head order. The physical arrangement on the desk
        // is not knowable from DRM - only a human knows that - so this is a
        // default, not a discovery.
        xoff: heads[..idx].iter().map(|p| p.w).sum(),
        yoff: 0,
    })
}

/// The geometry last asked of one head's guest.
///
/// Carries WHEN WE asked, because that is what decides whether a
/// disagreement is ours to fix. A guest that has not caught up with a change
/// we just made should be asked again; a guest whose own operator picked a
/// resolution five minutes ago has made a decision, and overriding it is
/// what turned a settings dialog into a fight neither side could win.
#[derive(Clone, Copy)]
struct Told {
    want: (u32, u32),
    /// When we last changed our mind about the area.
    asked: std::time::Instant,
    /// When we last said so, re-asks included.
    said: std::time::Instant,
}

/// How long after our own change we keep chasing a guest that has not
/// adopted it. Long enough for a desktop still starting up - measured at two
/// re-asks before GNOME took the size - and short enough that a later change
/// by the guest's own operator is left alone.
const CHASE: std::time::Duration = std::time::Duration::from_secs(20);
/// Gap between re-asks. Each one makes the guest re-probe its displays.
const CHASE_GAP: std::time::Duration = std::time::Duration::from_secs(3);

/// Modes a guest is likely to already know, smallest first.
///
/// Not a complete list and not meant to be: it only has to contain something
/// close above any area this console can hand a guest, so that the guest is
/// asked for a size it recognises rather than one derived from our own
/// chrome layout.
const STANDARD_MODES: &[(u32, u32)] = &[
    (640, 480),
    (800, 600),
    (1024, 768),
    (1280, 720),
    (1280, 800),
    (1280, 1024),
    (1366, 768),
    (1440, 900),
    (1600, 900),
    (1600, 1200),
    (1680, 1050),
    (1920, 1080),
    (1920, 1200),
    (2048, 1152),
    (2560, 1080),
    (2560, 1440),
    (2560, 1600),
    (3440, 1440),
    (3840, 1600),
    (3840, 2160),
];

/// The mode to ask a guest for, given the area it will be drawn in.
///
/// The smallest standard mode that COVERS the area, so the image is only
/// ever scaled down into place - never up, which would blur text - and never
/// larger than the head's own mode, which is the most the panel can show.
/// Falls back to the head's mode when nothing in the table fits, which is
/// also the right answer for an unusual panel.
fn standard_mode(want: (u32, u32), native: (u32, u32)) -> (u32, u32) {
    STANDARD_MODES
        .iter()
        .copied()
        .filter(|&(w, h)| w >= want.0 && h >= want.1 && w <= native.0 && h <= native.1)
        .min_by_key(|&(w, h)| u64::from(w) * u64::from(h))
        .unwrap_or(native)
}

/// The geometry of every head, in the order the guest's scanouts map onto them.
fn head_geometries(heads: &[drm::Head]) -> Vec<Option<guest::HeadGeometry>> {
    (0..heads.len()).map(|i| head_geometry(heads, i)).collect()
}

/// Every port, with the detail the Network page shows.
fn ports_of(p: &crate::ipc::PillarState) -> Vec<ui::PortView> {
    let Some(n) = p.network.as_ref() else { return Vec::new() };
    n.interfaces
        .iter()
        .map(|i| ui::PortView {
            name: i.name.clone(),
            label: i.label.clone(),
            mac: i.mac.clone(),
            up: i.up,
            mgmt: i.is_mgmt,
            cost: i.cost,
            media: format!("{:?}", i.media),
            dhcp: i.network.is_dhcp,
            ipv4: i.network.ipv4.iter().map(|a| a.to_string()).collect(),
            subnet: i.network.subnet.map(|s| s.to_string()).unwrap_or_default(),
            routes: i.network.routes.iter().map(|a| a.to_string()).collect(),
            dns: i.network.dns_servers.iter().map(|a| a.to_string()).collect(),
            ntp: i.network.ntp_servers.clone(),
            errors: i.network.errors.clone(),
        })
        .collect()
}

/// App instances, with whether this console can show one.
fn apps_of(p: &crate::ipc::PillarState) -> Vec<ui::AppView> {
    p.apps
        .iter()
        .map(|a| ui::AppView {
            name: a.name.clone(),
            uuid: a.uuid.to_string(),
            version: a.version.clone(),
            state: format!("{:?}", a.state),
            error: a.error.clone(),
            has_console: !a.qmp_socket.is_empty(),
        })
        .collect()
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
        let vm = Vm::new(name.into(), vec![shared], tx);
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
        let shared = vm.head(0).shared.clone();
        let _ = std::thread::spawn(move || {
            let _g = shared.lock().unwrap();
            panic!("a guest listener died");
        })
        .join();
        assert!(vm.head(0).shared.is_poisoned(), "the test needs a poisoned mutex");

        // The render thread's accessor must still hand back the frame.
        let f = guest::frame(&vm.head(0).shared);
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
        assert!(!reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff, &[]));
        assert_eq!(vms.len(), 1);

        vms[0].head(0).shared.lock().unwrap().gone = true;
        let changed = reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff, &[]);
        assert!(vms.is_empty(), "a dead guest must not keep its tab");
        assert!(changed, "the active slot changed hands and input must be re-pointed");
    }

    /// The hand-configured tab from GUI_VMS has no socket to re-attach to, so
    /// dropping it on death would remove it for good. See the Task 8 ruling.
    #[test]
    fn keeps_a_hand_configured_tab_whose_guest_died() {
        let pillar = pillar_listing(&[]);
        let mut vms = vec![a_vm("manual", "")];
        vms[0].head(0).shared.lock().unwrap().gone = true;
        let mut active = 0usize;
        let mut backoff = Backoff::default();

        assert!(!reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff, &[]));
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
        assert!(!reconcile_tabs(&mut vms, &pillar, &mut active, &mut backoff, &[]));
        assert!(vms.is_empty());
    }
}
