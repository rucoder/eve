// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! EVE GUI monitor.
//!
//! An egui interface drawn straight onto the console through DRM/KMS, with each
//! VM's framebuffer rendered into a tab. There is no Wayland, no X and no seat
//! manager: EVE has none of them, and this runs as plain root on a VT.
//!
//! The point of it is to stop passing the iGPU through to guests. A guest gets
//! a virtual GPU instead, and its framebuffer is composited here.

mod drm;
mod guest;
mod input;
mod ipc;
mod logger;
mod qmp;
mod scanout;
mod ui;
mod vt;

use std::sync::Arc;

use smithay::backend::renderer::{Bind, Color32F, Frame as _, Renderer};
use smithay::utils::{Rectangle, Transform};

use scanout::Vm;

/// egui points-per-pixel. The console is small and far away; 1.0 is unreadable.
/// Shared with the input thread, which converts the same coordinates.
pub const POINTS_PER_PIXEL: f32 = 2.0;

struct Config {
    card: String,
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
            card: std::env::args()
                .nth(1)
                .or_else(|| env("GUI_CARD"))
                .unwrap_or_else(|| "/dev/dri/card0".into()),
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

fn main() -> anyhow::Result<()> {
    logger::init();
    let cfg = Config::from_env();
    // Held for the whole run; Drop puts the VT keyboard back.
    let _vtkbd = vt::VtKeyboard::take();
    vt::install_signal_handlers();
    log::info!("orientation mode = {} (0=none 1=flipY 2=flipX 3=rot180)", cfg.orient);

    let mut gpu = drm::open(&cfg.card)?;
    let mut heads = drm::discover_heads(&mut gpu)?;

    // egui_glow painter sharing smithay's GL context.
    let gl: Arc<glow::Context> = gpu.renderer.with_context(|gl| gl.clone())?;
    let mut painter = egui_glow::Painter::new(gl, "", None, false)
        .map_err(|e| anyhow::anyhow!("egui_glow painter: {e}"))?;
    let egui_ctx = egui::Context::default();
    log::info!("egui_glow painter created on smithay's GL context");

    let mut vms = spawn_vms(&cfg.vms);
    anyhow::ensure!(!vms.is_empty(), "no VMs: set GUI_VMS=\"linux=<bus>;windows=<bus>\"");
    let mut active = 0usize;

    let inp = input::spawn(heads[0].w, heads[0].h, cfg.ptr_scale)?;
    inp.set_active(vms[active].tx.clone());
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

            // Guest framebuffer: once per frame, not once per head.
            vms[active].update(&mut gpu.renderer, &mut painter, &egui_ctx, cfg.probe, n);

            // Guest hardware cursor.
            {
                let g = vms[active].shared.lock().unwrap();
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
                gfps_now = vms[active].seq.saturating_sub(win_gseq) as f32 / wdt;
                win_t = std::time::Instant::now();
                win_frames = 0;
                win_gseq = vms[active].seq;
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

                let tabs: Vec<String> = vms.iter().map(|v| v.name.clone()).collect();
                let (orphans, cursor_visible, has_cursor) = {
                    let g = vms[active].shared.lock().unwrap();
                    (g.orphan_updates, g.cursor_visible, g.cursor.is_some())
                };
                let view = ui::Frame {
                    head: &head_name,
                    fps: fps_now,
                    guest_fps: gfps_now,
                    frame: n,
                    elapsed: start.elapsed().as_secs_f32(),
                    tabs: &tabs,
                    active,
                    focus,
                    pointer: egui::pos2(cx / POINTS_PER_PIXEL, cy / POINTS_PER_PIXEL),
                    guest: ui::GuestView {
                        dma_id: vms[active].dma_id,
                        dma_size: vms[active].dma_size,
                        dma_flip: vms[active].dma_flip,
                        tex: vms[active].tex.as_ref(),
                        seq: vms[active].seq,
                        orphan_updates: orphans,
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
            let want = hot_tab.filter(|t| *t < vms.len()).or(act.tab);
            if let Some(t) = want {
                if t != active {
                    active = t;
                    inp.set_active(vms[active].tx.clone());
                    win_gseq = vms[active].seq; // not a real rate jump
                    cur_seq = u64::MAX; // reload this guest's cursor
                    log::info!("tab -> {}", vms[active].name);
                }
            }
            if act.send_wake {
                send_keys(&vms[active], &[(input::KEY_LEFTSHIFT, true), (input::KEY_LEFTSHIFT, false)]);
                log::info!("sent wake keystroke to {}", vms[active].name);
            }
            if act.send_cad {
                send_keys(&vms[active], input::CTRL_ALT_DEL);
                log::info!("sent Ctrl+Alt+Del to {}", vms[active].name);
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
                st.guest_size = vms[active].size;
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
    shutdown(gpu, heads, vms, painter);
    loop_result
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
) {
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
