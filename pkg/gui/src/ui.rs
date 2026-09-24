// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The on-screen chrome: tab bar, status line, the guest image and the cursor.
//!
//! Everything the UI needs arrives in [`Frame`] and everything it wants done
//! leaves in [`Actions`], so the frame loop owns all the state and this module
//! stays a pure function of it.

use crate::input::Focus;

/// The active guest's framebuffer, whichever path produced it.
pub struct GuestView<'a> {
    pub dma_id: Option<egui::TextureId>,
    pub dma_size: egui::Vec2,
    pub dma_flip: bool,
    pub tex: Option<&'a egui::TextureHandle>,
    pub seq: u64,
    /// Updates that arrived with no scanout - the guest's display is asleep.
    pub orphan_updates: u64,
}

/// A hardware cursor the guest published, for us to draw locally.
pub struct CursorView<'a> {
    pub tex: &'a egui::TextureHandle,
    pub hotspot: (f32, f32),
}

pub struct Frame<'a> {
    pub head: &'a str,
    pub fps: f32,
    pub guest_fps: f32,
    pub frame: u32,
    pub elapsed: f32,
    pub tabs: &'a [String],
    pub active: usize,
    pub focus: Focus,
    /// Host pointer, in egui points.
    pub pointer: egui::Pos2,
    pub guest: GuestView<'a>,
    pub cursor: Option<CursorView<'a>>,
}

#[derive(Default)]
pub struct Actions {
    /// A tab the user clicked.
    pub tab: Option<usize>,
    pub send_cad: bool,
    pub send_wake: bool,
    /// Where the guest image landed, in points. Input maps through this.
    pub viewport: Option<egui::Rect>,
}

pub fn draw(ctx: &egui::Context, f: &Frame) -> Actions {
    let mut act = Actions::default();
    top_bar(ctx, f, &mut act);
    egui::CentralPanel::default().show(ctx, |ui| central(ui, f, &mut act));
    // Our own pointer goes on a foreground layer so no panel can clip it, and
    // only over OUR chrome: inside the guest view either the guest composites
    // its cursor or we drew it above, and a second arrow looks broken.
    let over_guest = act.viewport.is_some_and(|r| r.contains(f.pointer));
    if f.focus == Focus::Gui && !over_guest {
        draw_arrow(ctx, f.pointer);
    }
    act
}

fn top_bar(ctx: &egui::Context, f: &Frame, act: &mut Actions) {
    egui::TopBottomPanel::top("bar").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.heading("EVE GUI");
            ui.separator();
            for (i, name) in f.tabs.iter().enumerate() {
                if ui.selectable_label(i == f.active, name).clicked() {
                    act.tab = Some(i);
                }
            }
            ui.separator();
            // The chord itself is forwarded too (see vt::VtKeyboard), but a
            // Windows logon screen is precisely where you are not grabbed yet.
            if ui
                .button("Ctrl+Alt+Del")
                .on_hover_text("send to the active guest")
                .clicked()
            {
                act.send_cad = true;
            }
            // A blanked guest display makes QEMU withhold the scanout, so there
            // is nothing to draw until something wakes it. A keystroke does;
            // pointer motion does not reliably.
            if ui
                .button("Wake")
                .on_hover_text("tap Shift in the active guest to wake its display")
                .clicked()
            {
                act.send_wake = true;
            }
            ui.separator();
            ui.label(format!(
                "{}  ·  {:.0} fps  ·  guest {:.0} fps  ·  frame {}  ·  t={:.1}s",
                f.head, f.fps, f.guest_fps, f.frame, f.elapsed
            ));
            ui.separator();
            ui.label(match (f.guest.tex, f.guest.dma_id) {
                (_, Some(_)) => format!(
                    "guest: {}x{} dmabuf zero-copy (frame {})",
                    f.guest.dma_size.x, f.guest.dma_size.y, f.guest.seq
                ),
                (Some(t), _) => {
                    format!("guest: {}x{} copy (frame {})", t.size()[0], t.size()[1], f.guest.seq)
                }
                _ => "guest: waiting for scanout…".to_string(),
            });
            ui.separator();
            let (colour, text) = match f.focus {
                Focus::Guest => (egui::Color32::LIGHT_GREEN, "INPUT -> GUEST  (Ctrl+Alt+G to release)"),
                Focus::Gui => (egui::Color32::GRAY, "INPUT -> GUI    (click the VM to grab)"),
            };
            ui.colored_label(colour, text);
            ui.separator();
            ui.weak("Ctrl+Alt+1/2 = tab");
        });
    });
}

fn central(ui: &mut egui::Ui, f: &Frame, act: &mut Actions) {
    let avail = ui.available_rect_before_wrap();
    let src = if f.guest.dma_id.is_some() {
        Some(f.guest.dma_size)
    } else {
        f.guest.tex.map(|t| t.size_vec2())
    };

    let Some(sz) = src else {
        ui.centered_and_justified(|ui| {
            if f.guest.orphan_updates > 0 {
                ui.label(format!(
                    "guest is sending updates ({}) but QEMU never sent a scanout \
                     — its display is asleep.\nPress Wake.",
                    f.guest.orphan_updates
                ));
            } else {
                ui.label("no guest framebuffer yet — is the VM running?");
            }
        });
        return;
    };

    // Letterbox by hand. Relying on centered_and_justified's response rect gave
    // the FULL panel, which skewed the host->guest mapping and made clicks land
    // in the wrong place.
    let k = (avail.width() / sz.x).min(avail.height() / sz.y);
    let draw = sz * k;
    let rect = egui::Rect::from_center_size(avail.center(), draw);

    match f.guest.dma_id {
        Some(id) => {
            let uv = if f.guest.dma_flip {
                egui::Rect::from_min_max(egui::pos2(0.0, 1.0), egui::pos2(1.0, 0.0))
            } else {
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0))
            };
            ui.put(rect, egui::Image::new(egui::load::SizedTexture::new(id, draw)).uv(uv));
        }
        None => {
            if let Some(t) = f.guest.tex {
                ui.put(rect, egui::Image::new(t).fit_to_exact_size(draw));
            }
        }
    }

    // The guest published its hardware cursor bitmap, so draw it at OUR pointer
    // position: that costs no round trip. A guest that composites its cursor
    // into the framebuffer instead can only show it after a guest redraw plus
    // our next frame, which is what made the pointer feel laggy.
    if let Some(c) = &f.cursor {
        if rect.contains(f.pointer) {
            let at = f.pointer - egui::vec2(c.hotspot.0 * k, c.hotspot.1 * k);
            ui.painter().image(
                c.tex.id(),
                egui::Rect::from_min_size(at, c.tex.size_vec2() * k),
                egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                egui::Color32::WHITE,
            );
        }
    }
    act.viewport = Some(rect);
}

/// A standard arrow, as an explicit triangle mesh: the shape is concave, so
/// `convex_polygon` renders it wrong.
fn draw_arrow(ctx: &egui::Context, p: egui::Pos2) {
    const OUTLINE: [(f32, f32); 7] = [
        (0.0, 0.0), (0.0, 15.6), (4.3, 11.7), (6.9, 18.2), (9.4, 17.1), (6.8, 10.8), (11.4, 10.6),
    ];
    let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("ptr")));
    let v: Vec<egui::Pos2> = OUTLINE.iter().map(|(x, y)| p + egui::vec2(*x, *y)).collect();

    let mut mesh = egui::Mesh::default();
    for q in &v {
        mesh.vertices.push(egui::epaint::Vertex {
            pos: *q,
            uv: egui::epaint::WHITE_UV,
            color: egui::Color32::WHITE,
        });
    }
    for tri in [[0u32, 1, 2], [0, 2, 6], [2, 3, 5], [3, 4, 5], [2, 5, 6]] {
        mesh.indices.extend_from_slice(&tri);
    }
    painter.add(egui::Shape::mesh(mesh));

    let mut outline = v.clone();
    outline.push(v[0]);
    painter.add(egui::Shape::line(outline, egui::Stroke::new(1.0_f32, egui::Color32::from_gray(20))));
}

/// Correct egui's output for the FBO/scanout coordinate mismatch.
///
/// mode: 0=none 1=flipY 2=flipX 3=rot180. Settled empirically on the target
/// hardware; flipY is the one that is right for a GBM scanout buffer.
pub fn fix_orientation(prims: &mut [egui::ClippedPrimitive], w: f32, h: f32, mode: u8) {
    if mode == 0 {
        return;
    }
    let fx = |x: f32| if mode == 2 || mode == 3 { w - x } else { x };
    let fy = |y: f32| if mode == 1 || mode == 3 { h - y } else { y };
    for p in prims.iter_mut() {
        let r = p.clip_rect;
        let (x0, x1) = (fx(r.min.x), fx(r.max.x));
        let (y0, y1) = (fy(r.min.y), fy(r.max.y));
        p.clip_rect = egui::Rect::from_min_max(
            egui::pos2(x0.min(x1), y0.min(y1)),
            egui::pos2(x0.max(x1), y0.max(y1)),
        );
        if let egui::epaint::Primitive::Mesh(m) = &mut p.primitive {
            for v in m.vertices.iter_mut() {
                v.pos = egui::pos2(fx(v.pos.x), fy(v.pos.y));
            }
            if mode != 3 {
                m.indices.chunks_mut(3).for_each(|t| t.swap(0, 2));
            }
        }
    }
}
