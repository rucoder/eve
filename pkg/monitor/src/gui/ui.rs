// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! The on-screen chrome: tab bar, status line, the guest image and the cursor.
//!
//! Everything the UI needs arrives in [`Frame`] and everything it wants done
//! leaves in [`Actions`], so the frame loop owns all the state and this module
//! stays a pure function of it.

use crate::gui::input::Focus;

/// The active guest's framebuffer, whichever path produced it.
pub struct GuestView<'a> {
    pub dma_id: Option<egui::TextureId>,
    pub dma_size: egui::Vec2,
    pub dma_flip: bool,
    pub tex: Option<&'a egui::TextureHandle>,
    pub seq: u64,
    /// Updates that arrived with no scanout - the guest's display is asleep.
    pub orphan_updates: u64,
    /// What QEMU said this buffer is. On screen because a wrong format shows
    /// up as a blank tab, which looks identical to a guest that is not
    /// drawing - and the logs that would tell them apart are at whatever
    /// level pillar last set.
    pub desc: Option<crate::gui::scanout::GuestDesc>,
    /// Non-black pixels the readback last found in the blit target, when
    /// GUI_PROBE is on: the one fact that separates "we sampled nothing" from
    /// "the guest drew nothing".
    pub probe_nonblack: Option<(usize, usize)>,
}

/// The pixel format, tiling and readback of the active guest's buffer, as a
/// suffix for the status line. Empty when there is nothing to say yet.
fn guest_detail(g: &GuestView<'_>) -> String {
    let Some(d) = g.desc else { return String::new() };
    let fourcc = d.fourcc.to_le_bytes();
    let name: String = fourcc.iter().map(|&c| c as char).collect();
    let probe = match g.probe_nonblack {
        Some((nz, total)) => format!("  ·  {nz}/{total} non-black"),
        None => String::new(),
    };
    format!(
        "  ·  {name} (0x{:08x}) mod=0x{:x} stride={} y0={}{}",
        d.fourcc,
        d.modifier,
        d.stride,
        if d.y0_top { "top" } else { "bottom" },
        probe,
    )
}

/// Which page of the node tab is showing. Mirrors the TUI's tabs, minus the
/// two it has that we have no data for over IPC (Vault, Dmesg).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodePage {
    Summary,
    Network,
    Apps,
}

impl NodePage {
    pub const ALL: [NodePage; 3] = [NodePage::Summary, NodePage::Network, NodePage::Apps];
    fn title(self) -> &'static str {
        match self {
            NodePage::Summary => "Summary",
            NodePage::Network => "Network",
            NodePage::Apps => "Applications",
        }
    }
}

/// One network port, as the Network page shows it.
pub struct PortView {
    pub name: String,
    pub label: String,
    pub mac: String,
    pub up: bool,
    pub mgmt: bool,
    pub cost: u8,
    pub media: String,
    pub dhcp: bool,
    pub ipv4: Vec<String>,
    pub subnet: String,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub ntp: Vec<String>,
    pub errors: Vec<String>,
}

/// One app instance, as the Applications page shows it.
pub struct AppView {
    pub name: String,
    pub uuid: String,
    pub version: String,
    pub state: String,
    pub error: String,
    pub has_console: bool,
}

/// A hardware cursor the guest published, for us to draw locally.
pub struct CursorView<'a> {
    pub tex: &'a egui::TextureHandle,
    pub hotspot: (f32, f32),
}

/// What the Node tab shows, from pillar's DeviceStatus and NetworkStatus.
pub struct NodeView<'a> {
    pub name: &'a str,
    pub serial: &'a str,
    pub server: &'a str,
    pub model: &'a str,
    /// (interface, address). Empty until pillar reports any.
    pub interfaces: &'a [(String, String)],
    pub connected: bool,
}

/// What the Node tab shows about the console's own display. Worth surfacing:
/// a resolution that looks wrong is usually explained by the EDID column -
/// without one the driver invents a preferred mode, and under QEMU it tracks
/// the window rather than anything the operator chose.
pub struct DisplayView<'a> {
    pub card: &'a str,
    pub connector: &'a str,
    pub w: i32,
    pub h: i32,
    pub refresh: u32,
    pub edid: bool,
    pub pinned: Option<&'a str>,
    pub scale: f32,
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
    pub node: NodeView<'a>,
    pub display: DisplayView<'a>,
    /// Tab 0 is the node page; guests follow.
    pub node_tab: bool,
    /// Chrome hidden, guest filling the head. The bar comes back as an
    /// overlay while the pointer is at the top edge.
    pub fullscreen: bool,
    /// Which page the node tab is showing.
    pub page: NodePage,
    pub ports: &'a [PortView],
    pub apps: &'a [AppView],
}

#[derive(Default)]
pub struct Actions {
    /// A tab the user clicked.
    pub tab: Option<usize>,
    /// A node-page the user clicked in the side nav.
    pub page: Option<NodePage>,
    pub send_cad: bool,
    pub send_wake: bool,
    /// Where the guest image landed, in points. Input maps through this.
    pub viewport: Option<egui::Rect>,
}

/// How close to the top edge, in points, reveals the chrome in fullscreen.
/// Deliberately generous: a pointer that is being *thrown* at the edge
/// overshoots by a few pixels and then sits exactly at 0, but one moved by
/// hand stops short, and a 2px strip is unhittable on a 1080p panel.
const REVEAL_BAND: f32 = 48.0;

pub fn draw(ctx: &egui::Context, f: &Frame) -> Actions {
    let mut act = Actions::default();
    // In fullscreen the bar is drawn last, as an overlay, so it sits above
    // the guest image instead of taking space from it.
    let reveal = f.pointer.y <= REVEAL_BAND;
    if !f.fullscreen {
        top_bar(ctx, f, &mut act);
    }
    let frame = if f.fullscreen {
        // No margins and no rounding: every point belongs to the guest.
        egui::Frame::NONE.fill(ctx.style().visuals.panel_fill)
    } else {
        egui::Frame::central_panel(&ctx.style())
    };
    egui::CentralPanel::default().frame(frame).show(ctx, |ui| central(ui, f, &mut act));
    if f.fullscreen && reveal {
        egui::Area::new(egui::Id::new("fs_bar"))
            .order(egui::Order::Foreground)
            .fixed_pos(egui::pos2(0.0, 0.0))
            .show(ctx, |ui| {
                let w = ctx.screen_rect().width();
                egui::Frame::NONE
                    .fill(ui.visuals().panel_fill.gamma_multiply(0.94))
                    .inner_margin(egui::Margin::symmetric(8, 4))
                    .show(ui, |ui| {
                        ui.set_width(w - 16.0);
                        bar_contents(ui, f, &mut act);
                    });
            });
    }
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
    egui::TopBottomPanel::top("bar").show(ctx, |ui| bar_contents(ui, f, act));
}

/// The chrome itself, so the panel and the fullscreen overlay draw the same
/// thing rather than drifting apart.
fn bar_contents(ui: &mut egui::Ui, f: &Frame, act: &mut Actions) {
    {
        ui.horizontal(|ui| {
            ui.heading("EVE GUI");
            ui.separator();
            for (i, name) in f.tabs.iter().enumerate() {
                if ui.selectable_label(i == f.active, name).clicked() {
                    act.tab = Some(i);
                }
            }
            ui.separator();
            // The chord itself is forwarded too (see vt::CtrlAltDelGuard), but a
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
                    "guest: {}x{} dmabuf zero-copy (frame {}){}",
                    f.guest.dma_size.x,
                    f.guest.dma_size.y,
                    f.guest.seq,
                    guest_detail(&f.guest),
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
            ui.separator();
            ui.weak(if f.fullscreen {
                "Ctrl+Alt+F = leave fullscreen"
            } else {
                "Ctrl+Alt+F = fullscreen"
            });
        });
    }
}

fn central(ui: &mut egui::Ui, f: &Frame, act: &mut Actions) {
    if f.node_tab {
        // Vertical nav on the left, like the TUI's tab strip but down the
        // side: the pages are few and their names are words, so a column
        // costs less width than a row costs height on a 4:3 guest head.
        egui::SidePanel::left("node_nav")
            .resizable(false)
            .exact_width(170.0)
            .show_inside(ui, |ui| {
                ui.add_space(12.0);
                for p in NodePage::ALL {
                    let hit = ui.add_sized(
                        [ui.available_width(), 32.0],
                        egui::SelectableLabel::new(p == f.page, p.title()),
                    );
                    if hit.clicked() {
                        act.page = Some(p);
                    }
                    ui.add_space(4.0);
                }
            });
        match f.page {
            NodePage::Summary => node_page(ui, &f.node, &f.display, f.fps, &f.guest),
            NodePage::Network => network_page(ui, f.ports),
            NodePage::Apps => apps_page(ui, f.apps),
        }
        return;
    }
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

/// Every port pillar reports, with the detail the summary has no room for.
fn network_page(ui: &mut egui::Ui, ports: &[PortView]) {
    ui.add_space(12.0);
    ui.heading("Network");
    ui.add_space(8.0);
    if ports.is_empty() {
        ui.label("no ports reported yet");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        for p in ports {
            let title = format!(
                "{}{}  ·  {}  ·  {}{}",
                p.name,
                if p.label.is_empty() || p.label == p.name { String::new() } else { format!(" ({})", p.label) },
                if p.up { "up" } else { "down" },
                if p.mgmt { "management" } else { "app-only" },
                if p.cost > 0 { format!("  ·  cost {}", p.cost) } else { String::new() },
            );
            ui.add_space(6.0);
            ui.label(egui::RichText::new(title).strong());
            egui::Grid::new(format!("port_{}", p.name))
                .num_columns(2)
                .spacing([24.0, 6.0])
                .show(ui, |ui| {
                    let join = |v: &Vec<String>| if v.is_empty() { "—".to_string() } else { v.join(", ") };
                    for (k, v) in [
                        ("MAC", p.mac.clone()),
                        ("Media", p.media.clone()),
                        ("Address", format!("{}{}", join(&p.ipv4),
                            if p.dhcp { "  (DHCP)" } else { "  (static)" })),
                        ("Subnet", if p.subnet.is_empty() { "—".into() } else { p.subnet.clone() }),
                        ("Gateway", join(&p.routes)),
                        ("DNS", join(&p.dns)),
                        ("NTP", join(&p.ntp)),
                    ] {
                        ui.label(egui::RichText::new(k).weak());
                        ui.label(v);
                        ui.end_row();
                    }
                    if !p.errors.is_empty() {
                        ui.label(egui::RichText::new("Errors").weak());
                        ui.colored_label(egui::Color32::LIGHT_RED, p.errors.join("; "));
                        ui.end_row();
                    }
                });
            ui.add_space(6.0);
            ui.separator();
        }
    });
}

/// What pillar says is deployed here, and which of them this console can show.
fn apps_page(ui: &mut egui::Ui, apps: &[AppView]) {
    ui.add_space(12.0);
    ui.heading("Applications");
    ui.add_space(8.0);
    if apps.is_empty() {
        ui.label("no app instances on this node");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("apps")
            .num_columns(5)
            .spacing([24.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                for h in ["Name", "State", "Version", "Console", "UUID"] {
                    ui.label(egui::RichText::new(h).strong());
                }
                ui.end_row();
                for a in apps {
                    ui.label(&a.name);
                    // An app in error says so where it is read, not in a log.
                    if a.error.is_empty() {
                        ui.label(&a.state);
                    } else {
                        ui.colored_label(egui::Color32::LIGHT_RED, format!("{} — {}", a.state, a.error));
                    }
                    ui.label(if a.version.is_empty() { "—" } else { a.version.as_str() });
                    ui.label(if a.has_console { "yes" } else { "—" });
                    ui.label(egui::RichText::new(&a.uuid).weak());
                    ui.end_row();
                }
            });
    });
}

fn node_page(
    ui: &mut egui::Ui,
    n: &NodeView,
    d: &DisplayView,
    fps: f32,
    g: &GuestView<'_>,
) {
    if !n.connected {
        ui.centered_and_justified(|ui| ui.label("waiting for pillar…"));
        return;
    }
    // A 1080p panel, not an 80x25 terminal: two columns, generous spacing.
    ui.add_space(12.0);
    ui.columns(2, |col| {
        col[0].heading("Node");
        col[0].add_space(8.0);
        egui::Grid::new("node")
            .num_columns(2)
            .spacing([28.0, 10.0])
            .show(&mut col[0], |ui| {
                for (k, v) in [
                    ("Name", n.name),
                    ("Serial", n.serial),
                    ("Model", n.model),
                    ("Controller", n.server),
                ] {
                    ui.label(egui::RichText::new(k).strong());
                    ui.label(if v.is_empty() { "—" } else { v });
                    ui.end_row();
                }
            });

        col[1].heading("Network");
        col[1].add_space(8.0);
        egui::Grid::new("net")
            .num_columns(2)
            .spacing([28.0, 10.0])
            .show(&mut col[1], |ui| {
                if n.interfaces.is_empty() {
                    ui.label("no interfaces reported");
                    ui.end_row();
                }
                for (name, addr) in n.interfaces {
                    ui.label(egui::RichText::new(name).strong());
                    ui.label(if addr.is_empty() { "—" } else { addr.as_str() });
                    ui.end_row();
                }
            });
    });

    ui.add_space(18.0);
    ui.separator();
    ui.add_space(12.0);
    ui.heading("Display");
    ui.add_space(8.0);
    let mode = format!("{}x{} @ {}Hz", d.w, d.h, d.refresh);
    let scale = format!("{:.2}x", d.scale);
    let source = match (d.pinned, d.edid) {
        (Some(p), _) => format!("pinned to {p} in config.json"),
        (None, true) => "preferred mode from the display's EDID".to_string(),
        (None, false) => "largest mode offered - no EDID, so nothing states a preference".to_string(),
    };
    egui::Grid::new("display")
        .num_columns(2)
        .spacing([28.0, 10.0])
        .show(ui, |ui| {
            for (k, v) in [
                ("Resolution", mode.as_str()),
                ("Chosen", source.as_str()),
                ("UI scale", scale.as_str()),
                ("Card", d.card),
                ("Connector", d.connector),
            ] {
                ui.label(egui::RichText::new(k).strong());
                ui.label(if v.is_empty() { "—" } else { v });
                ui.end_row();
            }
            ui.label(egui::RichText::new("Rendering").strong());
            ui.label(format!("{fps:.0} fps"));
            ui.end_row();
        });

    // The active guest's buffer, in the same place an operator already looks
    // for what this console is drawing. A wrong pixel format shows up as a
    // blank tab, which is indistinguishable from a guest that is not drawing
    // until you can see the format.
    ui.add_space(18.0);
    ui.separator();
    ui.add_space(12.0);
    ui.heading("Guest");
    ui.add_space(8.0);
    egui::Grid::new("guest")
        .num_columns(2)
        .spacing([28.0, 10.0])
        .show(ui, |ui| {
            let path = match (g.tex, g.dma_id) {
                (_, Some(_)) => "dmabuf, zero-copy",
                (Some(_), _) => "copy, through host memory",
                _ => "—",
            };
            let size = match (g.dma_id, g.tex) {
                (Some(_), _) => format!("{}x{}", g.dma_size.x, g.dma_size.y),
                (None, Some(t)) => format!("{}x{}", t.size()[0], t.size()[1]),
                _ => "—".to_string(),
            };
            let mut rows = vec![
                ("Scanout".to_string(), path.to_string()),
                ("Size".to_string(), size),
                ("Frames".to_string(), g.seq.to_string()),
            ];
            if let Some(desc) = g.desc {
                let name: String = desc.fourcc.to_le_bytes().iter().map(|&c| c as char).collect();
                // What QEMU declared and what we import it as: they differ
                // whenever the declared format claimed an alpha channel a
                // scanout does not have.
                let mapped = crate::gui::scanout::opaque_name(desc.fourcc);
                rows.push((
                    "Format".to_string(),
                    format!("{name} (0x{:08x}) -> {mapped}", desc.fourcc),
                ));
                rows.push(("Modifier".to_string(), format!("0x{:x}", desc.modifier)));
                rows.push(("Stride".to_string(), format!("{} bytes", desc.stride)));
                rows.push((
                    "Origin".to_string(),
                    if desc.y0_top { "top-left" } else { "bottom-left" }.to_string(),
                ));
            }
            if let Some((nz, total)) = g.probe_nonblack {
                rows.push(("Readback".to_string(), format!("{nz} / {total} non-black px")));
            }
            for (k, v) in rows {
                ui.label(egui::RichText::new(k).strong());
                ui.label(v);
                ui.end_row();
            }
        });
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
