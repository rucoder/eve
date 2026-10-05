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
    /// the probe is on: the one fact that separates "we sampled nothing" from
    /// "the guest drew nothing".
    pub probe_nonblack: Option<(usize, usize)>,
    /// The guest told us it turned this display off.
    pub asleep: bool,
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
/// two it has that we have no data for over IPC (Vault, Dmesg), plus pillar's
/// debug options.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodePage {
    Summary,
    Network,
    Apps,
    Debug,
}

impl NodePage {
    pub const ALL: [NodePage; 4] =
        [NodePage::Summary, NodePage::Network, NodePage::Apps, NodePage::Debug];
    fn title(self) -> &'static str {
        match self {
            NodePage::Summary => "Summary",
            NodePage::Network => "Network",
            NodePage::Apps => "Applications",
            NodePage::Debug => "Debug",
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

/// A port being edited. Owned copies, taken from the cached PortView when the
/// dialog opens: pillar keeps updating underneath, and fields must not change
/// under the operator mid-edit.
#[derive(Clone)]
pub struct PortEdit {
    pub iface: String,
    pub dhcp: bool,
    pub addr: String,
    pub subnet: String,
    pub gateway: String,
    pub dns: String,
    pub ntp: String,
    /// What the port looked like before Apply, kept so Undo can put it back
    /// without asking pillar to remember anything.
    pub previous: Option<Box<PortEdit>>,
}

impl PortEdit {
    /// Every field parses, so Apply is safe to offer. DHCP needs nothing.
    pub fn valid(&self) -> bool {
        if self.dhcp {
            return true;
        }
        self.addr.trim().parse::<std::net::IpAddr>().is_ok()
            && subnet_ok(&self.subnet)
            && (self.gateway.trim().is_empty()
                || self.gateway.trim().parse::<std::net::IpAddr>().is_ok())
            && list_ok(&self.dns)
    }
}

fn subnet_ok(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty() && s.parse::<ipnet::IpNet>().is_ok()
}

fn list_ok(s: &str) -> bool {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .all(|x| x.parse::<std::net::IpAddr>().is_ok())
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
    /// This head takes input: it alone has the controls and a pointer. Every
    /// other head shows the same bar, read-only, and is never hit-tested.
    pub input: bool,
    /// The head that does, named on the others.
    pub input_head: &'a str,
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
    /// Pillar's debug options, as it last sent them.
    pub debug: &'a [crate::ipc::monitorapi::DebugOption],
    /// The port editor, when one is open.
    pub edit: Option<&'a PortEdit>,
    /// Whether the readback probe is running.
    pub probe: bool,
    /// Host-side memory for the active guest, if it has a cgroup yet.
    pub vmstat: Option<&'a crate::gui::vmstat::Series>,
    /// A remote session owns the guest's display, so we are not drawing it.
    pub remote: bool,
    /// The guest's pointer is relative (PS/2): it moves its own cursor from
    /// our deltas, and while grabbed ours stays frozen where the grab click
    /// was.
    pub relative: bool,
}

#[derive(Default)]
pub struct Actions {
    /// A tab the user clicked.
    pub tab: Option<usize>,
    /// A node-page the user clicked in the side nav.
    pub page: Option<NodePage>,
    /// Open the editor for this port.
    pub edit_port: Option<String>,
    /// The dialog's state changed; the render loop keeps it.
    pub edit_update: Option<PortEdit>,
    /// Send this configuration to pillar.
    pub apply_port: Option<PortEdit>,
    /// Close without sending.
    pub edit_cancel: bool,
    pub send_cad: bool,
    pub send_wake: bool,
    /// Leave fullscreen; the overlay's button, equivalent to Ctrl+Alt+F.
    pub toggle_fullscreen: bool,
    /// Ask pillar to set a debug option: key, value.
    pub set_debug: Option<(String, String)>,
    /// Chrome drawn over the guest, in points. Input must reach US here even
    /// while the guest holds the pointer, or the way out is unclickable
    /// exactly when it is needed.
    pub chrome: Option<egui::Rect>,
    /// The guest's own cursor was painted this frame. When it was not,
    /// somebody still has to draw one.
    pub guest_cursor: bool,
    /// Where the guest image landed, in points. Input maps through this.
    pub viewport: Option<egui::Rect>,
    /// The whole area the guest may draw in, in points - the letterboxed
    /// image's container. This, NOT `viewport`, is the size we ask the guest
    /// to render at: `viewport` is derived from the guest's current size, so
    /// asking for it feeds the guest's answer back into the next question.
    pub area: Option<egui::Rect>,
}

impl Actions {
    /// Fold another head's frame into this one.
    ///
    /// `draw` runs once per head and returns that head's Actions, so a
    /// button pressed on head 0 is in head 0's result and nowhere else.
    /// Keeping only the last head's result threw those away: with two
    /// monitors a tab click on the first one never took effect, because the
    /// second head's frame - which saw no click - replaced it.
    ///
    /// Only the user's INTENTS are folded here. The geometry fields
    /// (`chrome`, `viewport`, `area`, `guest_cursor`) are per-head by
    /// nature and are collected per head by the caller; merging those would
    /// put one head's rectangle in another head's coordinate space.
    pub fn absorb(&mut self, other: &Actions) {
        self.tab = self.tab.or(other.tab);
        self.page = self.page.or(other.page);
        self.edit_port = self.edit_port.take().or_else(|| other.edit_port.clone());
        self.edit_update = self.edit_update.take().or_else(|| other.edit_update.clone());
        self.apply_port = self.apply_port.take().or_else(|| other.apply_port.clone());
        self.edit_cancel |= other.edit_cancel;
        self.send_cad |= other.send_cad;
        self.send_wake |= other.send_wake;
        self.toggle_fullscreen |= other.toggle_fullscreen;
        self.set_debug = self.set_debug.take().or_else(|| other.set_debug.clone());
    }
}

/// How close to the top edge, in points, reveals the chrome in fullscreen.
/// Deliberately generous: a pointer that is being *thrown* at the edge
/// overshoots by a few pixels and then sits exactly at 0, but one moved by
/// hand stops short, and a 2px strip is unhittable on a 1080p panel.
const REVEAL_BAND: f32 = 48.0;

/// Width of the fullscreen escape tab, in points.
const TAB_W: f32 = 200.0;

/// Height of the closed tab - a hint that something is there, small enough
/// to sit above a guest's own top panel without hiding any of it.
const TAB_SHUT_H: f32 = 5.0;

pub fn draw(ctx: &egui::Context, f: &Frame) -> Actions {
    let mut act = Actions::default();
    // In fullscreen the bar is drawn last, as an overlay, so it sits above
    // the guest image instead of taking space from it.
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
    if !f.input {
        return act;
    }
    if f.fullscreen {
        fs_tab(ctx, f, &mut act);
    }
    // Our own pointer goes on a foreground layer so no panel can clip it, and
    // only over OUR chrome: inside the guest view either the guest composites
    // its cursor or we drew it above, and a second arrow looks broken.
    if let Some(e) = f.edit {
        port_dialog(ctx, e, &mut act);
    }
    let over_guest = act.viewport.is_some_and(|r| r.contains(f.pointer));
    // Over our own chrome the guest's cursor is behind it, so draw ours even
    // when the guest holds the pointer - otherwise the operator is aiming at
    // the exit button with nothing visible to aim.
    let over_chrome = act.chrome.is_some_and(|r| r.contains(f.pointer));
    // Over the guest we normally let the guest's own cursor stand in, so it
    // looks native. But a guest that publishes no hardware cursor - or
    // hides it, which Windows does when it thinks the pointer is on another
    // monitor - would otherwise leave the operator with no pointer at all
    // and no way to tell a lost cursor from a wedged console.
    let no_pointer_at_all = over_guest && !act.guest_cursor;
    // A relative guest overrides all of that. Grabbed, ours is frozen at the
    // grab click, and drawing it there is a second pointer that never moves.
    // Ungrabbed, the guest's cursor cannot follow ours, so ours is the only
    // one that means anything, over the guest or not.
    let show = if f.relative {
        f.focus == Focus::Gui
    } else {
        (f.focus == Focus::Gui && !over_guest) || over_chrome || no_pointer_at_all
    };
    if show {
        draw_arrow(ctx, f.pointer);
    }
    act
}

/// The way out of fullscreen: a small tab at the top centre, like the
/// connection bar an RDP client drops down.
///
/// Deliberately NOT the whole status bar. Full width covers the guest's own
/// top panel - an XFCE menu, a Windows taskbar docked to the top - and the
/// operator cannot reach it without leaving fullscreen first, which is the
/// one thing the bar is there to let them do. Centred for the same reason:
/// the corners are where guests put their menus.
fn fs_tab(ctx: &egui::Context, f: &Frame, act: &mut Actions) {
    let sw = ctx.screen_rect().width();
    let w = TAB_W.min(sw);
    let x0 = ((sw - w) / 2.0).max(0.0);
    // Only the tab's own column reveals it, so the pointer can reach the
    // guest's top-left menu with no chrome appearing over it. The hot zone
    // does not move with the animation, or the tab would chatter as it slid
    // out from under the pointer.
    let hot = egui::Rect::from_min_size(egui::pos2(x0, 0.0), egui::vec2(w, REVEAL_BAND));
    let open = hot.contains(f.pointer);
    if open {
        act.chrome = Some(hot);
    }

    let id = egui::Id::new("fs_tab");
    let t = ctx.animate_bool_with_time(id.with("open"), open, 0.13);
    // Ease out: it should arrive gently rather than stop dead.
    let e = 1.0 - (1.0 - t).powi(3);
    // Height measured last frame. The tab is one row of chrome, so the first
    // frame's guess only has to be close; it is corrected below.
    let full_h: f32 = ctx.data(|d| d.get_temp(id.with("h")).unwrap_or(34.0));
    // Slid fully home at e=1. At e=0 all but TAB_SHUT_H is above the top
    // edge, so the shut state is simply the tab peeking out - no second
    // widget pretending to be a sliver, and nothing to keep in step.
    let y = -(full_h - TAB_SHUT_H).max(0.0) * (1.0 - e);

    egui::Area::new(id)
        .order(egui::Order::Foreground)
        // An Area is kept inside the screen by default, which silently
        // snapped the negative y back to 0: the tab never moved and only the
        // contents faded. Sliding it off the top edge is the whole point.
        .constrain(false)
        .fixed_pos(egui::pos2(x0, y))
        .show(ctx, |ui| {
            let r = egui::Frame::NONE
                .fill(ui.visuals().panel_fill.gamma_multiply(0.96))
                .corner_radius(egui::CornerRadius { nw: 0, ne: 0, sw: 8, se: 8 })
                .inner_margin(egui::Margin::symmetric(10, 5))
                .show(ui, |ui| {
                    ui.set_width(w - 20.0);
                    ui.horizontal(|ui| {
                        // Fade the contents in behind the slide, so the
                        // peeking edge reads as a handle rather than as a
                        // clipped button.
                        ui.set_opacity(e);
                        if ui.button("Exit fullscreen").clicked() {
                            act.toggle_fullscreen = true;
                        }
                        ui.weak("Ctrl+Alt+F");
                    });
                })
                .response
                .rect;
            ctx.data_mut(|d| d.insert_temp(id.with("h"), r.height()));
        });
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
                if f.input {
                    if ui.selectable_label(i == f.active, name).clicked() {
                        act.tab = Some(i);
                    }
                } else {
                    let t = egui::RichText::new(name);
                    ui.label(if i == f.active { t.strong() } else { t.weak() });
                }
            }
            ui.separator();
            if f.input {
                // The chord itself is forwarded too (see vt::CtrlAltDelGuard),
                // but a Windows logon screen is precisely where you are not
                // grabbed yet.
                if ui
                    .button("Ctrl+Alt+Del")
                    .on_hover_text("send to the active guest")
                    .clicked()
                {
                    act.send_cad = true;
                }
                // A blanked guest display makes QEMU withhold the scanout, so
                // there is nothing to draw until something wakes it. A
                // keystroke does; pointer motion does not reliably.
                if ui
                    .button("Wake")
                    .on_hover_text("tap Shift in the active guest to wake its display")
                    .clicked()
                {
                    act.send_wake = true;
                }
                ui.separator();
            }
            ui.label(format!(
                "{} {}x{}@{}Hz  ·  {:.0} fps  ·  guest {:.0} fps  ·  frame {}  ·  t={:.1}s",
                f.head, f.display.w, f.display.h, f.display.refresh, f.fps, f.guest_fps, f.frame, f.elapsed
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
            if !f.input {
                ui.weak(format!("controls on {}", f.input_head));
                ui.separator();
            }
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
    if f.node_tab && !f.input {
        ui.centered_and_justified(|ui| {
            ui.weak(format!("the Node page is on {}", f.input_head));
        });
        return;
    }
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
            NodePage::Summary => {
                node_page(ui, &f.node, &f.display, f.fps, &f.guest, f.probe, f.vmstat)
            }
            NodePage::Network => network_page(ui, f.ports, act),
            NodePage::Apps => apps_page(ui, f.apps),
            NodePage::Debug => debug_page(ui, f.debug, act),
        }
        return;
    }
    let avail = ui.available_rect_before_wrap();
    let src = if f.guest.dma_id.is_some() {
        Some(f.guest.dma_size)
    } else {
        f.guest.tex.map(|t| t.size_vec2())
    };

    if f.remote {
        ui.centered_and_justified(|ui| {
            ui.label(
                "a remote session has this guest's display.\n\
                 It comes back here when the remote client disconnects.",
            );
        });
        return;
    }
    let Some(sz) = src else {
        ui.centered_and_justified(|ui| {
            if f.guest.asleep {
                // Said, not inferred: QEMU tells us outright when the guest
                // releases its scanout.
                ui.label("the guest turned this display off.\nPress Wake, or move the mouse.");
            } else if f.guest.orphan_updates > 0 {
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
            act.guest_cursor = true;
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
    act.area = Some(avail);
}

/// The port editor. Modal on purpose: changing the address of the port you
/// are reaching the node through is not something to do while half-reading
/// another page.
fn port_dialog(ctx: &egui::Context, e: &PortEdit, act: &mut Actions) {
    let mut ed = e.clone();
    let mut close = false;
    egui::Modal::new(egui::Id::new("port_edit")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading(format!("Configure {}", ed.iface));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.radio_value(&mut ed.dhcp, true, "DHCP");
            ui.radio_value(&mut ed.dhcp, false, "Static");
        });
        ui.add_space(8.0);
        ui.add_enabled_ui(!ed.dhcp, |ui| {
            egui::Grid::new("port_edit_grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    // Each field says whether it parses, as it is typed: a
                    // static address that does not is how a node is lost.
                    field(ui, "Address", &mut ed.addr, |v| {
                        v.trim().parse::<std::net::IpAddr>().is_ok()
                    });
                    field(ui, "Subnet", &mut ed.subnet, |v| subnet_ok(v));
                    field(ui, "Gateway", &mut ed.gateway, |v| {
                        v.trim().is_empty() || v.trim().parse::<std::net::IpAddr>().is_ok()
                    });
                    field(ui, "DNS", &mut ed.dns, |v| list_ok(v));
                });
        });
        ui.add_space(6.0);
        egui::Grid::new("port_edit_common")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                field(ui, "NTP", &mut ed.ntp, |_| true);
            });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(ed.valid(), egui::Button::new("Apply")).clicked() {
                act.apply_port = Some(ed.clone());
                close = true;
            }
            if ui.button("Cancel").clicked() {
                close = true;
            }
            // Undo re-sends what the port had before the last Apply. Nothing
            // on the pillar side has to remember it - the previous values
            // travel with the dialog.
            if let Some(prev) = ed.previous.clone() {
                ui.separator();
                if ui
                    .button("Undo last change")
                    .on_hover_text(format!(
                        "put {} back to {}",
                        prev.iface,
                        if prev.dhcp { "DHCP".to_string() } else { prev.addr.clone() }
                    ))
                    .clicked()
                {
                    act.apply_port = Some((*prev).clone());
                    close = true;
                }
            }
        });
        if !ed.dhcp && !ed.valid() {
            ui.add_space(6.0);
            ui.colored_label(egui::Color32::LIGHT_RED, "address, subnet and DNS must parse");
        }
    });
    if close {
        act.edit_cancel = true;
    } else {
        act.edit_update = Some(ed);
    }
}

/// One labelled text field that colours itself when it does not parse.
fn field(ui: &mut egui::Ui, label: &str, value: &mut String, ok: impl Fn(&str) -> bool) {
    ui.label(egui::RichText::new(label).weak());
    let good = ok(value);
    let edit = egui::TextEdit::singleline(value).desired_width(300.0);
    let r = ui.add(edit);
    if !good && !value.trim().is_empty() {
        ui.painter().rect_stroke(
            r.rect.expand(1.0),
            2.0,
            egui::Stroke::new(1.0, egui::Color32::LIGHT_RED),
            egui::StrokeKind::Outside,
        );
    }
    ui.end_row();
}

/// Every port pillar reports, with the detail the summary has no room for.
fn network_page(ui: &mut egui::Ui, ports: &[PortView], act: &mut Actions) {
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
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(title).strong());
                if ui.small_button("Edit").clicked() {
                    act.edit_port = Some(p.name.clone());
                }
            });
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

/// Pillar's debug options, one widget each. A change goes to pillar, and the
/// page shows the value pillar sends back rather than assuming it took.
fn debug_page(ui: &mut egui::Ui, options: &[crate::ipc::monitorapi::DebugOption], act: &mut Actions) {
    ui.add_space(12.0);
    ui.heading("Debug");
    ui.add_space(8.0);
    if options.is_empty() {
        ui.label("waiting for pillar…");
        return;
    }
    egui::ScrollArea::vertical().show(ui, |ui| {
        ui.set_max_width(760.0);
        for o in options {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(&o.label).strong());
                ui.weak(&o.key);
                if o.scope == "vm" {
                    ui.weak("·  applies on next start of an application");
                }
            });
            ui.weak(&o.description);
            ui.add_space(4.0);
            match o.kind.as_str() {
                "bool" => {
                    let mut on = o.value == "true";
                    let text = if on { "on" } else { "off" };
                    if ui.checkbox(&mut on, text).changed() {
                        act.set_debug = Some((o.key.clone(), on.to_string()));
                    }
                }
                "enum" => {
                    egui::ComboBox::from_id_salt(("debug", o.key.as_str()))
                        .selected_text(&o.value)
                        .show_ui(ui, |ui| {
                            for c in &o.choices {
                                if ui.selectable_label(*c == o.value, c).clicked() && *c != o.value {
                                    act.set_debug = Some((o.key.clone(), c.clone()));
                                }
                            }
                        });
                }
                "string" => {
                    // What is being typed, kept until Apply: pillar's value
                    // must not overwrite it mid-edit.
                    let id = egui::Id::new(("debug_draft", o.key.as_str()));
                    let mut draft = ui.data(|d| d.get_temp::<String>(id)).unwrap_or_else(|| o.value.clone());
                    ui.horizontal(|ui| {
                        let r = ui.add(egui::TextEdit::singleline(&mut draft).desired_width(420.0));
                        let entered = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        let apply = ui.add_enabled(draft != o.value, egui::Button::new("Apply")).clicked();
                        if (apply || entered) && draft != o.value {
                            act.set_debug = Some((o.key.clone(), draft.trim().to_string()));
                            ui.data_mut(|d| d.remove::<String>(id));
                        } else if r.changed() {
                            ui.data_mut(|d| d.insert_temp(id, draft.clone()));
                        }
                    });
                }
                _ => {
                    ui.label(&o.value);
                }
            }
            ui.add_space(6.0);
            ui.separator();
        }
    });
}

fn node_page(
    ui: &mut egui::Ui,
    n: &NodeView,
    d: &DisplayView,
    fps: f32,
    g: &GuestView<'_>,
    probe: bool,
    vmstat: Option<&crate::gui::vmstat::Series>,
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
                rows.push(("Planes".to_string(), desc.planes.to_string()));
                rows.push(("Stride".to_string(), format!("{} bytes", desc.stride)));
                let (x, y, _, _) = desc.rect;
                rows.push((
                    "Buffer".to_string(),
                    format!("{}x{}, this head at +{x}+{y}", desc.backing.0, desc.backing.1),
                ));
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
            ui.label(egui::RichText::new("Probe").strong());
            ui.label(if probe { "on (Debug page)" } else { "off (Debug page)" });
            ui.end_row();
        });

    if let Some(v) = vmstat {
        ui.add_space(18.0);
        ui.separator();
        ui.add_space(12.0);
        ui.heading("Guest memory");
        ui.add_space(8.0);
        memory_plot(ui, v);
    }
}

/// Bytes as a short human string. Guest memory spans orders of magnitude
/// across a boot, so one fixed unit is unreadable at one end or the other.
fn mib(b: u64) -> String {
    let m = b as f64 / (1024.0 * 1024.0);
    if m >= 1024.0 { format!("{:.2} GiB", m / 1024.0) } else { format!("{m:.0} MiB") }
}

/// The guest's charge against its cgroup limit, over time.
///
/// Drawn by hand rather than with a plotting crate: it is two polylines and
/// a threshold, and the console links against enough already.
fn memory_plot(ui: &mut egui::Ui, v: &crate::gui::vmstat::Series) {
    let cur = v.latest();
    let frac = v.headroom();
    // The colour IS the warning: nothing else on this page says "about to be
    // killed", and that is the state worth noticing from across a room.
    let trace = if frac > 0.9 {
        egui::Color32::from_rgb(235, 90, 80)
    } else if frac > 0.75 {
        egui::Color32::from_rgb(235, 180, 80)
    } else {
        egui::Color32::from_rgb(110, 190, 240)
    };
    let gpu_col = egui::Color32::from_rgb(160, 130, 220);

    egui::Grid::new("vmmem").num_columns(2).spacing([28.0, 10.0]).show(ui, |ui| {
        ui.label(egui::RichText::new("Now").strong());
        ui.label(format!(
            "{} of {}  ({:.0}%)   \u{b7}   GPU {}",
            mib(cur.usage), mib(v.limit), frac * 100.0, mib(cur.shmem)
        ));
        ui.end_row();
        ui.label(egui::RichText::new("Peak").strong());
        let age = v.peak_age.as_secs();
        let ago = if age < 60 { format!("{age}s ago") } else { format!("{}m ago", age / 60) };
        let pf = if v.limit > 0 { v.peak.usage as f32 / v.limit as f32 * 100.0 } else { 0.0 };
        ui.label(
            egui::RichText::new(format!(
                "{} ({pf:.0}%)  \u{b7}  GPU {}  \u{b7}  {ago}",
                mib(v.peak.usage), mib(v.peak.shmem)
            ))
            .color(if pf > 90.0 {
                egui::Color32::from_rgb(235, 90, 80)
            } else {
                ui.visuals().text_color()
            }),
        );
        ui.end_row();
    });

    ui.add_space(10.0);
    let w = (ui.available_width() - 24.0).max(200.0);
    let (rect, _) = ui.allocate_exact_size(egui::vec2(w, 150.0), egui::Sense::hover());
    let p = ui.painter_at(rect);
    p.rect_filled(rect, 4.0, ui.visuals().extreme_bg_color);

    if v.limit == 0 || v.samples.is_empty() {
        p.text(rect.center(), egui::Align2::CENTER_CENTER, "waiting for the first sample",
               egui::FontId::proportional(13.0), ui.visuals().weak_text_color());
        return;
    }

    // Full scale is the limit, always. A plot that rescales to its own data
    // hides the only thing this exists to show: how close the guest is to
    // being killed.
    let y_of = |b: u64| rect.bottom() - (b as f32 / v.limit as f32).min(1.0) * rect.height();
    let n = v.samples.len().max(2) - 1;
    let x_of = |i: usize| rect.left() + (i as f32 / n as f32) * rect.width();

    let ly = y_of(v.limit);
    let red = egui::Color32::from_rgb(200, 70, 60);
    p.line_segment([egui::pos2(rect.left(), ly), egui::pos2(rect.right(), ly)],
                   egui::Stroke::new(1.0, red));
    p.text(egui::pos2(rect.right() - 4.0, ly + 2.0), egui::Align2::RIGHT_TOP,
           format!("limit {}", mib(v.limit)), egui::FontId::proportional(11.0), red);

    let series: [(fn(&crate::gui::vmstat::Sample) -> u64, egui::Color32); 2] =
        [(|s| s.shmem, gpu_col), (|s| s.usage, trace)];
    for (sel, col) in series {
        let pts: Vec<egui::Pos2> =
            v.samples.iter().enumerate().map(|(i, s)| egui::pos2(x_of(i), y_of(sel(s)))).collect();
        if pts.len() > 1 {
            p.add(egui::Shape::line(pts, egui::Stroke::new(1.6, col)));
        }
    }

    // Mark the peak where it happened, not only in the text above.
    if let Some((i, s)) = v.samples.iter().enumerate().max_by_key(|(_, s)| s.usage) {
        let at = egui::pos2(x_of(i), y_of(s.usage));
        p.circle_filled(at, 3.0, trace);
        p.text(at - egui::vec2(0.0, 8.0), egui::Align2::CENTER_BOTTOM, mib(s.usage),
               egui::FontId::proportional(11.0), trace);
    }

    ui.horizontal(|ui| {
        ui.colored_label(trace, "total");
        ui.colored_label(gpu_col, "GPU (shmem)");
        ui.weak(format!("\u{b7} last {}s", v.samples.len()));
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
