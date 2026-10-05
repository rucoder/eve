// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Getting a guest's framebuffer into something egui can draw.
//!
//! QEMU offers two shapes over the D-Bus display, and which one arrives depends
//! on how the guest's GPU was configured, not on anything we choose:
//!
//! * **dmabuf** (`ScanoutDMABUF2`, or `ScanoutDMABUF` from an older QEMU) -
//!   fds for a buffer the host GPU already holds. Zero copy: we import it as a
//!   texture and draw the head's rectangle of it. Needs `gl=on`.
//! * **copy** (`Scanout`/`Update`) - the pixels themselves, in the message.
//!   Costs a full framebuffer per frame and cannot keep up with a busy guest,
//!   so prefer the dmabuf path for every guest that can do it.

use std::collections::HashMap;

use smithay::backend::allocator::dmabuf::{Dmabuf, DmabufFlags, MAX_PLANES};
use smithay::backend::allocator::{Fourcc, Modifier};
use smithay::backend::renderer::gles::GlesTexture;
use smithay::backend::renderer::glow::GlowRenderer;
use smithay::backend::renderer::{
    Bind, Color32F, ExportMem, Frame, ImportDma, Offscreen, Renderer,
};
use smithay::utils::{Rectangle, Transform};

use crate::gui::guest;
use crate::gui::input::GuestAct;

/// How `opaque` rewrites a fourcc, as a name for the status page.
pub fn opaque_name(fourcc: u32) -> String {
    match Fourcc::try_from(fourcc) {
        Ok(fc) => {
            let o = opaque(fc);
            let n: String = (o as u32).to_le_bytes().iter().map(|&c| c as char).collect();
            if o == fc { format!("{n} (unchanged)") } else { n }
        }
        Err(_) => "unknown to drm-fourcc".to_string(),
    }
}

/// The same memory layout, with the fourth byte marked "don't care".
///
/// A scanout has nothing behind it: it is what a display controller puts on
/// its primary plane, and QEMU's own GL path blits it with
/// `glBlitFramebuffer` (`ui/egl-helpers.c`), which by specification cannot
/// blend. Its alpha byte is therefore never composited by anyone.
///
/// The fourcc QEMU hands us says nothing to the contrary: on the D-Bus path it
/// comes from `eglExportDMABUFImageQueryMESA`, i.e. Mesa describing the buffer
/// it allocated, not a claim that the alpha channel carries transparency. A
/// guest that leaves that byte at zero - Linux fbcon does, and so do most
/// compositors on their scanout - would otherwise import as fully transparent
/// and blend away to whatever the blit target already held.
///
/// Channel order, bit depth and stride are untouched; only `has_alpha`
/// changes, which is what decides whether smithay blends the blit or copies
/// it.
fn opaque(fc: Fourcc) -> Fourcc {
    match fc {
        Fourcc::Argb8888 => Fourcc::Xrgb8888,
        Fourcc::Abgr8888 => Fourcc::Xbgr8888,
        Fourcc::Rgba8888 => Fourcc::Rgbx8888,
        Fourcc::Bgra8888 => Fourcc::Bgrx8888,
        Fourcc::Argb2101010 => Fourcc::Xrgb2101010,
        Fourcc::Abgr2101010 => Fourcc::Xbgr2101010,
        // Anything else is already opaque, or a layout whose alpha we have no
        // X twin for: leave it exactly as QEMU described it.
        other => other,
    }
}

/// One tab: a guest, its input channel, and one framebuffer state per head.
pub struct Vm {
    pub name: String,
    /// Distinguishes one attach from the next on the same QMP socket. A guest
    /// that reboots keeps its socket path, so the path alone cannot tell the
    /// render loop that the tab it is pointing at is a different guest now.
    pub id: u64,
    /// The QMP socket this tab was created from; the identity we reconcile on.
    /// Empty for a tab configured by hand through GUI_VMS.
    pub source: String,
    pub tx: std::sync::mpsc::SyncSender<GuestAct>,
    /// One per guest scanout, in head order: `scanouts[i]` is what we draw on
    /// physical head `i`. Never empty - a guest with no usable console is not
    /// given a tab at all.
    pub scanouts: Vec<Scanout>,
}

/// One guest scanout: the QEMU console feeding it and everything we need to
/// get its pixels onto one physical head.
pub struct Scanout {
    /// For logs only - `<vm>#<console>`, so two heads of one guest are told
    /// apart in a line that has no other context.
    label: String,
    /// The guest has turned this display off; there is nothing to draw and
    /// nothing worth holding on to. Published so the UI can say so rather
    /// than show a frozen desktop.
    pub asleep: bool,
    pub shared: guest::Shared,

    /// Framebuffer size in guest pixels, from whichever path delivered it.
    /// On the dmabuf path this is the head's rectangle, not the buffer
    /// behind it.
    ///
    /// Owned per VM because input needs it to map host -> guest and it must
    /// survive tab switches. It was once published only when a scanout message
    /// happened to arrive, and zeroed on every tab switch - which killed the
    /// pointer in any dmabuf guest you switched away from and back, because
    /// QEMU sends `ScanoutDMABUF` once and only `UpdateDMABUF` after it.
    pub size: (u32, u32),
    /// Frames seen, for the rate readout. Advanced on both paths.
    pub seq: u64,
    /// Guest frames per second, from `Vm::sample_rates`, and the listener's
    /// frame count it last sampled.
    pub fps: f32,
    rate_seq: Option<u64>,

    /// Copy path: the uploaded guest image.
    pub tex: Option<egui::TextureHandle>,

    /// dmabuf path.
    pub dma_id: Option<egui::TextureId>,
    pub dma_size: egui::Vec2,
    pub dma_flip: bool,
    /// The part of `dma_tex` this head shows, in its buffer coordinates.
    dma_src: Rectangle<f64, smithay::utils::Buffer>,
    dma_tex: Option<GlesTexture>,
    dma_2d: Option<GlesTexture>,
    /// The last scanout we took, so a guest that switches format or layout
    /// mid-session - starting a real GUI on top of fbcon, a compositor moving
    /// to a tiled modifier, a second head moving within a shared framebuffer -
    /// says so in the log once, instead of either never or on every frame. A
    /// guest that rotates buffers sends a scanout per frame (see
    /// `dma_cache`), so this cannot be logged per scanout.
    dma_format: Option<GuestDesc>,
    /// What QEMU last described, and what the readback last found, for the
    /// status line. Kept here because a log level is set by pillar at runtime
    /// (`TUIConfig`) and can hide a `debug!` exactly when it is needed.
    pub desc: Option<GuestDesc>,
    pub probe_nonblack: Option<(usize, usize)>,
    /// Imported scanout textures, keyed by dma-buf identity.
    ///
    /// An installed GNOME sends a NEW `ScanoutDMABUF` every frame because it
    /// rotates its buffers, where Windows sends one and then only
    /// `UpdateDMABUF`. Re-importing an EGLImage, rebuilding the blit target and
    /// re-registering an egui texture on every one of those - at 60Hz - was
    /// throttling the guest badly. The buffers repeat, so key on their identity.
    ///
    /// The `Dmabuf` is kept beside the texture, and not merely dropped after
    /// the import, so that our own open fd pins the dma-buf for as long as the
    /// entry lives. An inode is reused the moment its last reference goes, so
    /// without that a guest compositor that tears down and reallocates its
    /// buffer set - a session restart, a mode set to the same mode - could land
    /// a new buffer on a cached inode and be served the old, freed texture:
    /// stale pixels on screen, nothing logged, and nothing that recovers short
    /// of a resize.
    dma_cache: HashMap<BufferKey, (GlesTexture, Dmabuf)>,
    /// The guest frame `dma_2d` holds, so the external->2D blit runs once per
    /// guest frame rather than once per console frame: at 60 Hz with a 4K and
    /// a 1080p head that was most of the console's GPU time with nothing on
    /// screen changing. None after an import, which may be another buffer.
    blitted: Option<u64>,
}

/// What QEMU said the scanout buffer is, for the status line.
#[derive(Clone, Copy, PartialEq)]
pub struct GuestDesc {
    pub fourcc: u32,
    pub modifier: u64,
    /// Of plane 0.
    pub stride: u32,
    pub y0_top: bool,
    pub planes: usize,
    /// This head's x, y, w, h within the buffer, and the buffer's size.
    pub rect: (u32, u32, u32, u32),
    pub backing: (u32, u32),
    pub method: &'static str,
}

impl GuestDesc {
    pub fn of(d: &guest::GuestDmabuf) -> Self {
        Self {
            fourcc: d.fourcc,
            modifier: d.modifier,
            stride: d.planes.first().map_or(0, |p| p.stride),
            y0_top: d.y0_top,
            planes: d.planes.len(),
            rect: (d.x, d.y, d.w, d.h),
            backing: (d.backing_w, d.backing_h),
            method: d.method,
        }
    }
}

/// More buffers than any sane compositor rotates; a resize also clears it.
const DMA_CACHE_MAX: usize = 8;

/// What makes one imported scanout buffer the same as another. The inode alone
/// is not enough even with the fd pinned: a guest may hand back the same buffer
/// re-described, and sampling it through the old geometry would tear.
///
/// The head's rectangle is not part of it: that is chosen at the blit, so a
/// buffer imported for one rectangle serves any other.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct BufferKey {
    ino: u64,
    w: u32,
    h: u32,
    /// Offset and stride of each plane, zero past the last. The offset
    /// matters: a guest may flip between framebuffers in one buffer.
    layout: [(u32, u32); MAX_PLANES],
    fourcc: u32,
    modifier: u64,
}

impl Vm {
    pub fn new(
        name: String,
        shareds: Vec<guest::Shared>,
        tx: std::sync::mpsc::SyncSender<GuestAct>,
    ) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self {
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            source: String::new(),
            tx,
            scanouts: shareds
                .into_iter()
                .enumerate()
                .map(|(i, sh)| Scanout::new(format!("{name}#{i}"), sh))
                .collect(),
            name,
        }
    }

    /// Record which QMP socket this tab came from.
    pub fn with_source(mut self, source: String) -> Self {
        self.source = source;
        self
    }

    /// The scanout shown on head `i`, falling back to the first one.
    ///
    /// A guest can offer fewer scanouts than the box has monitors - QEMU's
    /// `max_outputs` is fixed at domain start, monitors are not - and the
    /// alternative to mirroring the first one is a black panel.
    pub fn head(&self, i: usize) -> &Scanout {
        self.scanouts.get(i).unwrap_or(&self.scanouts[0])
    }

    /// Pick up whatever the guest has produced on every head since last frame.
    pub fn update(
        &mut self,
        renderer: &mut GlowRenderer,
        painter: &mut egui_glow::Painter,
        egui_ctx: &egui::Context,
        probe: bool,
        frame: u32,
    ) {
        for s in self.scanouts.iter_mut() {
            s.update(renderer, painter, egui_ctx, probe, frame);
        }
    }

    pub fn release_gl(&mut self) {
        for s in self.scanouts.iter_mut() {
            s.release_gl();
        }
    }

    /// Update every head's guest frame rate, `dt` seconds after the last
    /// call. Read off the listener's counter rather than `seq`, which only
    /// moves while the tab is on screen.
    pub fn sample_rates(&mut self, dt: f32) {
        for s in self.scanouts.iter_mut() {
            let seq = guest::frame(&s.shared).seq;
            s.fps = s.rate_seq.map_or(0.0, |was| seq.saturating_sub(was) as f32 / dt);
            s.rate_seq = Some(seq);
        }
    }
}

impl Scanout {
    fn new(label: String, shared: guest::Shared) -> Self {
        Self {
            label,
            asleep: false,
            shared,
            size: (0, 0),
            seq: 0,
            fps: 0.0,
            rate_seq: None,
            tex: None,
            dma_id: None,
            dma_size: egui::vec2(1.0, 1.0),
            dma_flip: false,
            dma_src: Rectangle::default(),
            dma_tex: None,
            dma_2d: None,
            dma_format: None,
            desc: None,
            probe_nonblack: None,
            dma_cache: HashMap::new(),
            blitted: None,
        }
    }

    /// Pick up whatever the guest has produced since the last frame.
    fn update(
        &mut self,
        renderer: &mut GlowRenderer,
        painter: &mut egui_glow::Painter,
        egui_ctx: &egui::Context,
        probe: bool,
        frame: u32,
    ) {
        if std::mem::take(&mut guest::frame(&self.shared).copy_takeover) && self.dma_id.is_some() {
            log::info!("{}: guest switched back to the copy path", self.label);
            self.release_gl();
        }
        // The guest released its scanout. Give the GPU memory back rather
        // than pinning a buffer nothing will draw into again: on wake the
        // guest allocates a new one and QEMU sends a fresh ScanoutDMABUF,
        // so there is nothing here worth keeping warm.
        let off = guest::frame(&self.shared).display_off;
        if off != self.asleep {
            self.asleep = off;
            if off {
                log::info!("{}: display off, releasing {} cached buffer(s)",
                           self.label, self.dma_cache.len());
                self.release_gl();
                self.size = (0, 0);
                self.desc = None;
                self.tex = None;
            } else {
                log::info!("{}: display back", self.label);
            }
        }
        self.take_scanout(renderer);
        self.upload_copy(egui_ctx);
        self.blit_external(renderer, painter, probe, frame);
    }

    /// dmabuf path: import (or reuse) the buffer QEMU handed us.
    fn take_scanout(&mut self, renderer: &mut GlowRenderer) {
        let d = match guest::frame(&self.shared).dmabuf.take() {
            Some(d) => d,
            None => return,
        };
        self.size = (d.w, d.h);
        let new_size = egui::vec2(d.w as f32, d.h as f32);
        let resized = self.dma_size != new_size;

        let desc = GuestDesc::of(&d);
        self.desc = Some(desc);

        let mut layout = [(0, 0); MAX_PLANES];
        for (l, p) in layout.iter_mut().zip(&d.planes) {
            *l = (p.offset, p.stride);
        }
        let key = BufferKey {
            ino: d.ino,
            w: d.backing_w,
            h: d.backing_h,
            layout,
            fourcc: d.fourcc,
            modifier: d.modifier,
        };
        let cached = (d.ino != 0)
            .then(|| self.dma_cache.get(&key).map(|(t, _)| t.clone()))
            .flatten();
        let tex = match cached {
            Some(t) => Some(t),
            None => {
                // The whole buffer, every plane: smithay passes each plane's
                // fd, offset and pitch to EGL, and the modifier on all of them.
                let built = Fourcc::try_from(d.fourcc).ok().and_then(|fc| {
                    let mut b = Dmabuf::builder(
                        (d.backing_w as i32, d.backing_h as i32),
                        opaque(fc),
                        Modifier::from(d.modifier),
                        DmabufFlags::empty(),
                    );
                    for (i, p) in d.planes.into_iter().enumerate() {
                        b.add_plane(p.fd, i as u32, p.offset, p.stride);
                    }
                    b.build()
                });
                let imported = built.and_then(|buf| {
                    renderer.import_dmabuf(&buf, None).ok().map(|t| (t, buf))
                });
                match imported {
                    Some((t, buf)) => {
                        if resized || self.dma_cache.is_empty() {
                            log::info!("imported scanout dmabuf {}x{} zero-copy", d.w, d.h);
                        } else {
                            log::debug!("imported scanout dmabuf {}x{} (ino {})", d.w, d.h, d.ino);
                        }
                        if d.ino != 0 {
                            // A resize invalidates every buffer we were holding.
                            if resized || self.dma_cache.len() > DMA_CACHE_MAX {
                                self.dma_cache.clear();
                            }
                            // Storing `buf` keeps our fd open, which is what
                            // makes the inode in the key trustworthy.
                            self.dma_cache.insert(key, (t.clone(), buf));
                        }
                        Some(t)
                    }
                    None => {
                        log::error!(
                            "dmabuf import FAILED (fourcc=0x{:08x} mod=0x{:x} planes={})",
                            d.fourcc,
                            d.modifier,
                            desc.planes
                        );
                        None
                    }
                }
            }
        };

        if let Some(t) = tex {
            if self.dma_format != Some(desc) {
                self.dma_format = Some(desc);
                // Both the declared fourcc and what we import it as: they
                // differ whenever `opaque` rewrote an alpha format, and that
                // rewrite is the whole reason a guest's pixels are visible at
                // all.
                let as_ = Fourcc::try_from(desc.fourcc).map(opaque);
                let (x, y, w, h) = desc.rect;
                log::info!(
                    "{}: scanout format {w}x{h}+{x}+{y} of {}x{} fourcc=0x{:08x} -> {:?} \
                     mod=0x{:x} planes={} ({})",
                    self.label, desc.backing.0, desc.backing.1, desc.fourcc, as_,
                    desc.modifier, desc.planes, desc.method
                );
            }
            self.dma_size = new_size;
            self.dma_src = Rectangle::new(
                (d.x as f64, d.y as f64).into(),
                (d.w as f64, d.h as f64).into(),
            );
            self.dma_flip = d.y0_top;
            self.dma_tex = Some(t);
            self.blitted = None;
            // The 2D blit target depends only on the SIZE, not on which buffer
            // we sample, so it only needs rebuilding on a resize.
            if resized {
                self.dma_2d = None;
                self.dma_id = None;
            }
        }
    }

    /// Copy path: upload the pixels, damaged rectangle only where we can.
    fn upload_copy(&mut self, egui_ctx: &egui::Context) {
        let mut g = guest::frame(&self.shared);
        if self.dma_id.is_some() {
            // Only the copy branch advances seq, and it is skipped on the
            // dmabuf path - so the frame counter and guest rate read 0 forever.
            // guest.rs does bump the shared seq on every UpdateDMABUF.
            self.seq = g.seq;
            return;
        }
        if g.seq == self.seq || g.w == 0 || g.rgba.len() != (g.w * g.h * 4) as usize {
            return;
        }
        self.seq = g.seq;
        self.size = (g.w, g.h);
        let (gw, gh) = (g.w as usize, g.h as usize);
        let dirty = g.dirty.take();

        match (&mut self.tex, dirty) {
            (Some(t), Some((dx, dy, dw, dh))) if dw > 0 && dh > 0 && (dw as usize) < gw => {
                let (dx, dy, dw, dh) = (dx as usize, dy as usize, dw as usize, dh as usize);
                let mut sub = Vec::with_capacity(dw * dh * 4);
                for row in 0..dh {
                    let o = ((dy + row) * gw + dx) * 4;
                    sub.extend_from_slice(&g.rgba[o..o + dw * 4]);
                }
                t.set_partial(
                    [dx, dy],
                    egui::ColorImage::from_rgba_unmultiplied([dw, dh], &sub),
                    egui::TextureOptions::LINEAR,
                );
            }
            (slot, _) => {
                let img = egui::ColorImage::from_rgba_unmultiplied([gw, gh], &g.rgba);
                match slot {
                    Some(t) => t.set(img, egui::TextureOptions::LINEAR),
                    None => {
                        *slot = Some(egui_ctx.load_texture("guest", img, egui::TextureOptions::LINEAR))
                    }
                }
            }
        }
    }

    /// Blit the imported scanout into an ordinary 2D texture.
    ///
    /// An imported dmabuf is `GL_TEXTURE_EXTERNAL_OES`, which egui_glow's
    /// `sampler2D` shader cannot sample. The blit stays entirely GPU-side.
    fn blit_external(
        &mut self,
        renderer: &mut GlowRenderer,
        painter: &mut egui_glow::Painter,
        probe: bool,
        frame: u32,
    ) {
        let ext = match self.dma_tex.as_ref() {
            Some(t) => t.clone(),
            None => return,
        };
        let (w, h) = (self.dma_size.x as i32, self.dma_size.y as i32);

        if self.dma_2d.is_none() {
            let sz = smithay::utils::Size::<i32, smithay::utils::Buffer>::from((w, h));
            match Offscreen::<GlesTexture>::create_buffer(renderer, Fourcc::Abgr8888, sz) {
                Ok(mut t) => {
                    set_sampler_params(renderer, t.tex_id());
                    // A fresh offscreen holds whatever the driver last left in
                    // that memory. Every pixel the blit below does not write
                    // stays as it is, so an import that silently contributes
                    // nothing - which is exactly what an alpha-zero scanout
                    // used to do - shows that garbage rather than a blank
                    // screen, and reads as a hardware fault instead of a bug
                    // in here. Start it opaque black.
                    let psz = smithay::utils::Size::<i32, smithay::utils::Physical>::from((w, h));
                    let cleared = (|| -> anyhow::Result<()> {
                        let mut fb = renderer.bind(&mut t)?;
                        let mut fr = renderer.render(&mut fb, psz, Transform::Normal)?;
                        fr.clear(Color32F::BLACK, &[Rectangle::from_size(psz)])?;
                        let _ = fr.finish()?;
                        Ok(())
                    })();
                    if let Err(e) = cleared {
                        log::warn!("clearing the blit target failed: {e}");
                    }
                    self.dma_2d = Some(t);
                }
                Err(e) => {
                    log::error!("create_buffer failed: {e}");
                    return;
                }
            }
        }

        let target = match self.dma_2d.as_mut() {
            Some(t) => t,
            None => return,
        };
        // Same buffer, same guest frame: the target already holds it.
        // Implicit dma-buf fencing orders our read after QEMU's write, and
        // every guest write is followed by an UpdateDMABUF, so the last
        // frame always gets its own blit.
        if self.blitted == Some(self.seq) && self.dma_id.is_some() {
            if probe && frame % 600 == 1 {
                self.probe_nonblack = probe_target(renderer, target, w, h);
            }
            return;
        }
        let psz = smithay::utils::Size::<i32, smithay::utils::Physical>::from((w, h));
        let dst = Rectangle::from_size(psz);
        // Only this head's rectangle of the imported buffer. Its y counts
        // from the buffer's first row whichever way up the image is, as in
        // QEMU's own egl_fb_blit; the flip is applied when it is drawn.
        let src = self.dma_src;
        // Keep the target's alpha at the opaque value it was cleared to.
        //
        // The scanout's fourth byte is an X, not an A: virtio-gpu declares
        // XBGR8888 and the guest leaves that byte at zero (Linux fbcon paints
        // 0x01010100 for its background and 0xcccccc00 for its text). This
        // target has to be Abgr8888 - egui_glow's shader needs a plain
        // sampler2D, which an external OES texture cannot give it - so a copy
        // that carries the source's fourth byte lands a zero in the channel
        // egui blends by, and every guest pixel vanishes. Masking alpha off
        // for the blit keeps the copy to colour only.
        alpha_writes(renderer, false);
        let blit = (|| -> anyhow::Result<()> {
            let mut fb = renderer.bind(target)?;
            let mut fr = renderer.render(&mut fb, psz, Transform::Normal)?;
            fr.render_texture_from_to(&ext, src, dst, &[dst], &[], Transform::Normal, 1.0)?;
            let _ = fr.finish()?;
            Ok(())
        })();
        // Unconditionally, including on the error path: the mask is global GL
        // state, and leaving it off would silently break every later draw.
        alpha_writes(renderer, true);
        if let Err(e) = blit {
            log::error!("blit ext->2d failed: {e}");
            return;
        }
        self.blitted = Some(self.seq);

        if probe && frame % 600 == 1 {
            self.probe_nonblack = probe_target(renderer, target, w, h);
        }
        if self.dma_id.is_none() {
            let id = target.tex_id();
            // A panic here skips shutdown(), which leaves DRM master and the
            // GL objects behind and the panel black until the box is rebooted.
            // Texture 0 means the blit failed; drawing nothing is recoverable.
            let Some(id) = std::num::NonZeroU32::new(id) else {
                log::error!("{}: blit produced texture 0, skipping this frame", self.label);
                return;
            };
            self.dma_id = Some(painter.register_native_texture(glow::NativeTexture(id)));
            log::info!("external->2D blit active, egui texture registered");
        }
    }

    /// Drop this scanout's GL objects, in the order the driver wants.
    fn release_gl(&mut self) {
        self.blitted = None;
        drop(self.dma_2d.take());
        drop(self.dma_tex.take());
        self.dma_cache.clear();
        self.dma_id = None;
    }
}

/// Turn writes to the alpha channel on or off for whatever is drawn next.
///
/// Used to protect the blit target's opaque alpha from the scanout's X byte;
/// see `blit_external`. Colour writes are left enabled either way.
fn alpha_writes(renderer: &mut GlowRenderer, on: bool) {
    let _ = renderer.with_context(|gl| unsafe {
        use glow::HasContext as _;
        gl.color_mask(true, true, true, on);
    });
}

/// A fresh GL texture defaults to `MIN_FILTER = NEAREST_MIPMAP_LINEAR`, which
/// needs mipmaps we never generate. egui_glow does not set sampler state on a
/// *native* texture, so it would sample an incomplete texture and draw black.
fn set_sampler_params(renderer: &mut GlowRenderer, tex_id: u32) {
    let _ = renderer.with_context(|gl| unsafe {
        use glow::HasContext as _;
        let tex = glow::NativeTexture(std::num::NonZeroU32::new(tex_id).unwrap());
        gl.bind_texture(glow::TEXTURE_2D, Some(tex));
        for (k, v) in [
            (glow::TEXTURE_MIN_FILTER, glow::LINEAR),
            (glow::TEXTURE_MAG_FILTER, glow::LINEAR),
            (glow::TEXTURE_WRAP_S, glow::CLAMP_TO_EDGE),
            (glow::TEXTURE_WRAP_T, glow::CLAMP_TO_EDGE),
        ] {
            gl.tex_parameter_i32(glow::TEXTURE_2D, k, v as i32);
        }
        gl.bind_texture(glow::TEXTURE_2D, None);
    });
}

/// Read the blit target back and count non-black pixels.
///
/// This exists because QMP `screendump` returns "no surface" once the scanout
/// is a dmabuf, so it is the only way to answer "is there anything in the
/// buffer at all" on the GL path. Pillar's console.probe turns it on.
fn probe_target(
    renderer: &mut GlowRenderer,
    target: &mut GlesTexture,
    w: i32,
    h: i32,
) -> Option<(usize, usize)> {
    let fb = renderer.bind(target).ok()?;
    let rect = Rectangle::from_size(smithay::utils::Size::<i32, smithay::utils::Buffer>::from((w, h)));
    match renderer.copy_framebuffer(&fb, rect, Fourcc::Abgr8888) {
        Ok(map) => match renderer.map_texture(&map) {
            Ok(px) => {
                let nz = px
                    .chunks(4)
                    .filter(|c| c[0] as u32 + c[1] as u32 + c[2] as u32 > 30)
                    .count();
                let total = px.len() / 4;
                // info, not debug: pillar sets the level at runtime, and a
                // probe that only speaks at debug is silent in the one
                // situation it exists for.
                log::info!("PROBE blit target {w}x{h}: {nz} / {total} non-black px");
                return Some((nz, total));
            }
            Err(e) => log::info!("PROBE map_texture failed: {e}"),
        },
        Err(e) => log::info!("PROBE copy_framebuffer failed: {e}"),
    }
    None
}
