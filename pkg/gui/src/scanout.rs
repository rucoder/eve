// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Getting a guest's framebuffer into something egui can draw.
//!
//! QEMU offers two shapes over the D-Bus display, and which one arrives depends
//! on how the guest's GPU was configured, not on anything we choose:
//!
//! * **dmabuf** (`ScanoutDMABUF`) - an fd for a buffer the host GPU already
//!   holds. Zero copy: we import it as a texture. Needs `gl=on`.
//! * **copy** (`Scanout`/`Update`) - the pixels themselves, in the message.
//!   Costs a full framebuffer per frame and cannot keep up with a busy guest,
//!   so prefer the dmabuf path for every guest that can do it.

use std::collections::HashMap;

use smithay::backend::allocator::dmabuf::{Dmabuf, DmabufFlags};
use smithay::backend::allocator::{Fourcc, Modifier};
use smithay::backend::renderer::gles::GlesTexture;
use smithay::backend::renderer::glow::GlowRenderer;
use smithay::backend::renderer::{Bind, ExportMem, Frame, ImportDma, Offscreen, Renderer};
use smithay::utils::{Rectangle, Transform};

use crate::guest;
use crate::input::GuestAct;

/// One tab: a guest, its input channel, and its framebuffer state.
pub struct Vm {
    pub name: String,
    pub shared: guest::Shared,
    pub tx: std::sync::mpsc::Sender<GuestAct>,

    /// Framebuffer size in guest pixels, from whichever path delivered it.
    ///
    /// Owned per VM because input needs it to map host -> guest and it must
    /// survive tab switches. It was once published only when a scanout message
    /// happened to arrive, and zeroed on every tab switch - which killed the
    /// pointer in any dmabuf guest you switched away from and back, because
    /// QEMU sends `ScanoutDMABUF` once and only `UpdateDMABUF` after it.
    pub size: (u32, u32),
    /// Frames seen, for the rate readout. Advanced on both paths.
    pub seq: u64,

    /// Copy path: the uploaded guest image.
    pub tex: Option<egui::TextureHandle>,

    /// dmabuf path.
    pub dma_id: Option<egui::TextureId>,
    pub dma_size: egui::Vec2,
    pub dma_flip: bool,
    dma_tex: Option<GlesTexture>,
    dma_2d: Option<GlesTexture>,
    /// Imported scanout textures, keyed by dma-buf inode.
    ///
    /// An installed GNOME sends a NEW `ScanoutDMABUF` every frame because it
    /// rotates its buffers, where Windows sends one and then only
    /// `UpdateDMABUF`. Re-importing an EGLImage, rebuilding the blit target and
    /// re-registering an egui texture on every one of those - at 60Hz - was
    /// throttling the guest badly. The buffers repeat, so key on the inode.
    dma_cache: HashMap<u64, GlesTexture>,
}

/// More buffers than any sane compositor rotates; a resize also clears it.
const DMA_CACHE_MAX: usize = 8;

impl Vm {
    pub fn new(
        name: String,
        shared: guest::Shared,
        tx: std::sync::mpsc::Sender<GuestAct>,
    ) -> Self {
        Self {
            name,
            shared,
            tx,
            size: (0, 0),
            seq: 0,
            tex: None,
            dma_id: None,
            dma_size: egui::vec2(1.0, 1.0),
            dma_flip: false,
            dma_tex: None,
            dma_2d: None,
            dma_cache: HashMap::new(),
        }
    }

    /// Pick up whatever the guest has produced since the last frame.
    pub fn update(
        &mut self,
        renderer: &mut GlowRenderer,
        painter: &mut egui_glow::Painter,
        egui_ctx: &egui::Context,
        probe: bool,
        frame: u32,
    ) {
        if std::mem::take(&mut self.shared.lock().unwrap().copy_takeover) && self.dma_id.is_some() {
            log::info!("{}: guest switched back to the copy path", self.name);
            self.release_gl();
        }
        self.take_scanout(renderer);
        self.upload_copy(egui_ctx);
        self.blit_external(renderer, painter, probe, frame);
    }

    /// dmabuf path: import (or reuse) the buffer QEMU handed us.
    fn take_scanout(&mut self, renderer: &mut GlowRenderer) {
        let d = match self.shared.lock().unwrap().dmabuf.take() {
            Some(d) => d,
            None => return,
        };
        self.size = (d.w, d.h);
        let new_size = egui::vec2(d.w as f32, d.h as f32);
        let resized = self.dma_size != new_size;

        let cached = (d.ino != 0)
            .then(|| self.dma_cache.get(&d.ino).cloned())
            .flatten();
        let tex = match cached {
            Some(t) => Some(t),
            None => {
                let built = Fourcc::try_from(d.fourcc).ok().and_then(|fc| {
                    let mut b = Dmabuf::builder(
                        (d.w as i32, d.h as i32),
                        fc,
                        Modifier::from(d.modifier),
                        DmabufFlags::empty(),
                    );
                    b.add_plane(d.fd, 0, 0, d.stride);
                    b.build()
                });
                let t = built.and_then(|buf| renderer.import_dmabuf(&buf, None).ok());
                match &t {
                    Some(t) => {
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
                            self.dma_cache.insert(d.ino, t.clone());
                        }
                    }
                    None => log::error!(
                        "dmabuf import FAILED (fourcc=0x{:08x} mod=0x{:x})",
                        d.fourcc,
                        d.modifier
                    ),
                }
                t
            }
        };

        if let Some(t) = tex {
            self.dma_size = new_size;
            self.dma_flip = d.y0_top;
            self.dma_tex = Some(t);
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
        let mut g = self.shared.lock().unwrap();
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
                Ok(t) => {
                    set_sampler_params(renderer, t.tex_id());
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
        let psz = smithay::utils::Size::<i32, smithay::utils::Physical>::from((w, h));
        let dst = Rectangle::from_size(psz);
        let src = Rectangle::from_size(smithay::utils::Size::<f64, smithay::utils::Buffer>::from(
            (w as f64, h as f64),
        ));
        let blit = (|| -> anyhow::Result<()> {
            let mut fb = renderer.bind(target)?;
            let mut fr = renderer.render(&mut fb, psz, Transform::Normal)?;
            fr.render_texture_from_to(&ext, src, dst, &[dst], &[], Transform::Normal, 1.0)?;
            let _ = fr.finish()?;
            Ok(())
        })();
        if let Err(e) = blit {
            log::error!("blit ext->2d failed: {e}");
            return;
        }

        if probe && frame % 120 == 1 {
            probe_target(renderer, target, w, h);
        }
        if self.dma_id.is_none() {
            let id = target.tex_id();
            let gl_tex = glow::NativeTexture(std::num::NonZeroU32::new(id).unwrap());
            self.dma_id = Some(painter.register_native_texture(gl_tex));
            log::info!("external->2D blit active, egui texture registered");
        }
    }

    /// Drop this tab's GL objects, in the order the driver wants.
    pub fn release_gl(&mut self) {
        drop(self.dma_2d.take());
        drop(self.dma_tex.take());
        self.dma_cache.clear();
        self.dma_id = None;
    }
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
/// buffer at all" on the GL path. Enable with `GUI_PROBE=1`.
fn probe_target(renderer: &mut GlowRenderer, target: &mut GlesTexture, w: i32, h: i32) {
    let Ok(fb) = renderer.bind(target) else { return };
    let rect = Rectangle::from_size(smithay::utils::Size::<i32, smithay::utils::Buffer>::from((w, h)));
    match renderer.copy_framebuffer(&fb, rect, Fourcc::Abgr8888) {
        Ok(map) => match renderer.map_texture(&map) {
            Ok(px) => {
                let nz = px
                    .chunks(4)
                    .filter(|c| c[0] as u32 + c[1] as u32 + c[2] as u32 > 30)
                    .count();
                log::debug!("PROBE blit target {w}x{h}: {nz} / {} non-black px", px.len() / 4);
            }
            Err(e) => log::debug!("PROBE map_texture failed: {e}"),
        },
        Err(e) => log::debug!("PROBE copy_framebuffer failed: {e}"),
    }
}
