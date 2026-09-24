// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! DRM/KMS scanout: opening the card, bringing up GBM + EGL, finding the
//! connected heads, and waiting for page flips.
//!
//! There is deliberately no Wayland, no X and no seat manager here. We are
//! plain root on a VT, which is what EVE gives us.

use std::fs::OpenOptions;
use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use smithay::backend::allocator::gbm::{GbmAllocator, GbmBufferFlags, GbmDevice};
use smithay::backend::allocator::{Format, Fourcc, Modifier};
use smithay::backend::drm::{DrmDevice, DrmDeviceFd, DrmDeviceNotifier, GbmBufferedSurface};
use smithay::backend::egl::{EGLContext, EGLDisplay};
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::glow::GlowRenderer;
use smithay::reexports::drm::control::{connector, crtc, Device as ControlDevice, ModeTypeFlags};
use smithay::utils::DeviceFd;

pub type HeadSurface = GbmBufferedSurface<GbmAllocator<DrmDeviceFd>, ()>;

/// One connected connector, with its CRTC and scanout swapchain.
pub struct Head {
    pub name: String,
    pub crtc: crtc::Handle,
    pub surface: HeadSurface,
    pub w: i32,
    pub h: i32,
}

/// The card, plus everything layered on it. `renderer` and the heads are kept
/// separate so the frame loop can borrow them independently.
pub struct Gpu {
    pub drm: DrmDevice,
    pub gbm: GbmDevice<DrmDeviceFd>,
    pub renderer: GlowRenderer,
    pub raw_fd: RawFd,
    /// Must stay alive for the device to keep delivering events.
    _notifier: DrmDeviceNotifier,
}

/// Open the card and bring up GBM, EGL and a glow renderer on it.
pub fn open(path: &str) -> anyhow::Result<Gpu> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let fd = DrmDeviceFd::new(DeviceFd::from(OwnedFd::from(file)));
    let (drm, _notifier) = DrmDevice::new(fd.clone(), false)?;
    let gbm = GbmDevice::new(fd)?;
    log::info!("DRM + GBM up on {path} (plain root, no seat manager)");

    let egl_display = unsafe { EGLDisplay::new(gbm.clone())? };
    let egl_context = EGLContext::new(&egl_display)?;
    let gles = unsafe { GlesRenderer::new(egl_context)? };
    let renderer: GlowRenderer = gles.into();
    log::info!("EGL + GlowRenderer up");

    let raw_fd = drm.as_fd().as_raw_fd();
    Ok(Gpu { drm, gbm, renderer, raw_fd, _notifier })
}

/// One head per connected connector.
pub fn discover_heads(gpu: &mut Gpu) -> anyhow::Result<Vec<Head>> {
    let res = gpu.drm.resource_handles()?;
    let mut heads = Vec::new();
    let mut used_crtcs: std::collections::HashSet<u32> = Default::default();

    for h in res.connectors() {
        let c: connector::Info = gpu.drm.get_connector(*h, false)?;
        if c.state() != connector::State::Connected {
            continue;
        }
        let name = format!("{}-{}", c.interface().as_str(), c.interface_id());
        let mode = c
            .modes()
            .iter()
            .find(|m| m.mode_type().contains(ModeTypeFlags::PREFERRED))
            .or_else(|| c.modes().first())
            .copied()
            .ok_or_else(|| anyhow::anyhow!("{name}: no modes"))?;

        // Prefer the CRTC already wired to this connector, but fall back to any
        // free one the encoder can drive. Requiring a pre-assigned CRTC fails
        // intermittently: after a previous DRM master exits the encoder is left
        // unassigned, and startup dies with "no crtc".
        let encs: Vec<_> = c
            .encoders()
            .iter()
            .filter_map(|e| gpu.drm.get_encoder(*e).ok())
            .collect();
        let crtc = encs
            .iter()
            .find_map(|e| e.crtc())
            .filter(|c| !used_crtcs.contains(&Into::<u32>::into(*c)))
            .or_else(|| {
                encs.iter().find_map(|e| {
                    res.filter_crtcs(e.possible_crtcs())
                        .into_iter()
                        .find(|c| !used_crtcs.contains(&Into::<u32>::into(*c)))
                })
            })
            .ok_or_else(|| anyhow::anyhow!("{name}: no free crtc"))?;
        used_crtcs.insert(Into::<u32>::into(crtc));

        let ds = gpu.drm.create_surface(crtc, mode, &[c.handle()])?;
        let alloc = GbmAllocator::new(
            gpu.gbm.clone(),
            GbmBufferFlags::RENDERING | GbmBufferFlags::SCANOUT,
        );
        let fmts = vec![
            Format { code: Fourcc::Xrgb8888, modifier: Modifier::Invalid },
            Format { code: Fourcc::Argb8888, modifier: Modifier::Invalid },
        ];
        let surface: HeadSurface =
            GbmBufferedSurface::new(ds, alloc, &[Fourcc::Xrgb8888, Fourcc::Argb8888], fmts)?;
        let (w, h) = mode.size();
        log::info!("  head {name}: crtc={crtc:?} {w}x{h}");
        heads.push(Head { name, crtc, surface, w: w as i32, h: h as i32 });
    }

    anyhow::ensure!(!heads.is_empty(), "no connected heads");
    Ok(heads)
}

/// Block until every CRTC has reported its page flip.
///
/// Bounded by a deadline: losing DRM master (a VT switch) means the flip we are
/// waiting for will never arrive, and hanging forever is worse than a frame.
pub fn wait_for_flips(
    drm: &mut DrmDevice,
    raw_fd: RawFd,
    heads: &[Head],
    frame: u32,
) -> anyhow::Result<()> {
    let mut pending: std::collections::HashSet<u32> =
        heads.iter().map(|h| Into::<u32>::into(h.crtc)).collect();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);

    while !pending.is_empty() {
        if !crate::vt::running() {
            break;
        }
        anyhow::ensure!(std::time::Instant::now() < deadline, "flip {frame} timed out");
        // Input has its own thread, so DRM is the only fd we wait on here.
        let mut pfds = [libc::pollfd { fd: raw_fd, events: libc::POLLIN, revents: 0 }];
        if unsafe { libc::poll(pfds.as_mut_ptr(), 1, 100) } <= 0 {
            continue;
        }
        if pfds[0].revents & libc::POLLIN == 0 {
            continue;
        }
        match drm.receive_events() {
            Ok(evs) => {
                for e in evs {
                    if let smithay::reexports::drm::control::Event::PageFlip(pf) = e {
                        pending.remove(&Into::<u32>::into(pf.crtc));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => anyhow::bail!("receive_events: {e}"),
        }
    }
    Ok(())
}

/// Release DRM master. Without this, stale state is left behind and the next
/// run renders black until the host is rebooted.
pub fn drop_master(raw_fd: RawFd) {
    // DRM_IO(0x1f); libc::Ioctl is c_int on musl and c_ulong on glibc.
    const DRM_IOCTL_DROP_MASTER: libc::Ioctl = 0x641f;
    unsafe { libc::ioctl(raw_fd, DRM_IOCTL_DROP_MASTER) };
}
