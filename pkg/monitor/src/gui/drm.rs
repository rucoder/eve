// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! DRM/KMS scanout: opening the card, bringing up GBM + EGL, finding the
//! connected heads, and waiting for page flips.
//!
//! There is deliberately no Wayland, no X and no seat manager here. We are
//! plain root on a VT, which is what EVE gives us.

use std::fs::OpenOptions;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use smithay::backend::allocator::gbm::{GbmAllocator, GbmBufferFlags, GbmDevice};
use smithay::backend::allocator::{Format, Fourcc, Modifier};
use smithay::backend::drm::{DrmDevice, DrmDeviceFd, DrmDeviceNotifier, GbmBufferedSurface};
use smithay::backend::egl::{EGLContext, EGLDisplay};
use smithay::backend::renderer::gles::GlesRenderer;
use smithay::backend::renderer::glow::GlowRenderer;
use smithay::reexports::drm::control::{connector, crtc, Device as ControlDevice, Mode, ModeTypeFlags};
use smithay::utils::DeviceFd;

pub type HeadSurface = GbmBufferedSurface<GbmAllocator<DrmDeviceFd>, ()>;

/// One connected connector, with its CRTC and scanout swapchain.
pub struct Head {
    pub name: String,
    pub crtc: crtc::Handle,
    pub surface: HeadSurface,
    pub w: i32,
    pub h: i32,
    /// Vertical refresh of the mode actually set, for the Node page.
    pub refresh: u32,
    /// Whether the connector supplied an EDID. Without one the preferred mode
    /// is the driver's invention, which is worth seeing when a resolution
    /// looks wrong.
    pub edid: bool,
    /// Physical size in millimetres, from EDID. None when the connector does
    /// not report one, which is also what `edid` reflects.
    pub mm: Option<(u32, u32)>,
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

/// Does this card have anything plugged into it?
///
/// Worth checking before committing to a card: the node number is not stable
/// across machines - the same GUI needs card1 on one box and card0 on another -
/// and picking a card with no output looks identical to a broken renderer.
fn has_connected_output(path: &str) -> bool {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            // Say which error it was. EACCES from the container's device
            // cgroup and ENOENT from a node that does not exist are the same
            // `false` here, but only one of them is a packaging bug - and the
            // caller's "no card with a connected output" points at the display
            // either way, which sends you looking in the wrong place.
            if e.kind() != std::io::ErrorKind::NotFound {
                log::warn!("{path}: {e}");
            }
            return false;
        }
    };
    let fd = DrmDeviceFd::new(DeviceFd::from(OwnedFd::from(file)));
    let Ok((drm, _n)) = DrmDevice::new(fd, false) else {
        return false;
    };
    let Ok(res) = drm.resource_handles() else {
        return false;
    };
    res.connectors().iter().any(|h| {
        drm.get_connector(*h, false)
            .is_ok_and(|c| c.state() == connector::State::Connected)
    })
}

/// The card to use: the caller's choice if given, otherwise the first one with
/// something plugged in.
pub fn pick_card(configured: Option<&str>) -> anyhow::Result<String> {
    if let Some(p) = configured {
        return Ok(p.to_string());
    }
    for n in 0..4 {
        let path = format!("/dev/dri/card{n}");
        if has_connected_output(&path) {
            log::info!("picked {path}: has a connected output");
            return Ok(path);
        }
    }
    anyhow::bail!("no /dev/dri/card* with a connected output")
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

/// Which mode to drive a connector at.
///
/// An explicit request wins outright, so an operator can pin a resolution the
/// connector offers but does not prefer. It comes from `gui.mode` in
/// /persist/monitor/config/config.json, or from `GUI_MODE=WxH` in the
/// environment for a one-off run.
///
/// Otherwise PREFERRED, *if* it means anything. A connector with no EDID has
/// nothing to express a preference with, and the flag then sits on whatever
/// fallback the driver invented - virtio-gpu under QEMU advertises 640x480
/// PREFERRED while also offering modes up to 5120x2160. Taking the largest
/// mode in that case is what the user expects; honouring a fabricated
/// preference is not. With a real EDID the panel's own preferred mode is
/// authoritative and is used unchanged.
fn pick_mode(c: &connector::Info, name: &str, want_mode: Option<&str>) -> Option<Mode> {
    let area = |m: &Mode| m.size().0 as u64 * m.size().1 as u64;

    let requested = want_mode.map(|m| m.to_string())
        .or_else(|| std::env::var("GUI_MODE").ok());
    if let Some(want) = requested {
        let want = want.trim().to_lowercase();
        if let Some(m) = c.modes().iter().find(|m| {
            format!("{}x{}", m.size().0, m.size().1) == want
        }) {
            log::info!("{name}: mode {want} as configured");
            return Some(*m);
        }
        let offered: Vec<String> = c.modes().iter()
            .map(|m| format!("{}x{}", m.size().0, m.size().1)).collect();
        log::warn!("{name}: configured mode {want} is not offered; have {}", offered.join(" "));
    }

    // A real display reports its physical size from EDID; virtio-gpu with no
    // EDID reports nothing, which is the signal that PREFERRED is fabricated.
    let has_edid = c.size().map_or(false, |(w, h)| w > 0 && h > 0);
    if !has_edid {
        if let Some(m) = c.modes().iter().max_by_key(|m| area(m)) {
            log::info!("{name}: no EDID, so PREFERRED is a driver default - taking the largest offered mode {}x{}",
                       m.size().0, m.size().1);
            return Some(*m);
        }
    }

    c.modes()
        .iter()
        .find(|m| m.mode_type().contains(ModeTypeFlags::PREFERRED))
        .or_else(|| c.modes().first())
        .copied()
}

/// One head per connected connector.
/// A kernel uevent socket, for noticing a monitor plugged in or pulled out.
///
/// DRM reports connector changes as uevents, not as events on the DRM fd -
/// that fd only carries vblank and page flips. libudev would do this too, but
/// this console deliberately has no udev (see `input.rs`, which reads evdev
/// and inotify directly), and the kernel's netlink group needs neither.
///
/// The alternative, re-probing connectors on a timer, is worse than it looks:
/// `drmModeGetConnector` forces a probe, which means DDC traffic and
/// milliseconds per connector, so a poll fast enough to feel instant would
/// cost more than the compositor.
pub struct HotplugWatch {
    fd: OwnedFd,
}

impl HotplugWatch {
    pub fn new() -> anyhow::Result<Self> {
        // SAFETY: plain socket(2) with constant arguments.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::NETLINK_KOBJECT_UEVENT,
            )
        };
        if fd < 0 {
            return Err(anyhow::anyhow!("uevent socket: {}", std::io::Error::last_os_error()));
        }
        // SAFETY: fd is ours and valid; from_raw_fd takes ownership.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        // Group 1 is the kernel's own broadcast. Group 2 is udev's rewritten
        // copy, which nothing sends here because there is no udev.
        addr.nl_groups = 1;
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc < 0 {
            return Err(anyhow::anyhow!("uevent bind: {}", std::io::Error::last_os_error()));
        }
        Ok(Self { fd })
    }

    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Drain the socket; true if any event was a DRM hotplug. Non-blocking,
    /// so it is safe to call whether or not the fd polled readable.
    pub fn drained_hotplug(&self) -> bool {
        let mut hit = false;
        let mut buf = [0u8; 4096];
        loop {
            // SAFETY: buf is valid for its own length; the socket is
            // non-blocking so this returns EAGAIN once drained.
            let n = unsafe {
                libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            if n <= 0 {
                return hit;
            }
            // A uevent is NUL-separated KEY=VALUE lines after a header line.
            let msg = String::from_utf8_lossy(&buf[..n as usize]);
            let drm = msg.contains("/drm/card") || msg.contains("SUBSYSTEM=drm");
            if drm && (msg.contains("HOTPLUG=1") || msg.contains("ACTION=change")) {
                log::info!("drm hotplug uevent");
                hit = true;
            }
        }
    }
}

pub fn discover_heads(gpu: &mut Gpu, want_mode: Option<&str>) -> anyhow::Result<Vec<Head>> {
    rediscover_heads(gpu, want_mode, Vec::new())
}

/// Re-discover the heads, reusing the surfaces of monitors that stayed put.
///
/// A head that is still there must keep the surface it has. Building a second
/// surface for a CRTC the first one still owns fails the kernel's atomic test
/// with EINVAL - which is what a naive "throw them all away and discover
/// again" does, because the old heads are only dropped once the new set is
/// built. Dropping them first instead would black the panel on every hotplug
/// and lose the working set if discovery then failed.
pub fn rediscover_heads(
    gpu: &mut Gpu,
    want_mode: Option<&str>,
    old: Vec<Head>,
) -> anyhow::Result<Vec<Head>> {
    let res = gpu.drm.resource_handles()?;
    let mut connected: Vec<(connector::Info, String, Mode)> = Vec::new();
    for h in res.connectors() {
        let c: connector::Info = gpu.drm.get_connector(*h, false)?;
        if c.state() != connector::State::Connected {
            continue;
        }
        let name = format!("{}-{}", c.interface().as_str(), c.interface_id());
        let mode = pick_mode(&c, &name, want_mode).ok_or_else(|| anyhow::anyhow!("{name}: no modes"))?;
        connected.push((c, name, mode));
    }

    // Keep what is unchanged; everything else is dropped here, before a
    // single new surface is built, so its CRTC is free for whoever wants it.
    let mut kept: std::collections::HashMap<String, Head> = Default::default();
    for h in old {
        let same = connected
            .iter()
            .any(|(_, n, m)| *n == h.name && m.size() == (h.w as u16, h.h as u16));
        if same {
            kept.insert(h.name.clone(), h);
        } else {
            log::info!("  head {} released", h.name);
        }
    }
    let mut used_crtcs: std::collections::HashSet<u32> =
        kept.values().map(|h| Into::<u32>::into(h.crtc)).collect();

    let mut heads = Vec::new();
    for (c, name, mode) in connected {
        if let Some(h) = kept.remove(&name) {
            heads.push(h);
            continue;
        }

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
        let refresh = mode.vrefresh();
        let mm = c.size().filter(|(mw, mh)| *mw > 0 && *mh > 0);
        let edid = mm.is_some();
        log::info!("  head {name}: crtc={crtc:?} {w}x{h}@{refresh} edid={edid} mm={mm:?}");
        heads.push(Head {
            name, crtc, surface, w: w as i32, h: h as i32, refresh, edid, mm,
        });
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
        if !crate::gui::vt::running() {
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
