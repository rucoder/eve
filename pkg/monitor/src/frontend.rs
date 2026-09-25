// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Which console this device gets.

/// The two consoles. The TUI is the floor: it works on any device with a
/// terminal, which is all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Frontend {
    Tui,
    Gui,
}

/// Is there a DRM card with something plugged into it? Returns its path.
pub fn probe_drm() -> Option<String> {
    crate::gui::drm::pick_card(std::env::var("GUI_CARD").ok().as_deref()).ok()
}

/// Injectable for tests; production passes `probe_drm`.
pub fn choose(probe: &dyn Fn() -> Option<String>) -> Frontend {
    match probe() {
        Some(card) => {
            log::info!("graphical console on {card}");
            Frontend::Gui
        }
        None => {
            log::info!("no usable DRM device; text console");
            Frontend::Tui
        }
    }
}

/// Tracks which console should be showing. `capable` starts fixed at the
/// boot-time probe - see `try_upgrade_capable` for why it does not always
/// stay that way, and why it only ever moves false -> true, never back.
pub struct Console {
    capable: bool,
    gpu_available: bool,
}

impl Console {
    pub fn new(initial: Frontend) -> Self {
        Self {
            capable: initial == Frontend::Gui,
            gpu_available: true,
        }
    }

    /// Pillar has taken the GPU for an app, or given it back.
    pub fn set_gpu_available(&mut self, yes: bool) {
        self.gpu_available = yes;
    }

    /// Whether this device can show the GUI at all right now.
    pub fn capable(&self) -> bool {
        self.capable
    }

    /// Re-probes for a usable DRM device, upgrading `capable` to true if one
    /// is now found. Never downgrades - the guard is inside this method
    /// (not left to callers) so a future caller can't accidentally revert a
    /// working GUI device to the TUI by calling this unconditionally; that
    /// would be a worse failure mode than the occasional wasted probe this
    /// forgoes when already capable.
    ///
    /// A device that boots with the iGPU already bound to vfio-pci (e.g.
    /// `debug.enable.vga=false` from the start) finds no `/dev/dri/card*` at
    /// `Console::new` time and would otherwise stay `capable: false` for the
    /// life of the process - even after pillar restores the GPU and a real
    /// card exists. Call this on that restore so the boot-time answer isn't
    /// treated as permanent.
    pub fn try_upgrade_capable(&mut self, probe: &dyn Fn() -> Option<String>) {
        if !self.capable {
            self.capable = choose(probe) == Frontend::Gui;
        }
    }

    /// Same upgrade-only rule as `try_upgrade_capable`, for a caller that
    /// already probed independently (e.g. a watcher thread deciding whether
    /// to hand control back) and just needs to report the result, rather
    /// than this probing DRM a second time. Probing twice for the same
    /// answer risks disagreeing on a flapping card - one probe says yes and
    /// switches, the other says no moments later - which would restart the
    /// TUI session in a loop, the exact failure `capable` exists to avoid.
    pub fn adopt_capable(&mut self, found: bool) {
        if found {
            self.capable = true;
        }
    }

    pub fn want(&self) -> Frontend {
        if self.capable && self.gpu_available {
            Frontend::Gui
        } else {
            Frontend::Tui
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Xeon server, or any GPU this kernel has no driver for, has no
    /// /dev/dri/card* at all. It must land on the TUI without ever touching
    /// EGL - and without a restart loop, which is what a hard failure here
    /// used to cause.
    #[test]
    fn no_drm_device_means_tui() {
        assert_eq!(choose(&|| None), Frontend::Tui);
    }

    /// A card with a connected output means the graphical console, which is
    /// the preferred one wherever it can run.
    #[test]
    fn a_usable_card_means_gui() {
        assert_eq!(choose(&|| Some("/dev/dri/card0".into())), Frontend::Gui);
    }

    /// An app taking the iGPU, then giving it back, must not strand the
    /// console in text mode - and repeating that must be stable, because an
    /// app that crashloops will do it many times.
    #[test]
    fn gpu_taken_and_returned_round_trips() {
        let mut c = Console::new(Frontend::Gui);
        assert_eq!(c.want(), Frontend::Gui);
        c.set_gpu_available(false);
        assert_eq!(c.want(), Frontend::Tui);
        c.set_gpu_available(true);
        assert_eq!(c.want(), Frontend::Gui);
        for _ in 0..100 {
            c.set_gpu_available(false);
            c.set_gpu_available(true);
        }
        assert_eq!(c.want(), Frontend::Gui);
    }

    /// A device that never had a GPU stays on the TUI whatever pillar says
    /// about GPU availability - there is nothing to switch to.
    #[test]
    fn a_tui_only_device_ignores_gpu_messages() {
        let mut c = Console::new(Frontend::Tui);
        c.set_gpu_available(true);
        assert_eq!(c.want(), Frontend::Tui);
    }

    /// A device that boots with the iGPU already in vfio-pci (e.g.
    /// debug.enable.vga=false) starts `capable: false`. If pillar later
    /// restores the GPU and a real card now exists, upgrading must be able
    /// to discover it - otherwise the GUI would never come back short of a
    /// process restart, exactly the bug this method exists to avoid.
    #[test]
    fn a_restore_can_discover_a_gpu_that_only_appears_after_boot() {
        let mut c = Console::new(Frontend::Tui);
        assert!(!c.capable());
        assert_eq!(c.want(), Frontend::Tui);

        c.try_upgrade_capable(&|| Some("/dev/dri/card0".into()));
        assert!(c.capable());
        c.set_gpu_available(true);
        assert_eq!(c.want(), Frontend::Gui);
    }

    /// Upgrading is not a one-way latch to capable - a probe that still
    /// finds nothing must leave the device on the TUI.
    #[test]
    fn try_upgrade_capable_can_also_confirm_there_is_still_no_gpu() {
        let mut c = Console::new(Frontend::Tui);
        c.try_upgrade_capable(&|| None);
        assert!(!c.capable());
        assert_eq!(c.want(), Frontend::Tui);
    }

    /// `adopt_capable` mirrors `try_upgrade_capable`'s upgrade-only rule for
    /// a caller reporting a result it already has rather than a probe to run
    /// - it must still never downgrade an already-capable device.
    #[test]
    fn adopt_capable_only_ever_upgrades() {
        let mut c = Console::new(Frontend::Tui);
        c.adopt_capable(false);
        assert!(!c.capable());
        c.adopt_capable(true);
        assert!(c.capable());
        c.adopt_capable(false);
        assert!(c.capable(), "must not downgrade");
    }
}
