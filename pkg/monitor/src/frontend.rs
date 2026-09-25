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

/// Tracks which console should be showing. `capable` is fixed at startup: a
/// device with no GPU never switches, whatever pillar reports.
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
}
