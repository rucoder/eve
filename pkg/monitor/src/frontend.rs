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
}
