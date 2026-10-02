// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Per-head counters for measuring the display pipeline, read over a local
//! socket:
//!
//!   socat - UNIX-CONNECT:/run/eve-gui/stats
//!
//! One JSON line per connection. Every counter only ever grows: a reader takes
//! two snapshots and divides the difference by the time between them, so
//! nothing here has a window or a rate of its own.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;

pub const MAX_HEADS: usize = 8;

pub struct Head {
    /// UpdateDMABUF calls from the guest console shown on this head.
    pub updates: AtomicU64,
    /// Pixels those updates said had changed.
    pub update_px: AtomicU64,
    /// Page flips queued on this head.
    pub flips: AtomicU64,
    /// Flips that put a guest image on screen newer than the last one shown.
    /// `updates - shown` is guest frames that were overwritten before any
    /// flip could show them.
    pub shown: AtomicU64,
}

impl Head {
    const fn new() -> Self {
        Self {
            updates: AtomicU64::new(0),
            update_px: AtomicU64::new(0),
            flips: AtomicU64::new(0),
            shown: AtomicU64::new(0),
        }
    }
}

static HEADS: [Head; MAX_HEADS] = [const { Head::new() }; MAX_HEADS];
/// Render-loop time per frame, up to the flip wait: how much of the frame
/// budget the console itself uses.
pub static BUSY_NS: AtomicU64 = AtomicU64::new(0);
pub static FRAMES: AtomicU64 = AtomicU64::new(0);
/// Connector name and mode per head, written only when the head set changes.
static NAMES: Mutex<Vec<(String, i32, i32)>> = Mutex::new(Vec::new());

/// Counters for head `i`; heads past MAX_HEADS share the last slot.
pub fn head(i: usize) -> &'static Head {
    &HEADS[i.min(MAX_HEADS - 1)]
}

pub fn set_heads(heads: &[crate::gui::drm::Head]) {
    *NAMES.lock().unwrap() = heads.iter().map(|h| (h.name.clone(), h.w, h.h)).collect();
}

fn snapshot() -> String {
    let names = NAMES.lock().unwrap().clone();
    let heads: Vec<serde_json::Value> = names
        .iter()
        .enumerate()
        .map(|(i, (name, w, h))| {
            let c = head(i);
            serde_json::json!({
                "name": name, "w": w, "h": h,
                "updates": c.updates.load(Relaxed),
                "update_px": c.update_px.load(Relaxed),
                "flips": c.flips.load(Relaxed),
                "shown": c.shown.load(Relaxed),
            })
        })
        .collect();
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    serde_json::json!({
        "t": ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9,
        "frames": FRAMES.load(Relaxed),
        "busy_ns": BUSY_NS.load(Relaxed),
        "heads": heads,
    })
    .to_string()
}

/// Start the listener; GUI_STATS_SOCKET moves it.
pub fn spawn() {
    let path = std::env::var("GUI_STATS_SOCKET").unwrap_or_else(|_| "/run/eve-gui/stats".into());
    let _ = std::thread::Builder::new().name("stats".into()).spawn(move || {
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("stats: cannot listen on {path}: {e}");
                return;
            }
        };
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        log::info!("stats: pipeline counters on {path}");
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let _ = writeln!(conn, "{}", snapshot());
        }
    });
}
