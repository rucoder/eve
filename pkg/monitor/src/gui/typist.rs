// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Paste as keystrokes: text written to a local socket is typed into the
//! active guest.
//!
//! The operator at the box has no clipboard to paste from, and a guest needs
//! no agent for this: each character becomes key presses on the guest's own
//! keyboard, through the same path as the physical one. US layout only.
//!
//!   echo 'text' | socat - UNIX-CONNECT:/run/eve-gui/type
//!
//! The reply is one line: how many characters were typed, and how many could
//! not be (no US-layout key for them).

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::gui::input::GuestAct;

const KEY_LEFTSHIFT: u32 = 42;

/// The evdev keycode for `c` on a US keyboard, and whether it needs Shift.
fn key_for(c: char) -> Option<(u32, bool)> {
    const LETTERS: &[u32] = &[
        30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38, 50, // a..m
        49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44, // n..z
    ];
    Some(match c {
        'a'..='z' => (LETTERS[c as usize - 'a' as usize], false),
        'A'..='Z' => (LETTERS[c as usize - 'A' as usize], true),
        '1'..='9' => (2 + c as u32 - '1' as u32, false),
        '0' => (11, false),
        '!' => (2, true), '@' => (3, true), '#' => (4, true), '$' => (5, true),
        '%' => (6, true), '^' => (7, true), '&' => (8, true), '*' => (9, true),
        '(' => (10, true), ')' => (11, true),
        '-' => (12, false), '_' => (12, true), '=' => (13, false), '+' => (13, true),
        '[' => (26, false), '{' => (26, true), ']' => (27, false), '}' => (27, true),
        ';' => (39, false), ':' => (39, true), '\'' => (40, false), '"' => (40, true),
        '`' => (41, false), '~' => (41, true), '\\' => (43, false), '|' => (43, true),
        ',' => (51, false), '<' => (51, true), '.' => (52, false), '>' => (52, true),
        '/' => (53, false), '?' => (53, true),
        ' ' => (57, false), '\n' => (28, false), '\t' => (15, false),
        _ => return None,
    })
}

/// Start the listener. Off EVE it still works; the socket path can be moved
/// with GUI_TYPE_SOCKET, and the pause between key events with
/// GUI_TYPE_DELAY_MS (default 8: faster drops keys in the guest's PS/2 queue).
pub fn spawn(active: Arc<Mutex<Option<SyncSender<GuestAct>>>>) {
    let path = std::env::var("GUI_TYPE_SOCKET").unwrap_or_else(|_| "/run/eve-gui/type".into());
    let delay = Duration::from_millis(
        std::env::var("GUI_TYPE_DELAY_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(8),
    );
    let _ = std::thread::Builder::new().name("typist".into()).spawn(move || {
        if let Some(dir) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::remove_file(&path);
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                log::warn!("typist: cannot listen on {path}: {e}");
                return;
            }
        };
        // Whoever can write here can type into the guest: root only.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        log::info!("typist: paste-as-keystrokes on {path}");
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { continue };
            let mut text = String::new();
            if conn.read_to_string(&mut text).is_err() {
                let _ = conn.write_all(b"error: not UTF-8\n");
                continue;
            }
            let reply = type_text(&text, &active, delay);
            log::info!("typist: {reply}");
            let _ = writeln!(conn, "{reply}");
        }
    });
}

fn type_text(text: &str, active: &Mutex<Option<SyncSender<GuestAct>>>, delay: Duration) -> String {
    let Some(tx) = active.lock().unwrap().clone() else {
        return "no active guest: nothing typed".into();
    };
    let (mut typed, mut skipped) = (0usize, 0usize);
    // Blocking send, unlike the input thread's try_send: this thread is ours,
    // and losing a key-up here would leave Shift stuck in the guest.
    let send = |a: GuestAct| {
        let ok = tx.send(a).is_ok();
        std::thread::sleep(delay);
        ok
    };
    for c in text.chars() {
        if c == '\r' {
            continue;
        }
        let Some((code, shift)) = key_for(c) else {
            skipped += 1;
            continue;
        };
        let ok = (!shift || send(GuestAct::Key(KEY_LEFTSHIFT, true)))
            && send(GuestAct::Key(code, true))
            && send(GuestAct::Key(code, false))
            && (!shift || send(GuestAct::Key(KEY_LEFTSHIFT, false)));
        if !ok {
            return format!("guest went away after {typed} characters");
        }
        typed += 1;
    }
    format!("typed {typed}, skipped {skipped}")
}
