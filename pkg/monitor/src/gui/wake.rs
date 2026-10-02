// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Wakes the render loop when it has nothing to draw.
//!
//! The loop only renders a head when something on it changed, so with nothing
//! changing it would either spin or sleep through the next change. It blocks
//! here instead, and whoever produces a change - a guest frame, input, a
//! cursor - calls `wake`. A wake that arrives while the loop is busy is kept,
//! so the next `wait` returns at once and nothing is lost.

use std::sync::{Condvar, Mutex};
use std::time::Duration;

static PENDING: Mutex<bool> = Mutex::new(false);
static CV: Condvar = Condvar::new();

pub fn wake() {
    *PENDING.lock().unwrap() = true;
    CV.notify_one();
}

/// Block until `wake` or `timeout`, whichever is first.
pub fn wait(timeout: Duration) {
    let p = PENDING.lock().unwrap();
    let (mut p, _) = CV.wait_timeout_while(p, timeout, |p| !*p).unwrap();
    *p = false;
}
