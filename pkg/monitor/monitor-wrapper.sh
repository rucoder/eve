#!/bin/sh

# Copyright (c) 2024-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Everything the binary writes to stdout/stderr goes to a file as well as the
# screen. The Rust logger only captures what the program itself logs; libinput,
# mesa and a panic message all write to stderr and were previously visible for
# as long as the screen happened to show them and nowhere else.
OUT=/persist/monitor/console.log
mkdir -p "$(dirname "$OUT")"

# Keep one previous run, so the output that explains a restart survives it.
[ -f "$OUT" ] && mv -f "$OUT" "$OUT.prev"

# Line-buffered through tee so the file is useful while the process is alive.
/sbin/monitor 2>&1 | tee "$OUT"

# Do NOT block waiting for a keypress here. This runs under openvt from
# run-monitor.sh's restart loop on an unattended tty2: a read leaves the
# console dead until someone physically presses a key, and openvt never
# returns so nothing restarts. The output that the prompt existed to preserve
# is in $OUT now. Pause briefly instead, so a crash loop is throttled rather
# than spinning.
sleep 2
