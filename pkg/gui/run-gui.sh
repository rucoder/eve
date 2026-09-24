#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

echo "Running EVE GUI"
export RUST_BACKTRACE=1

# leave only panic on console
dmesg -n 1

# Guests to show, one "name=<d-bus address>" per line. Written by whoever
# starts the guests; see README.md - wiring this to pillar is still to do.
VMS_FILE=/run/eve-gui/vms

# run on the 2nd console in an infinite loop, as the TUI monitor does
while true; do
    if [ -r "$VMS_FILE" ]; then
        GUI_VMS=$(tr '\n' ';' < "$VMS_FILE")
        export GUI_VMS
    fi
    openvt -c 2 -s -f -w -- /sbin/eve-gui
    sleep 1
done
