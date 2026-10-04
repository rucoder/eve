#!/bin/sh

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

echo "Running EVE GUI"
export RUST_BACKTRACE=1

# leave only panic on console
dmesg -n 1

# Extra guests to show beyond the ones pillar reports, one
# "name=<d-bus address>" per line. A developer aid: on EVE the tab list comes
# from pillar over /run/monitor.sock, and a tab named here is kept whatever
# pillar says.
VMS_FILE=/run/eve-gui/vms

# Run on the 2nd console, as the TUI monitor did, and restart if it exits.
#
# Back off on repeated quick failures instead of spinning. A device with no GPU
# this kernel drives has no /dev/dri/card* to open, so the console cannot start
# at all - and at one restart per second that busy-loops a core and fills the
# log. Slow restarts still let a card that appears late (a VM's virtio-gpu, a
# driver that probes slowly) be picked up.
DELAY=1
while true; do
    if [ -r "$VMS_FILE" ]; then
        GUI_VMS=$(tr '\n' ';' < "$VMS_FILE")
        export GUI_VMS
    fi

    START=$(cut -d' ' -f1 /proc/uptime)
    openvt -c 2 -s -f -w -- /sbin/eve-gui
    END=$(cut -d' ' -f1 /proc/uptime)

    # Ran for a while then died? Treat it as a fresh start and retry promptly.
    # Died immediately? Something is wrong that retrying will not fix quickly.
    if [ "${START%.*}" -lt $(( ${END%.*} - 10 )) ]; then
        DELAY=1
    else
        DELAY=$(( DELAY * 2 ))
        [ "$DELAY" -gt 30 ] && DELAY=30
        echo "eve-gui exited immediately; retrying in ${DELAY}s"
    fi
    sleep "$DELAY"
done
