#!/bin/sh
echo "Running EVE monitor"
env RUST_BACKTRACE=1

# leave only panic on console
dmesg -n 1

# setup keymap
loadkeys -s us - <<EOF
control keycode 103 = F103
control keycode 108 = F108
control keycode 106 = F106
control keycode 105 = F105
string F103 = "\033[1;5A"
string F108 = "\033[1;5B"
string F106 = "\033[1;5C"
string F105 = "\033[1;5D"
EOF

openvt -c 2 -s -f -w -- /sbin/monitor
