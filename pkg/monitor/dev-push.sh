#!/bin/sh
# Rebuild the console for the device and swap it in, without rebuilding the
# image. Needs storage-init's /persist/services override (see
# pkg/storage-init/storage-init.sh) and a one-time stage on the device:
#
#   mkdir -p /persist/services
#   cp -a /containers/services/monitor/lower /persist/services/monitor
#   reboot                      # the bind is established at boot
#
# After that this script is the whole loop.
set -e
HOST="${1:-local-eve}"
DIR="$(cd "$(dirname "$0")" && pwd)"
IMG=eve-monitor-toolchain

# Same toolchain the package Dockerfile uses: musl target, the Alpine dev
# libraries the gui frontend links against, and dynamic linking. Named volumes
# keep the cargo registry and target dir across runs - buildkit's own cache
# does not survive, which is why the in-container package build re-downloads
# the crates index every time.
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q -t "$IMG" - <<'DOCKER'
FROM lfedge/eve-rust:1.93.1-1
RUN apk add --no-cache mesa-dev libdrm-dev libinput-dev libxkbcommon-dev eudev-dev pkgconf
ENV RUSTFLAGS="-C target-feature=-crt-static"
ENV CARGO_BUILD_TARGET=x86_64-unknown-linux-musl
DOCKER

docker run --rm \
  -v "$DIR:/app" \
  -v eve-monitor-cargo:/usr/local/cargo/registry \
  -v eve-monitor-target:/target \
  -w /app "$IMG" \
  sh -c 'CARGO_TARGET_DIR=/target cargo build --profile quick'

docker run --rm -v eve-monitor-target:/target -v /tmp:/out alpine \
  cp /target/x86_64-unknown-linux-musl/quick/monitor /out/monitor.new

# The bind mount replaces the service's whole rootfs, not just the binary, so
# anything in the image can be pushed the same way. The shell scripts live in
# this repo and change as often as the Rust does.
tar -C "$DIR" -cf /tmp/monitor-scripts.tar run-monitor.sh monitor-wrapper.sh

# Staged under /persist because that is the one filesystem the debug container
# (where ssh lands) and the host mount namespace both see; each has its own
# /tmp, and the nsenter half of the push below runs in the host's.
scp -o StrictHostKeyChecking=no /tmp/monitor.new /tmp/monitor-scripts.tar "$HOST:/persist/"
# The remote block below carries no prose on purpose. pkill -f matches whole
# command lines, and this ssh invocation's argv is itself a command line on
# the target: any comment mentioning the wrapper by name makes pkill match
# our own shell, drop the connection, and return 255 - while the console
# restarts regardless, so a working push reports failure. The [m] bracket
# keeps the pattern from matching itself; keeping the name out of the block
# entirely is what makes that hold.
#
# Each file is written twice, and both writes are needed:
#
#   1. into the bind-mounted lower dir under /persist, so the change is still
#      there after a reboot;
#   2. through the service's live overlay at .../rootfs, from the HOST mount
#      namespace, so the running container sees it now.
#
# The second write is what actually takes effect. Changing a live overlay's
# lower layer is not supported - the overlay caches what it has resolved, both
# positively and negatively - so a lower-dir write alone is invisible until
# something remounts the overlay, and a file that is new (rather than
# rewritten in place) stays invisible even to a restarted process. Writing
# through the overlay copies up into its upper layer, which is the supported
# path and takes effect immediately. The upper layer is tmpfs, which is why
# write 1 is still needed.
#
# Killing only the binary is not enough: the wrapper runs it and then sleeps
# before run-monitor.sh's loop restarts it, and a surviving wrapper holds the
# tty. Kill both, or two consoles end up fighting over DRM master.
ssh -o StrictHostKeyChecking=no "$HOST" '
  set -e
  test -d /persist/services/monitor || { echo "NOT_STAGED - see header"; exit 1; }
  mountpoint -q /containers/services/monitor/lower || { echo "NO_BIND - reboot once after staging"; exit 1; }
  rm -rf /persist/.ms && mkdir -p /persist/.ms
  tar -C /persist/.ms -xf /persist/monitor-scripts.tar
  cp /persist/monitor.new /persist/services/monitor/sbin/monitor
  for f in /persist/.ms/*.sh; do cp "$f" "/persist/services/monitor/sbin/$(basename "$f")"; done
  chmod +x /persist/services/monitor/sbin/monitor /persist/services/monitor/sbin/*.sh
  nsenter -t 1 -m -- sh -c '"'"'
    R=/containers/services/monitor/rootfs
    cp /persist/monitor.new "$R/sbin/monitor"
    for f in /persist/.ms/*.sh; do cp "$f" "$R/sbin/$(basename "$f")"; done
    chmod +x "$R"/sbin/monitor "$R"/sbin/*.sh
  '"'"'
  pkill -f "[m]onitor-wrapper" || true
  pkill -f "^/sbin/monitor$" || true
  i=0
  while [ $i -lt 20 ]; do
    sleep 2
    if pgrep -f "^/sbin/monitor$" >/dev/null; then echo "CONSOLE_BACK_UP"; exit 0; fi
    i=$((i+1))
  done
  echo "CONSOLE_DID_NOT_RESTART - check /persist/monitor/console.log"; exit 1
'
