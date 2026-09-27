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

scp -o StrictHostKeyChecking=no /tmp/monitor.new "$HOST:/tmp/monitor.new"
ssh -o StrictHostKeyChecking=no "$HOST" '
  set -e
  test -d /persist/services/monitor || { echo "not staged: see header of dev-push.sh"; exit 1; }
  mountpoint -q /containers/services/monitor/lower || { echo "bind not active - reboot once after staging"; exit 1; }
  cp /tmp/monitor.new /persist/services/monitor/sbin/monitor
  chmod +x /persist/services/monitor/sbin/monitor
  # Kill the wrapper, not just the binary. monitor-wrapper.sh runs
  # /sbin/monitor and then blocks on a read so a human can see panic output;
  # with only the binary killed that read waits forever on an unattended tty2,
  # openvt never returns, and run-monitor.sh never loops round to restart.
  pkill -f "/sbin/monitor-wrapper.sh" || true
  pkill -f "^/sbin/monitor$" || true
  i=0
  while [ $i -lt 20 ]; do
    sleep 2
    if pgrep -f "^/sbin/monitor$" >/dev/null; then echo "CONSOLE_BACK_UP"; exit 0; fi
    i=$((i+1))
  done
  echo "CONSOLE_DID_NOT_RESTART - check /persist/monitor/log"; exit 1
'
