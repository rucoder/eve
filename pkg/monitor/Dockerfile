# Copyright (c) 2024-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

ARG RUST_VERSION=lfedge/eve-rust:1.93.1-1
# RUST_VERSION carries an explicit tag by default
# hadolint ignore=DL3006
FROM --platform=$BUILDPLATFORM ${RUST_VERSION} AS toolchain-base
ARG TARGETARCH

FROM toolchain-base AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM toolchain-base AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM toolchain-base AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-musl"

# target-$TARGETARCH is a build stage, not an image
# hadolint ignore=DL3006
FROM target-$TARGETARCH AS toolchain
# The gui frontend links against the graphics and input stack: libgbm and
# libEGL for the scanout, libdrm for KMS, libinput for evdev.
# hadolint ignore=DL3018
RUN apk add --no-cache mesa-dev libdrm-dev libinput-dev libxkbcommon-dev eudev-dev pkgconf
# Link dynamically against musl. The Rust musl target defaults to a static
# binary, and there is no static libgbm or libinput to link against - mesa does
# not ship one - so a static build fails with "library not found: gbm". The
# shared libraries are installed into the runtime image below.
ENV RUSTFLAGS="-C target-feature=-crt-static"
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

FROM toolchain AS planer
COPY . /app

WORKDIR /app
# create a recipe
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS cacher
# copy the recipe
WORKDIR /app
COPY --from=planer /app/recipe.json recipe.json
# build the dependencies
RUN cargo chef cook --release --recipe-path recipe.json

# building the final image
FROM toolchain AS builder
COPY . /app
WORKDIR /app

# copy prebuilt dependencies
# and the cargo directory with crates.io index
COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

RUN cargo build --release
RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/release/monitor" /app/target/
# Single source of truth for the version: the crate manifest.
RUN awk -F'"' '/^version = / {print $2; exit}' Cargo.toml > /app/monitor-version.txt


FROM lfedge/eve-alpine:1d60238fe336a7782fb173fed1be692246a27dfa AS runtime
# mesa-dri-gallium carries the iris driver used by Gen12+ Intel graphics, which
# is what the gui frontend's EGL/GBM path needs at runtime; without it EGL
# falls back to software or fails outright.
# libxkbcommon is deliberately absent: smithay wants -lxkbcommon at LINK time,
# but nothing resolves it at run time - the gui binary's NEEDED list is
# libgbm, libinput, libgcc_s and libc, and no shipped library dlopens it. It
# reads evdev directly and puts the VT keyboard in K_OFF, so there is no
# keymap to build.
ENV PKGS="kbd pciutils usbutils mesa-gbm mesa-egl mesa-gles mesa-dri-gallium libdrm libinput-libs eudev-libs"
RUN eve-alpine-deploy.sh

# The stage below copies /out/usr/lib (and part of /out/usr/share) wholesale,
# so anything a package drags in ships. Each removal here was checked against
# the actual link closure of the binaries we run plus the libraries mesa
# dlopens - not guessed from names.
#
# NOT removed, though they look unused: usr/lib/gbm/dri_gbm.so, which libgbm
# resolves through GBM_BACKENDS_PATH rather than NEEDED, and
# usr/share/hwdata/pci.ids, which libpciaccess reads at run time.
#
# libLLVM stays too: libgallium.so lists it NEEDED, so removing it stops the
# loader dead even for iris, which does not itself use it. Dropping it means
# building mesa with -Dllvm=disabled -Dgallium-drivers=iris.
RUN set -e; \
    # Gallium drivers for hardware this image will never see. EVE's console
    # targets Gen12+ Intel; a host with no supported GPU has no render node
    # either, so it gets no display at all and never reaches a driver.
    find /out/usr/lib/gallium-pipe -name 'pipe_*.so' ! -name 'pipe_iris.so' -delete; \
    # apk's library has no business in a runtime image, and it is the only
    # thing here that pulls in the TLS stack.
    rm -f /out/usr/lib/libapk.so.* /out/usr/lib/libcrypto.so.* /out/usr/lib/libssl.so.*; \
    rm -rf /out/usr/lib/engines-3 /out/usr/lib/ossl-modules; \
    # libgallium needs libSPIRV-Tools.so, which needs only libstdc++ and libc;
    # the -opt/-shared/-reduce/-diff/-link/-lint siblings are unreachable.
    find /out/usr/lib -name 'libSPIRV-Tools-*.so' -delete; \
    # libgallium links the xcb shims. libX11-xcb.so has no NEEDED entries at
    # all, so libX11 itself is never loaded - and with it goes the xkb data.
    rm -f /out/usr/lib/libX11.so.*; \
    rm -rf /out/usr/share/X11; \
    # Alias directory of symlinks to ../../libLLVM.so.20.1, which stays put.
    rm -rf /out/usr/lib/llvm20; \
    # Radeon KMS helper: libgallium needs libdrm_amdgpu and libdrm_intel only.
    rm -f /out/usr/lib/libdrm_radeon.so.*

# Register the monitor TUI in the APK DB (mandatory for SBOM inclusion). The
# version comes from the crate manifest (Cargo.toml) — the single source of
# truth now that the source is colocated and no longer pulled by git tag.
COPY --from=builder /app/monitor-version.txt /tmp/monitor-version
RUN register-sbom-pkg.sh -n eve-monitor-rs -v "$(cat /tmp/monitor-version)" -l Apache-2.0 -u https://github.com/lf-edge/eve/tree/master/pkg/monitor

FROM scratch
COPY --from=runtime /out/usr/bin/openvt /usr/bin/openvt
COPY --from=runtime /out/usr/bin/loadkeys /usr/bin/loadkeys
COPY --from=runtime /out/bin/dmesg /usr/bin/dmesg
COPY --from=runtime /out/usr/bin/lsusb /usr/bin/lsusb
COPY --from=runtime /out/usr/bin/lspci /usr/bin/lspci
COPY --from=runtime /out/usr/share/keymaps/xkb/us.map.gz /usr/share/keymaps/xkb/us.map.gz
# libpciaccess (mesa) reads this at run time; see the prune block above.
COPY --from=runtime /out/usr/share/hwdata /usr/share/hwdata
COPY --from=runtime /out/lib /lib
COPY --from=runtime /out/usr/lib /usr/lib

# copy busybox and install all symbolic links but just for debugging
COPY --from=runtime /out/bin/busybox /bin/busybox
# using an 'exec' form of RUN, shell form of 'RUN'
# command expects /bin/sh which doesn't yet exist
RUN [ "/bin/busybox", "--install", "-s", "/bin" ]
COPY --from=runtime /out/usr/bin/du /usr/bin/du

COPY --from=builder /app/target/monitor /sbin/monitor
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json
COPY run-monitor.sh /sbin/run-monitor.sh
COPY monitor-wrapper.sh /sbin/monitor-wrapper.sh

CMD ["/sbin/run-monitor.sh"]
