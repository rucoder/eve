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
RUN cargo chef cook --profile quick --recipe-path recipe.json

# building the final image
FROM toolchain AS builder
COPY . /app
WORKDIR /app

# copy prebuilt dependencies
# and the cargo directory with crates.io index
COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

# TEMPORARY, for POC iteration: the quick profile drops LTO and size
# optimisation, which cuts the build substantially. Revert to --release before
# this ships - see [profile.quick] in Cargo.toml.
RUN cargo build --profile quick
RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/quick/monitor" /app/target/
# Single source of truth for the version: the crate manifest.
RUN awk -F'"' '/^version = / {print $2; exit}' Cargo.toml > /app/monitor-version.txt


FROM lfedge/eve-mesa:2288540d3bd8a081a27735367e2f0db295273f30 AS mesa

FROM lfedge/eve-alpine:1d60238fe336a7782fb173fed1be692246a27dfa AS runtime
# Mesa comes from pkg/mesa, built without LLVM, for iris (Gen9+ Intel, which
# the gui frontend's EGL/GBM path drives) plus virgl for EVE running as a VM.
# Its libraries need libdrm, expat, zlib, zstd and libstdc++ from Alpine.
# libxkbcommon is deliberately absent: smithay wants -lxkbcommon at LINK time,
# but nothing resolves it at run time - the gui binary's NEEDED list is
# libgbm, libinput, libgcc_s and libc, and no shipped library dlopens it. It
# reads evdev directly and puts the VT keyboard in K_OFF, so there is no
# keymap to build.
# libxkbcommon is pulled in through smithay. The release profile's LTO was
# eliding the reference, so the runtime got away without it; any build that
# does not do whole-program LTO - the quick profile, for one - leaves a real
# DT_NEEDED on libxkbcommon.so.0 and the console dies at startup with a
# missing shared library. Ship it rather than depend on an optimisation to
# make the dependency disappear.
ENV PKGS="kbd pciutils usbutils libdrm libexpat zlib zstd-libs libstdc++ libinput-libs libxkbcommon eudev-libs"
RUN eve-alpine-deploy.sh

# The Mesa runtime, and only the parts the console uses: libgallium, GBM and
# the dri_gbm backend libgbm loads through GBM_BACKENDS_PATH, glvnd's EGL and
# GLES dispatch, Mesa's EGL vendor library, the JSON that makes glvnd find it
# (without it libEGL.so.1 loads and reports no display), and driconf defaults.
COPY --from=mesa /usr/ /mesa/usr/
RUN cp -a /mesa/usr/lib/libgallium-*.so /mesa/usr/lib/libgbm.so.* /mesa/usr/lib/libEGL.so.* \
          /mesa/usr/lib/libEGL_mesa.so.* /mesa/usr/lib/libGLESv2.so.* \
          /mesa/usr/lib/libGLdispatch.so.* /out/usr/lib/ && \
    mkdir -p /out/usr/lib/gbm /out/usr/share && \
    cp -a /mesa/usr/lib/gbm/dri_gbm.so /out/usr/lib/gbm/ && \
    cp -a /mesa/usr/share/glvnd /mesa/usr/share/drirc.d /out/usr/share/

# The stage below copies /out/usr/lib (and part of /out/usr/share) wholesale,
# so anything a package drags in ships. Each removal here was checked against
# the actual link closure of the binaries we run plus the libraries mesa
# dlopens - not guessed from names.
#
# NOT removed, though it looks unused: usr/share/hwdata/pci.ids, which
# libpciaccess (lspci) reads at run time.
RUN set -e; \
    # apk's library has no business in a runtime image, and it is the only
    # thing here that pulls in the TLS stack.
    rm -f /out/usr/lib/libapk.so.* /out/usr/lib/libcrypto.so.* /out/usr/lib/libssl.so.*; \
    rm -rf /out/usr/lib/engines-3 /out/usr/lib/ossl-modules; \
    # libdrm's per-vendor helpers: pkg/mesa's libgallium links libdrm.so.2 only.
    rm -f /out/usr/lib/libdrm_*.so*

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
# libinput reads its device-quirks data at runtime and complains loudly
# ("failed to find data files") without it. The quirks are part of
# libinput-libs, alongside the shared library - the separate libinput package
# is the CLI tools, ships nothing under /usr/share, and is not in the
# eve-alpine mirror anyway. Taking both from one package is also what keeps
# them in step: a quirks file from a newer libinput than the .so on the
# device makes the parser reject the whole set.
COPY --from=runtime /out/usr/share/libinput /usr/share/libinput
COPY --from=runtime /out/usr/share/glvnd /usr/share/glvnd
COPY --from=runtime /out/usr/share/drirc.d /usr/share/drirc.d
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
