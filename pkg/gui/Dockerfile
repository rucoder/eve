# Copyright (c) 2026 Zededa, Inc.
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
# Unlike the TUI monitor, this package links against the graphics and input
# stack: libgbm and libEGL for the scanout, libdrm for KMS, libinput for evdev.
# hadolint ignore=DL3018
RUN apk add --no-cache mesa-dev libdrm-dev libinput-dev eudev-dev pkgconf
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

FROM toolchain AS planer
COPY . /app
WORKDIR /app
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS cacher
WORKDIR /app
COPY --from=planer /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

FROM toolchain AS builder
COPY . /app
WORKDIR /app
COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

RUN cargo build --release
RUN cargo sbom > sbom.spdx.json
RUN cp "/app/target/$CARGO_BUILD_TARGET/release/eve-gui" /app/target/
# Single source of truth for the version: the crate manifest.
RUN awk -F'"' '/^version = / {print $2; exit}' Cargo.toml > /app/gui-version.txt

FROM lfedge/eve-alpine:ef20bcb617db5545765f4d7486621cf606e5595e AS runtime
# mesa-dri-gallium carries the iris driver used by Gen12+ Intel graphics, which
# is what the EGL/GBM path needs at runtime; without it EGL falls back to
# software or fails outright.
ENV PKGS="kbd mesa-gbm mesa-egl mesa-gles mesa-dri-gallium libdrm libinput-libs eudev-libs"
RUN eve-alpine-deploy.sh

COPY --from=builder /app/gui-version.txt /tmp/gui-version
RUN register-sbom-pkg.sh -n eve-gui -v "$(cat /tmp/gui-version)" -l Apache-2.0 -u https://github.com/lf-edge/eve/tree/master/pkg/gui

FROM scratch
COPY --from=runtime /out/usr/bin/openvt /usr/bin/openvt
COPY --from=runtime /out/bin/dmesg /usr/bin/dmesg
COPY --from=runtime /out/lib /lib
COPY --from=runtime /out/usr/lib /usr/lib
COPY --from=runtime /out/usr/share /usr/share

# busybox and its symlinks, for debugging on the device
COPY --from=runtime /out/bin/busybox /bin/busybox
# using an 'exec' form of RUN, shell form of 'RUN'
# command expects /bin/sh which doesn't yet exist
RUN [ "/bin/busybox", "--install", "-s", "/bin" ]

COPY --from=builder /app/target/eve-gui /sbin/eve-gui
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json
COPY run-gui.sh /sbin/run-gui.sh

CMD ["/sbin/run-gui.sh"]
