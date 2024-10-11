# syntax=docker/dockerfile:1
ARG RUST_VERSION=lfedge/eve-rust:1.80.1
FROM --platform=$BUILDPLATFORM ${RUST_VERSION} AS toolchain-base
ARG TARGETARCH

FROM toolchain-base AS target-amd64
ENV CARGO_BUILD_TARGET="x86_64-unknown-linux-musl"

FROM toolchain-base AS target-arm64
ENV CARGO_BUILD_TARGET="aarch64-unknown-linux-musl"

FROM toolchain-base AS target-riscv64
ENV CARGO_BUILD_TARGET="riscv64gc-unknown-linux-gnu"

FROM target-$TARGETARCH AS toolchain
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

FROM toolchain AS planer
# get sources from GIT
ADD ./eve-monitor-rs /app

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
ADD ./eve-monitor-rs /app
WORKDIR /app

# copy prebuilt dependencies
# and the cargo directory with crates.io index
COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

RUN cargo build --release
RUN cargo sbom > sbom.spdx.json
RUN cp /app/target/$CARGO_BUILD_TARGET/release/monitor /app/target/


FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 AS runtime
ENV PKGS="kbd pciutils usbutils"
#ncurses-terminfo
RUN eve-alpine-deploy.sh

FROM scratch
COPY --from=runtime /out/usr/bin/openvt /usr/bin/openvt
COPY --from=runtime /out/usr/bin/loadkeys /usr/bin/loadkeys
COPY --from=runtime /out/bin/dmesg /usr/bin/dmesg
COPY --from=runtime /out/usr/bin/lsusb /usr/bin/lsusb
COPY --from=runtime /out/usr/bin/lspci /usr/bin/lspci
COPY --from=runtime /out/usr/share/keymaps/xkb/us.map.gz /usr/share/keymaps/xkb/us.map.gz
COPY --from=runtime /out/lib /lib
COPY --from=runtime /out/usr/lib /usr/lib

# copy busybox and sh but just for debugging
COPY --from=runtime /out/bin/sh /bin/sh
COPY --from=runtime /out/bin/busybox /bin/busybox
COPY --from=runtime /out/usr/bin/du /usr/bin/du

COPY --from=builder /app/target/monitor /sbin/monitor
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json
COPY run-monitor.sh /sbin/run-monitor.sh

CMD ["/sbin/run-monitor.sh"]
#21846
#9257
#19200
#14171
#14435
#15891
