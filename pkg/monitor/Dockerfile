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
ADD https://github.com/lf-edge/eve-monitor-rs /app

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
ADD https://github.com/lf-edge/eve-monitor-rs /app
WORKDIR /app

# copy prebuilt dependencies
# and the cargo directory with crates.io index
COPY --from=cacher /app/target /app/target
COPY --from=cacher $CARGO_HOME $CARGO_HOME
RUN echo "Cargo target: $CARGO_BUILD_TARGET"

RUN cargo build --release
RUN cargo sbom > sbom.spdx.json
RUN cp /app/target/$CARGO_BUILD_TARGET/release/monitor /app/target/

FROM alpine:3.20 AS runtime

RUN apk add --no-cache kbd pciutils usbutils ncurses ncurses-terminfo
COPY --from=builder /app/target/monitor /sbin/monitor
COPY --from=builder /app/sbom.spdx.json /sbin/sbom.spdx.json
COPY run-monitor.sh /sbin/run-monitor.sh

CMD ["/sbin/run-monitor.sh"]

