FROM alpine:3.20 AS toolchain
#install rust and cargo
RUN apk add --no-cache rustup gcc musl-dev
# call rustup-init but do not install default toolchain
RUN rustup-init -y --default-toolchain none --profile minimal
# set the PATH for the shell
ENV PATH="/root/.cargo/bin:${PATH}"
ADD rust-toolchain.toml /app/rust-toolchain.toml
# install the toolchain. This is the hack to install the toolchain without installing the default toolchain
# rust is a cross platform by default so we always compile for the target platform
# required toolchain is invoked utomatically
WORKDIR /app
RUN rustup show

# TODO: install specific version cargo-chef
RUN cargo install cargo-chef
FROM toolchain AS planer
# get sources from GIT
ADD git@github.com:rucoder/standalone-tui.git#rucoder/iface-details /app
ADD rust-toolchain.toml /app

# create a recipe
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain AS cacher
# copy the recipe
WORKDIR /app
COPY --from=planer /app/recipe.json recipe.json
# build the dependencies
RUN apk add --no-cache ncurses-dev ncurses-static
RUN cargo chef cook --release --recipe-path recipe.json

# building the final image
FROM toolchain AS builder
ADD git@github.com:rucoder/standalone-tui.git#rucoder/iface-details /app
COPY rust-toolchain.toml /app
WORKDIR /app

# copy the cooked dependencies
COPY --from=cacher /app/target target
# copy the .cargo directory
COPY --from=cacher /root/.cargo /root/.cargo
RUN cargo  build --release

FROM alpine:3.20 AS runtime
RUN apk add --no-cache kbd pciutils usbutils ncurses ncurses-terminfo
COPY --from=builder /app/target/release/monitor /sbin/monitor
COPY run-monitor.sh /sbin/run-monitor.sh

CMD ["/sbin/run-monitor.sh"]

#9448
#30650
#16169
#12509
#12147
