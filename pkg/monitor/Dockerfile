FROM alpine:3.20 as toolchain
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
FROM toolchain as planer
# copy sources
COPY ./src /app/src
COPY Cargo.toml /app/Cargo.toml
COPY Cargo.lock /app/Cargo.lock
# create a recipe
RUN cargo chef prepare --recipe-path recipe.json

FROM toolchain as cacher
# copy the recipe
WORKDIR /app
COPY --from=planer /app/recipe.json recipe.json
# build the dependencies
RUN apk add --no-cache ncurses-dev ncurses-static
RUN cargo chef cook --release --recipe-path recipe.json

# building the final image
FROM toolchain as builder
WORKDIR /app
# copy sources
COPY ./src /app/src
COPY Cargo.toml /app
COPY Cargo.lock /app
COPY rust-toolchain.toml /app

# copy the cooked dependencies
COPY --from=cacher /app/target target
# copy the .cargo directory
COPY --from=cacher /root/.cargo /root/.cargo
RUN apk add --no-cache ncurses-dev ncurses-static
RUN cargo  build --release

FROM alpine:3.20 as runtime
RUN apk add --no-cache kbd
COPY --from=builder /app/target/release/monitor /sbin/monitor
COPY run-monitor.sh /sbin/run-monitor.sh

CMD ["/sbin/run-monitor.sh"]
