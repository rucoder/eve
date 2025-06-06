# image was bootstraped using FROM lfedge/eve-alpine-base:353bf866797f6e60f91cbe1b00c439634adfcf13 AS cache
# to update please see https://github.com/lf-edge/eve/blob/master/docs/BUILD.md#how-to-update-eve-alpine-package
FROM lfedge/eve-alpine-base:353bf866797f6e60f91cbe1b00c439634adfcf13 AS cache

FROM lfedge/eve-alpine:b96ae7c5b776702cdc7596e3722e40cc0d353ad7 AS cache-riscv64
FROM cache AS cache-amd64
FROM cache AS cache-arm64
# hadolint ignore=DL3006
FROM cache-${TARGETARCH} AS cache-build

ARG ALPINE_VERSION=3.16
# this is only needed once, when this package
# is rebased on the new version of Alpine and
# you have to have FROM alpine:x.y.z above:
RUN apk update && apk upgrade -a

# Copy Dockerfile so we can include it in the hash
COPY Dockerfile abuild.conf /etc/
COPY mirrors /tmp/mirrors/
COPY build-cache.sh /bin/

# install abuild for signing (which requires gcc as well)
# hadolint ignore=DL3018
RUN apk add --no-cache abuild gcc sudo

# install a new key into /etc/apk/keys
# hadolint ignore=DL3059
RUN abuild-keygen -a -i -n

# create all the mirrors
WORKDIR /tmp/mirrors
RUN [ -f /etc/apk/repositories.upstream ] || mv /etc/apk/repositories /etc/apk/repositories.upstream
# hadolint ignore=DL3059
RUN [ -f /etc/apk/cache.url ] || echo https://dl-cdn.alpinelinux.org/alpine > /etc/apk/cache.url
RUN for repo in main community testing; do \
      for p in */"$repo"; do \
        if [ ! -f "$p" ]; then echo "skipping $p"; continue; fi &&\
        packages="" &&\
        if [ -f "$p" ]; then packages="$packages $(cat "$p")"; fi &&\
        if [ -f "$p.$(apk --print-arch)" ]; then packages="$packages $(cat "$p.$(apk --print-arch)")"; fi &&\
        if [ -n "$packages" ]; then build-cache.sh "$p" "/mirror/$(dirname "$p")" "$packages"; fi \
      done \
    done

# set the default repository to use
RUN cp /mirror/${ALPINE_VERSION}/rootfs/etc/apk/repositories /etc/apk
RUN cat /mirror/edge/rootfs/etc/apk/repositories >> /etc/apk/repositories
RUN apk update

FROM lfedge/eve-alpine:591df01e581889c3027514c8a91feaca1c8ad49f AS compactor

COPY --from=cache-build /etc/apk/repositories* /etc/apk/
COPY --from=cache-build /etc/apk/keys /etc/apk/keys/
COPY --from=cache-build /mirror /mirror/
COPY eve-alpine-deploy.sh go-compile.sh /bin/

RUN apk update && apk upgrade -a

# define arch-specific envs
FROM scratch as final-amd64
ENV EVE_BUILD_ARCH=x86_64
ENV EVE_TARGET_ARCH=x86_64
FROM scratch as final-arm64
ENV EVE_BUILD_ARCH=aarch64
ENV EVE_TARGET_ARCH=aarch64
FROM scratch as final-riscv64
ENV EVE_BUILD_ARCH=riscv64
ENV EVE_TARGET_ARCH=riscv64

# we merge layers in previous step
# so we should avoid large possible diff
# hadolint ignore=DL3006
FROM final-${TARGETARCH}
COPY --from=compactor / /
CMD ["/bin/sh"]
