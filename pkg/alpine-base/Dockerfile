FROM alpine:3.20 AS builder

WORKDIR /rootfs

# Since riscv64 is not officially supported yet, we use distinct package source
# busybox do not support https to storage.googleapis.com so we use http here
# and replace with https for repo url
RUN case $(uname -m) in \
    x86_64|aarch64|riscv64) \
        ROOTFS_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/$(uname -m)/alpine-minirootfs-3.20.0-$(uname -m).tar.gz"; \
        ;; \
    *) echo "Unsupported architecture $(uname -m). Exiting" && exit 1 \
      ;; \
    esac && \
    wget -q -O /tmp/rootfs.tar.gz "$ROOTFS_URL" && \
    tar xzf /tmp/rootfs.tar.gz

FROM scratch

# seed the root filesystem
COPY --from=builder /rootfs/ /

# set the defaults for docker run
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
CMD sh
