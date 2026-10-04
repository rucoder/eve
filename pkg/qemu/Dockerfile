# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# QEMU for KVM, built from upstream with EVE's patches in patches/, plus
# what its virtual GPU needs: virglrenderer, libepoxy and the Mesa from
# pkg/mesa.
#
# The image is a runtime tree for pkg/xen-tools to copy into the rootfs
# pillar runs each domain's QEMU from. It does not run on its own. Alpine's
# shared libraries that it links against (glib, pixman, gnutls, ...) are
# not included; the consumer installs them.
#
# Built from source rather than taken from Alpine:
#   virglrenderer  1.3.0 for native context; Alpine 3.22 has 1.1.0
#   libepoxy       Alpine's -dev package pulls in Alpine's Mesa and X11
#   liburing       not in the eve-alpine mirror

FROM lfedge/eve-mesa:b834a0cffbd661686550be6390f60933f1d22996 AS mesa

FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS build
# py3-pip and py3-wheel: QEMU's configure builds its Python tooling venv from
# the system site packages, and without them it goes to PyPI.
ENV BUILD_PKGS="build-base meson samurai pkgconf python3 py3-setuptools py3-pip py3-wheel py3-yaml perl bash \
    linux-headers flex bison glib-dev pixman-dev zlib-dev gnutls-dev libusb-dev \
    zstd-dev libaio-dev bzip2-dev libdrm-dev libcap-ng-dev attr-dev util-linux-dev \
    expat-dev dtc-dev coreutils"
RUN eve-alpine-deploy.sh

# Mesa's headers, pkg-config files and libraries, for building against.
COPY --from=mesa /usr/ /usr/

ENV LIBEPOXY_VERSION=1.5.10
ENV VIRGLRENDERER_VERSION=1.3.0
ENV LIBURING_VERSION=2.15
ENV QEMU_VERSION=11.1.2
# hadolint ignore=DL3020
ADD --checksum=sha256:072cda4b59dd098bba8c2363a6247299db1fa89411dc221c8b81b8ee8192e623 \
    https://download.gnome.org/sources/libepoxy/1.5/libepoxy-${LIBEPOXY_VERSION}.tar.xz /libepoxy.tar.xz
# hadolint ignore=DL3020
ADD --checksum=sha256:56170f8caa1bb642a2624b649e3bcca095ec2834814e5c308efc8a85a709e4ce \
    https://gitlab.freedesktop.org/virgl/virglrenderer/-/archive/virglrenderer-${VIRGLRENDERER_VERSION}/virglrenderer-virglrenderer-${VIRGLRENDERER_VERSION}.tar.gz /virglrenderer.tar.gz
# hadolint ignore=DL3020
ADD --checksum=sha256:28661631f95fce6b3a0f77e40442a937cf4c62cac76a2671ad68378cafb5c21e \
    https://git.kernel.org/pub/scm/linux/kernel/git/axboe/liburing.git/snapshot/liburing-${LIBURING_VERSION}.tar.gz /liburing.tar.gz
# hadolint ignore=DL3020
ADD --checksum=sha256:731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016 \
    https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz /qemu.tar.xz
RUN mkdir -p /src && \
    tar -C /src -xJf /libepoxy.tar.xz && \
    tar -C /src -xzf /virglrenderer.tar.gz && \
    tar -C /src -xzf /liburing.tar.gz && \
    tar -C /src -xJf /qemu.tar.xz

# Each library is installed twice: under /dist, which ships, and into the
# build root, for the next one to build against.
WORKDIR /src/libepoxy-${LIBEPOXY_VERSION}
RUN meson setup /build/libepoxy --prefix=/usr --buildtype=release \
        -Dglx=no -Dx11=false -Degl=yes -Dtests=false -Ddocs=false && \
    meson compile -C /build/libepoxy && \
    meson install -C /build/libepoxy --destdir /dist --strip && \
    meson install -C /build/libepoxy

WORKDIR /src/virglrenderer-virglrenderer-${VIRGLRENDERER_VERSION}
RUN meson setup /build/virglrenderer --prefix=/usr --buildtype=release \
        -Dplatforms=egl -Dvenus=false -Ddrm-renderers=i915-experimental \
        -Dtests=false && \
    meson compile -C /build/virglrenderer && \
    meson install -C /build/virglrenderer --destdir /dist --strip && \
    meson install -C /build/virglrenderer

WORKDIR /src/liburing-${LIBURING_VERSION}
RUN ./configure --prefix=/usr && \
    make -C src -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install DESTDIR=/dist && \
    make install

# Frame pointers, so a core dump gives a usable stack: unwinding a
# musl-linked QEMU without them gets a few frames at best.
WORKDIR /src/qemu-${QEMU_VERSION}
COPY patches /patches
RUN for p in /patches/*.patch; do patch -p1 < "$p" || exit 1; done
RUN case "$(uname -m)" in \
        x86_64)  TARGETS=x86_64-softmmu ;; \
        aarch64) TARGETS=aarch64-softmmu ;; \
        *)       echo "unsupported architecture $(uname -m)"; exit 1 ;; \
    esac && \
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --target-list="$TARGETS" \
        --enable-kvm --disable-xen --disable-tools \
        --disable-werror --disable-docs --disable-guest-agent \
        --disable-slirp --disable-sdl --disable-gtk --disable-curses \
        --enable-trace-backends=log,simple \
        --enable-libusb --enable-linux-aio --enable-linux-io-uring --enable-zstd \
        --enable-vhost-net --enable-vhost-kernel --enable-vhost-user \
        --enable-virtfs --enable-tpm --enable-vnc --enable-gnutls --enable-fdt=system \
        --enable-dbus-display --enable-opengl --enable-virglrenderer \
        --extra-cflags="-DXATTR_SIZE_MAX=65536 -fno-omit-frame-pointer" && \
    make -j "$(getconf _NPROCESSORS_ONLN)" && \
    make install DESTDIR=/dist

# QEMU ships stripped. To ship its debug info again - so a core from a device
# opens against the rootfs with gdb and no further setup - replace the plain
# strip below with the commented split, which keeps the symbols under
# /usr/lib/debug where gdb finds them through .gnu_debuglink. It costs about
# 58MB raw, 17MB in the squashfs rootfs.
WORKDIR /dist/usr/bin
RUN for f in *; do strip "$f" || :; done
# RUN mkdir -p /dist/usr/lib/debug/usr/bin && \
#     for f in qemu-system-*; do \
#         objcopy --only-keep-debug "$f" "/dist/usr/lib/debug/usr/bin/$f.debug" && \
#         strip --strip-debug --strip-unneeded "$f" && \
#         objcopy --add-gnu-debuglink="/dist/usr/lib/debug/usr/bin/$f.debug" "$f"; \
#     done && \
#     for f in *; do case "$f" in qemu-system-*) ;; *) strip "$f" || : ;; esac; done

# The Mesa this was built against, runtime parts only.
RUN cp -a /usr/lib/libgallium-*.so /usr/lib/libgbm.so.* /usr/lib/libEGL.so.* \
          /usr/lib/libEGL_mesa.so.* /usr/lib/libGLESv2.so.* /usr/lib/libOpenGL.so.* \
          /usr/lib/libGLdispatch.so.* /dist/usr/lib/ && \
    mkdir -p /dist/usr/lib/gbm /dist/usr/share && \
    cp -a /usr/lib/gbm/dri_gbm.so /dist/usr/lib/gbm/ && \
    cp -a /usr/share/glvnd /usr/share/drirc.d /dist/usr/share/

# Firmware for machines EVE never runs, and build-time files.
RUN rm -rf /dist/usr/include /dist/usr/lib/pkgconfig /dist/usr/share/man \
           /dist/usr/share/doc /dist/usr/share/qemu/edk2-* \
           /dist/usr/share/qemu/openbios-* /dist/usr/bin/virgl_test_server && \
    find /dist -name '*.a' -delete && \
    rm -f /dist/usr/share/qemu/skiboot.lid /dist/usr/share/qemu/hppa-firmware.img \
          /dist/usr/share/qemu/hppa-firmware64.img /dist/usr/share/qemu/s390-ccw.img \
          /dist/usr/share/qemu/s390-netboot.img /dist/usr/share/qemu/slof.bin \
          /dist/usr/share/qemu/opensbi-riscv32-generic-fw_dynamic.bin \
          /dist/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin

# Fail if anything that ships links libLLVM: pkg/mesa exists to keep it out.
RUN set -e; \
    for f in $(find /dist -name '*.so*' -type f) /dist/usr/bin/qemu-system-*; do \
        if readelf -d "$f" | grep -q 'NEEDED.*libLLVM'; then \
            echo "ERROR: $f links LLVM"; exit 1; \
        fi; \
    done

COPY --from=mesa /lib/apk/db/installed /mesa-sbom
RUN register-sbom-pkg.sh -o /dist -n libepoxy -v "${LIBEPOXY_VERSION}" -l MIT \
        -u https://github.com/anholt/libepoxy && \
    register-sbom-pkg.sh -o /dist -n virglrenderer -v "${VIRGLRENDERER_VERSION}" -l MIT \
        -u https://gitlab.freedesktop.org/virgl/virglrenderer && \
    register-sbom-pkg.sh -o /dist -n liburing -v "${LIBURING_VERSION}" \
        -l "LGPL-2.1-only OR MIT" -u https://github.com/axboe/liburing && \
    register-sbom-pkg.sh -o /dist -n qemu -v "${QEMU_VERSION}" -l GPL-2.0-only \
        -u https://www.qemu.org && \
    merge-sbom-db.sh -o /dist/lib/apk/db/installed /dist/lib/apk/db/installed /mesa-sbom

FROM scratch
COPY --from=build /dist/ /
