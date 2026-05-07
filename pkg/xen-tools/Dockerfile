# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-uefi:417cf0c3acf434fb0f775e8a588ae7b6e3523d6d AS uefi-build
FROM lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04 AS runx-build
ENV BUILD_PKGS="mkinitfs gcc musl-dev e2fsprogs chrony agetty"
RUN eve-alpine-deploy.sh

RUN rm -f /sbin/poweroff /etc/mkinitfs/features.d/base.files
COPY initrd/base.files /etc/mkinitfs/features.d/base.files
COPY initrd/init-initrd initrd/mount_disk.sh initrd/udhcpc_script.sh /
COPY initrd/poweroff /sbin/poweroff
COPY initrd/chroot2.c initrd/hacf.c /tmp/
COPY initrd/00000080 /etc/acpi/PWRF/
COPY initrd/eve-enter-container /bin/
COPY initrd/dotprofile /root/.profile
RUN gcc -s -o /chroot2 /tmp/chroot2.c -Wall -Werror
RUN gcc -s -o /hacf /tmp/hacf.c -Wall -Werror
RUN mkinitfs -n -F base -i /init-initrd -o /runx-initrd

FROM lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04 AS build
ENV BUILD_PKGS="\
    gcc make libc-dev dev86 xz-dev perl bash python3-dev \
    gettext iasl util-linux-dev ncurses-dev glib-dev \
    pixman-dev libaio-dev yajl-dev argp-standalone \
    linux-headers git patch texinfo tar libcap-ng-dev \
    attr-dev flex bison cmake libusb-dev zstd-dev \
    python3 py3-tomli build-base ninja gnutls-dev agetty"
# py3-tomli — needed by qemu 10.x's mkvenv when building under
# Python < 3.11 (Alpine 3.16 ships Python 3.10).  Python 3.11+
# has `tomllib` built-in and doesn't need this.

ENV BUILD_PKGS_arm64=dtc-dev

ENV PKGS="alpine-baselayout libgcc bash musl-utils libaio libbz2 glib pixman yajl keyutils libusb xz-libs libuuid zstd-libs util-linux-misc gnutls"
ENV PKGS_arm64=libfdt

RUN eve-alpine-deploy.sh

# Alpine linux defines all 64bit integer types as long. Patch
# /usr/include/bits/alltypes.h to fix compilation with -m32
WORKDIR /
COPY alpine.patch /
RUN patch -p1 < alpine.patch

ENV LIBURING_VERSION=0.7
ENV LIBURING_SOURCE=https://git.kernel.org/pub/scm/linux/kernel/git/axboe/liburing.git/snapshot/liburing-${LIBURING_VERSION}.tar.gz

# Download and verify liburing
# hadolint ignore=DL3020
ADD ${LIBURING_SOURCE} /liburing.tar.gz
RUN tar --absolute-names -xz < /liburing.tar.gz && mv "/liburing-${LIBURING_VERSION}" /liburing

WORKDIR /liburing
RUN ./configure --prefix=/usr
RUN make src && make install DESTDIR=/out && make install

# Filter out unneeded stuff
RUN rm -rf /out/usr/man
RUN strip /out/usr/lib/* || :

#
# Build upstream QEMU (v10.2.2) and stage it at /qemu-upstream/usr.
# Wired into Xen's build below via --with-system-qemu=PATH.
#
# Why: Xen 4.19 bundles qemu-xen 9.1.0 (xenbits.xen.org/git-http/qemu-xen.git
# master is still at 9.1.0 + Xen-PV patches as of 2026).  9.1.0 predates
# the major hw/vfio/igd.c refactor that landed in qemu 10.0 (BAR0 BDSM
# mirror, GMCH passthrough, ASLS clear, fw_cfg DSM-only, etc.) — exactly
# the code we need for clean Intel iGPU passthrough on Display 13
# (RPL-P / ADL-P).  Rather than backporting ~22 commits, swap in
# upstream qemu via the Xen-supported `--with-system-qemu=` mechanism.
#
ENV QEMU_VERSION v10.2.2
ENV QEMU_URL https://gitlab.com/qemu-project/qemu.git
WORKDIR /
ADD --keep-git-dir=true ${QEMU_URL}#${QEMU_VERSION} /qemu

# Local patches on top of upstream qemu — currently:
#   00012 — passive OpRegion dump (diagnostic)
#   00013 — ICH9-LPC x-device-id property (proprietary GOP whitelist spoof)
COPY qemu-upstream-patches /qemu-upstream-patches
WORKDIR /qemu
RUN set -e ; \
    if [ -d /qemu-upstream-patches ] && ls /qemu-upstream-patches/*.patch >/dev/null 2>&1 ; then \
        for patch in /qemu-upstream-patches/*.patch ; do \
            echo "Applying $patch" ; \
            git apply -p1 < "$patch" || exit 1 ; \
        done ; \
    fi

# QEMU configure flags chosen to match the feature set of the bundled
# qemu-xen build (linux-aio, libusb, vhost-net/kernel/user, vhost-vsock/scsi,
# linux-io-uring, zstd) plus KVM + GTK-less defaults.  Targets limited to
# x86_64-softmmu; qemu-system-i386 is symlinked to the x86_64 binary
# below to satisfy Xen's historical naming expectation.
RUN ./configure --prefix=/usr \
    --target-list=x86_64-softmmu \
    --enable-kvm \
    --enable-libusb \
    --enable-linux-aio \
    --enable-linux-io-uring \
    --enable-vhost-net --enable-vhost-kernel --enable-vhost-user \
    --enable-zstd \
    --disable-werror \
    --disable-docs \
    --disable-xen \
    --disable-tools \
    --disable-virglrenderer \
    --disable-spice \
    --disable-sdl --disable-gtk --disable-curses --disable-vnc-jpeg \
    --disable-rdma \
    --disable-fdt
# Notes on flags removed for qemu 10.x:
#   --enable-vhost-vsock / --enable-vhost-scsi — both auto-detected from
#       kernel uapi headers in qemu 10.x; explicit flags removed upstream.
#   --disable-blobs — renamed to --disable-install-blobs in 10.x.  Do
#       NOT pass it: qemu needs the bundled firmware blobs (vgabios,
#       efi-virtio.rom, kvmvapic, pvh, etc.) at runtime to boot guests.
#       The cleanup rm -f below trims arch-specific blobs we don't
#       need (slof / openbios / opensbi / hppa / s390 / skiboot).
RUN make -j "$(getconf _NPROCESSORS_ONLN)"
RUN make install DESTDIR=/qemu-upstream
# Xen historically refers to qemu-system-i386 even on x86_64 hosts; symlink it.
RUN cd /qemu-upstream/usr/bin && \
    [ -e qemu-system-i386 ] || ln -s qemu-system-x86_64 qemu-system-i386 && \
    ls -la qemu-system-*

# When changing this version, also update SEABIOS_UPSTREAM_REVISION to whatever is in `Config.mk` in the xen source
ENV XEN_VERSION=4.19.0
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz
# EXTRA_QEMUU_CONFIGURE_ARGS used to be forwarded by Xen to qemu-xen's
# configure.  With --with-system-qemu= we provide our own pre-built upstream
# qemu (above) and Xen no longer builds qemu, so this is unused.
# ENV EXTRA_QEMUU_CONFIGURE_ARGS="..."

WORKDIR /

# Download and verify xen
#TODO: verify Xen
# hadolint ignore=DL3020
ADD ${XEN_SOURCE} /xen.tar.gz
RUN [ -f "$(basename ${XEN_SOURCE})" ] || tar --absolute-names -xz < /xen.tar.gz && mv "/xen-${XEN_VERSION}" /xen

# Apply local patches
COPY patches-${XEN_VERSION} /patches
WORKDIR /xen
RUN cat /patches/*.patch /patches/"$(uname -m)"/*.patch | patch -p1

# we will need this to build xen; without it, it will try and download directly
# Note that Xen's `configure` command uses this env variable SEABIOS_UPSTREAM_URL to find the seabios source.
ENV SEABIOS_UPSTREAM_URL /seabios.git
# this revision should be kept in sync with the XEN_VERSION by reading `Config.mk` in the xen source
ENV SEABIOS_UPSTREAM_REVISION rel-1.16.3
ADD --keep-git-dir git://xenbits.xen.org/seabios.git#${SEABIOS_UPSTREAM_REVISION} ${SEABIOS_UPSTREAM_URL}
# we need this because it will complain about ambiguous refs
RUN git config --global core.warnambiguousrefs false

RUN mkdir -p /out

# FEATURES="--enable-stubdom --enable-vtpm-stubdom --enable-vtpmmgr-stubdom"
COPY gmp.patch /xen/stubdom

WORKDIR /xen

# disable golang as it does not play well together with musl (stderr is defined as FILE* const and fails to compile)
RUN ./configure --prefix=/usr --disable-xen --disable-golang --disable-qemu-traditional --disable-docs --enable-9pfs \
    --with-system-ovmf=/usr/lib/xen/boot/ovmf.bin --disable-stubdom --disable-openbios \
    --with-system-qemu=/usr/lib/xen/bin/qemu-system-i386
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && make dist
RUN dist/install.sh /out

# Stage the upstream qemu binary into the Xen install layout where
# --with-system-qemu= told Xen to look for it.  This puts qemu-system-i386
# / qemu-system-x86_64 next to xenstored / xenconsoled so the runtime
# image gets a single coherent /usr/lib/xen/bin tree.
RUN mkdir -p /out/usr/lib/xen/bin /out/usr/share/qemu && \
    cp -a /qemu-upstream/usr/bin/qemu-system-x86_64 /out/usr/lib/xen/bin/ && \
    ln -sf qemu-system-x86_64 /out/usr/lib/xen/bin/qemu-system-i386 && \
    if [ -d /qemu-upstream/usr/share/qemu ]; then \
        cp -a /qemu-upstream/usr/share/qemu/. /out/usr/share/qemu/ ; \
    fi

# Filter out a few things that we don't currently need
RUN rm -rf /out/usr/share/qemu-xen/qemu/edk2-* /out/var/run /usr/include /usr/lib/*.a
# FIXME: this is a workaround for Xen on ARM still requiring qemu-system-i386
#   https://wiki.xenproject.org/wiki/Xen_ARM_with_Virtualization_Extensions#Use_of_qemu-system-i386_on_ARM
WORKDIR /out/usr/lib/xen/bin/
RUN strip * || :
RUN if [ "$(uname -m)" = "x86_64" ]; then rm -f qemu-system-i386 && ln -s "qemu-system-$(uname -m)" qemu-system-i386 ;fi

COPY --from=uefi-build / /uefi/
RUN mkdir -p /out/usr/lib/xen/boot && cp /uefi/OVMF.fd /out/usr/lib/xen/boot/ovmf.bin && \
    cp /uefi/OVMF_PVH.fd /out/usr/lib/xen/boot/ovmf-pvh.bin && \
    [ -f /uefi/OVMF_CODE.fd ] && cp /uefi/OVMF_CODE.fd /out/usr/lib/xen/boot/OVMF_CODE.fd || : && \
    [ -f /uefi/igd.rom ] && cp /uefi/igd.rom /out/usr/lib/xen/boot/igd.rom || :

# We need to keep a slim profile, which means removing things we don't need.
# Some of the historical paths under /usr/share/qemu-xen/qemu/ no longer
# exist with --with-system-qemu= (Xen builds nothing under tools/qemu-xen/),
# so rm uses -f.  Equivalent files from upstream qemu live in
# /out/usr/share/qemu/ — drop them too.
RUN rm -rf /out/usr/lib/libxen*.a /out/usr/lib/libxl*.a /out/usr/lib/debug /out/usr/lib/python*
RUN rm -rf /out/usr/share/man
RUN rm -rf /out/usr/share/qemu-xen /out/usr/lib/xen/bin/qemu-storage-daemon
RUN rm -f /out/usr/share/qemu/openbios-* \
          /out/usr/share/qemu/skiboot.lid \
          /out/usr/share/qemu/hppa-firmware.img \
          /out/usr/share/qemu/s390-netboot.img \
          /out/usr/share/qemu/opensbi-riscv32-generic-fw_dynamic.bin \
          /out/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin \
          /out/usr/share/qemu/slof.bin

FROM scratch
COPY --from=build /out/ /
COPY --from=runx-build /runx-initrd /usr/lib/xen/boot/runx-initrd
COPY init.sh /
COPY qemu-ifup xen-start /etc/xen/scripts/

# Adjust /var/run, /var/lib and /var/lock to be shared
RUN mv /var /var.template && ln -s /run /var && ln -s /run /var.template/run

# Add a few mountpoints so we can use lowerfs in R/O mode
RUN mkdir /persist /hostfs

ENTRYPOINT []
CMD ["/init.sh"]
