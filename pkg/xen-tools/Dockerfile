# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-uefi:7e975cf524ce81922f283bf434563a08ac400a17 AS uefi-build
FROM lfedge/eve-qemu:6912406c9ccec7e76dad82459f3315b71cd114bb AS qemu
FROM lfedge/eve-alpine:1d60238fe336a7782fb173fed1be692246a27dfa AS runx-build
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

FROM lfedge/eve-alpine:1d60238fe336a7782fb173fed1be692246a27dfa AS build
ENV BUILD_PKGS="\
    gcc make libc-dev dev86 xz-dev perl bash python3-dev \
    gettext iasl util-linux-dev ncurses-dev glib-dev \
    pixman-dev libaio-dev yajl-dev argp-standalone \
    linux-headers git patch texinfo tar libcap-ng-dev \
    attr-dev flex bison cmake libusb-dev zstd-dev \
    python3 build-base ninja gnutls-dev agetty py3-setuptools"

ENV BUILD_PKGS_arm64=dtc-dev

ENV PKGS="alpine-baselayout libgcc bash musl-utils libaio libbz2 glib pixman yajl keyutils libusb xz-libs libuuid zstd-libs util-linux-misc gnutls zlib libdrm libexpat libstdc++ libcap-ng libfdt"

RUN eve-alpine-deploy.sh

# Alpine linux defines all 64bit integer types as long. Patch
# /usr/include/bits/alltypes.h to fix compilation with -m32
WORKDIR /
COPY alpine.patch /
RUN patch -p1 < alpine.patch

# When changing this version, also update SEABIOS_UPSTREAM_REVISION to whatever is in `Config.mk` in the xen source
ENV XEN_VERSION=4.21.1
ENV XEN_SOURCE=https://downloads.xenproject.org/release/xen/${XEN_VERSION}/xen-${XEN_VERSION}.tar.gz
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

# QEMU comes from pkg/qemu, built without Xen support: xl can no longer start
# a device model, so HVM guests and PV backends on the Xen flavour do not work.
# disable golang as it does not play well together with musl (stderr is defined as FILE* const and fails to compile)
RUN ./configure --prefix=/usr --disable-xen --disable-golang --disable-qemu-traditional --disable-docs --enable-9pfs \
    --with-system-qemu="/usr/bin/qemu-system-$(uname -m)" \
    --with-system-ovmf=/usr/lib/xen/boot/ovmf.bin --disable-stubdom --disable-openbios \
    --enable-vhost-vsock --enable-vhost-scsi \
    --disable-microblaze --disable-mips --disable-ppc \
    --disable-sparc --disable-tricore --disable-alpha --disable-hppa \
    --disable-storage-daemon
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && make dist
RUN dist/install.sh /out

# Register xen in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n xen -v "${XEN_VERSION}" -l GPL-2.0-only -u https://xenproject.org

# Register seabios in the APK DB, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n seabios -v "${SEABIOS_UPSTREAM_REVISION}" -l LGPL-2.1-only -u https://www.seabios.org

# Filter out a few things that we don't currently need
RUN rm -rf /out/var/run /out/usr/include
WORKDIR /out/usr/lib/xen/bin/
RUN for f in *; do strip "$f" || :; done

COPY --from=uefi-build / /uefi/
RUN mkdir -p /out/usr/lib/xen/boot && cp /uefi/OVMF.fd /out/usr/lib/xen/boot/ovmf.bin && \
    cp /uefi/OVMF_PVH.fd /out/usr/lib/xen/boot/ovmf-pvh.bin && \
    { [ -f /uefi/OVMF_CODE.fd ] && cp /uefi/OVMF_CODE.fd /out/usr/lib/xen/boot/OVMF_CODE.fd || :; } && \
    { [ -f /uefi/igd.rom ] && cp /uefi/igd.rom /out/usr/lib/xen/boot/igd.rom || :; }

# We need to keep a slim profile, which means removing things we don't need
RUN rm -rf /out/usr/lib/debug /out/usr/lib/python*
# eve-alpine-deploy.sh always installs apk-tools, and with it OpenSSL; nothing
# else here links libcrypto or libssl. The apk DB stays, for the SBOM.
RUN rm -rf /out/sbin/apk /out/usr/lib/libapk.so.* /out/usr/lib/libcrypto.so.* \
           /out/usr/lib/libssl.so.* /out/usr/lib/engines-3 /out/usr/lib/ossl-modules \
           /out/usr/bin/ssl_client
# Static libraries are build-time only; some live in subdirectories (e.g. xen/lib/libfdt.a).
RUN find /out -type f -name '*.a' -exec rm -f {} +
RUN rm -rf /out/usr/share/man

# QEMU for KVM, with virglrenderer and Mesa (pkg/qemu). The Alpine libraries it links are in PKGS; fail
# here, not at the first VM start, if one is missing.
COPY --from=qemu /usr/ /out/usr/
RUN set -e; missing=""; \
    for f in /out/usr/bin/qemu-system-* $(find /out/usr/lib -maxdepth 2 -name '*.so*' -type f); do \
        for lib in $(readelf -d "$f" | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p'); do \
            [ -e "/out/usr/lib/$lib" ] || [ -e "/out/lib/$lib" ] || missing="$missing $f:$lib"; \
        done; \
    done; \
    [ -z "$missing" ] || { echo "ERROR: unresolved libraries:$missing"; exit 1; }

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
