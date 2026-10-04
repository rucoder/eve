# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023-2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-uefi:69dbd346e47296abc02b605cc54b3f6e4fba4e98 AS uefi-build
FROM lfedge/eve-qemu:3560a1cf9287e75582ab9eb29418fd0ce3341707 AS qemu
FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS runx-build
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

FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS build
# readelf and strip, for the checks below.
ENV BUILD_PKGS="binutils"
# The Alpine libraries QEMU, virglrenderer and Mesa from pkg/qemu link, plus
# the base the scripts here run on.
ENV PKGS="alpine-baselayout libgcc bash musl-utils libaio libbz2 glib pixman yajl keyutils libusb xz-libs libuuid zstd-libs util-linux-misc gnutls zlib libdrm libexpat libstdc++ libfdt"
RUN eve-alpine-deploy.sh

# QEMU for KVM, with virglrenderer and Mesa (pkg/qemu). The Alpine libraries
# it links are in PKGS; fail here, not at the first VM start, if one is
# missing.
COPY --from=qemu /usr/ /out/usr/
RUN set -e; missing=""; \
    for f in /out/usr/bin/qemu-system-* $(find /out/usr/lib -maxdepth 2 -name '*.so*' -type f); do \
        for lib in $(readelf -d "$f" | sed -n 's/.*NEEDED.*\[\(.*\)\]/\1/p'); do \
            [ -e "/out/usr/lib/$lib" ] || [ -e "/out/lib/$lib" ] || missing="$missing $f:$lib"; \
        done; \
    done; \
    [ -z "$missing" ] || { echo "ERROR: unresolved libraries:$missing"; exit 1; }

COPY --from=uefi-build / /uefi/
RUN mkdir -p /out/usr/lib/xen/boot && \
    cp /uefi/OVMF.fd /out/usr/lib/xen/boot/ovmf.bin && \
    cp /uefi/OVMF_PVH.fd /out/usr/lib/xen/boot/ovmf-pvh.bin && \
    if [ -f /uefi/OVMF_CODE.fd ]; then \
        cp /uefi/OVMF_CODE.fd /out/usr/lib/xen/boot/OVMF_CODE.fd; \
    fi && \
    if [ -f /uefi/igd.rom ]; then \
        cp /uefi/igd.rom /out/usr/lib/xen/boot/igd.rom; \
    fi

# We need to keep a slim profile, which means removing things we don't need
RUN rm -rf /out/var/run /out/usr/include /out/usr/lib/python* /out/usr/share/man
RUN find /out -type f -name '*.a' -exec rm -f {} +
# eve-alpine-deploy.sh always installs apk-tools, and with it OpenSSL; nothing
# else here links libcrypto or libssl. The apk DB stays, for the SBOM.
RUN rm -rf /out/sbin/apk /out/usr/lib/libapk.so.* /out/usr/lib/libcrypto.so.* \
           /out/usr/lib/libssl.so.* /out/usr/lib/engines-3 /out/usr/lib/ossl-modules \
           /out/usr/bin/ssl_client

FROM scratch
COPY --from=build /out/ /
COPY --from=runx-build /runx-initrd /usr/lib/xen/boot/runx-initrd
COPY init.sh /
COPY qemu-ifup /etc/xen/scripts/

# Adjust /var/run, /var/lib and /var/lock to be shared
RUN mv /var /var.template && ln -s /run /var && ln -s /run /var.template/run

# Add a few mountpoints so we can use lowerfs in R/O mode
RUN mkdir /persist /hostfs

ENTRYPOINT []
CMD ["/init.sh"]
