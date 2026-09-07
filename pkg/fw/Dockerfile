# syntax=docker/dockerfile-upstream:1.7.0-labs
ARG PLATFORM=generic
# Firmware source selector: "upstream" (Alpine + kernel.org tarball, the default for
# kvm/xen/mini/nvidia) or "ubuntu" (the full Ubuntu linux-firmware set, used by HV=k).
ARG FW_SOURCE=upstream

ARG ALPINE_HASH="956e170f3908aa5148b0ddb130e60fd862c7988b"
FROM lfedge/eve-alpine:${ALPINE_HASH} AS build-base

ARG TARGETARCH

ENV BUILD_PKGS="tar make binutils zstd rdfind coreutils"
RUN eve-alpine-deploy.sh

ENV WIRELESS_REGDB_VERSION=2024.01.23
ENV WIRELESS_REGDB_REPO=https://mirrors.edge.kernel.org/pub/software/network/wireless-regdb/wireless-regdb
ADD ${WIRELESS_REGDB_REPO}-${WIRELESS_REGDB_VERSION}.tar.gz /wireless-regdb.tar.gz
RUN mkdir /wireless-regdb &&\
    tar -xz --strip-components=1 -C /wireless-regdb -f /wireless-regdb.tar.gz &&\
    cp /wireless-regdb/regulatory.db /wireless-regdb/regulatory.db.p7s /lib/firmware

# Nvidia Firmwares for Jetpack 5.1.3, Jetpack 6.0, and Jetpack 7.1
ENV JETPACK5_DEB=nvidia-l4t-firmware_35.5.0-20240219203809_arm64.deb
ENV JETPACK5_URL=https://repo.download.nvidia.com/jetson/t194/pool/main/n/nvidia-l4t-firmware/${JETPACK5_DEB}
ENV JETPACK6_DEB=nvidia-l4t-firmware_36.3.0-20240506102626_arm64.deb
ENV JETPACK6_URL=https://repo.download.nvidia.com/jetson/t234/pool/main/n/nvidia-l4t-firmware/${JETPACK6_DEB}
ENV JETPACK7_DEB=nvidia-l4t-firmware-openrm_38.4.0-20251230160601_arm64.deb
ENV JETPACK7_URL=https://repo.download.nvidia.com/jetson/som/pool/main/n/nvidia-l4t-firmware-openrm/${JETPACK7_DEB}

FROM build-base AS generic
ENV NVIDIA_FW_TEGRA=${JETPACK5_DEB}
ENV NVIDIA_FW_URL=${JETPACK5_URL}

FROM build-base AS nvidia-jp5
ENV NVIDIA_FW_TEGRA=${JETPACK5_DEB}
ENV NVIDIA_FW_URL=${JETPACK5_URL}

FROM build-base AS nvidia-jp6
ENV NVIDIA_FW_TEGRA=${JETPACK6_DEB}
ENV NVIDIA_FW_URL=${JETPACK6_URL}

FROM build-base AS nvidia-jp7
ENV NVIDIA_FW_TEGRA=${JETPACK7_DEB}
ENV NVIDIA_FW_URL=${JETPACK7_URL}

FROM ${PLATFORM} AS build

ADD ${NVIDIA_FW_URL} /${NVIDIA_FW_TEGRA}
RUN mkdir -p /nvidia-firmware && \
    if [ "${TARGETARCH}" = "arm64" ]; then \
        cd /nvidia-firmware ;\
        ar x ../"${NVIDIA_FW_TEGRA}" ;\
        zstd -d < data.tar.zst > data.tar ;\
        tar -xvf data.tar -C ./ ;\
        rm data.tar.zst data.tar ;\
    else \
        mkdir -p /nvidia-firmware/lib/firmware/ ;\
    fi

# RTL8822ce firmware
ENV RTL8822_FW_VERSION=ca9f4e199efbf8c377e8a1769ba5b05b23f92c82
ADD https://github.com/lwfinger/rtw88.git#${RTL8822_FW_VERSION} /rtw88

ENV LINUX_FIRMWARE_VERSION=20240811
ENV LINUX_FIRMWARE_URL=https://cdn.kernel.org/pub/linux/kernel/firmware/linux-firmware
ADD ${LINUX_FIRMWARE_URL}-${LINUX_FIRMWARE_VERSION}.tar.gz /linux-firmware.tar.gz
RUN mkdir /linux-firmware &&\
    tar -xz --strip-components=1 -C /linux-firmware -f /linux-firmware.tar.gz &&\
    make -C /linux-firmware FIRMWAREDIR="/lib/firmware" install

# add compat links for pre-5.0 kernel
RUN ln -s brcmfmac43455-sdio.raspberrypi,3-model-b-plus.txt /lib/firmware/brcm/brcmfmac43455-sdio.txt &&\
    ln -s brcmfmac43430-sdio.raspberrypi,3-model-b.txt /lib/firmware/brcm/brcmfmac43430-sdio.txt
# symlinks for Visionfive1 riscv64 boards
RUN ln -s ../cypress/cyfmac43430-sdio.bin /lib/firmware/brcm/brcmfmac43430-sdio.starfive,visionfive-v1.bin
# symlinks for Kontron wifi device (brcmfmac4356)
RUN ln -s brcmfmac4356-pcie.gpd-win-pocket.txt '/lib/firmware/brcm/brcmfmac4356-pcie.Kontron America-Agora Gateway 403.txt'
RUN ln -s brcmfmac4356-pcie.bin '/lib/firmware/brcm/brcmfmac4356-pcie.Kontron America-.bin'
RUN ln -s brcmfmac4356-pcie.gpd-win-pocket.txt /lib/firmware/brcm/brcmfmac4356-pcie.txt

ENV RPI_FIRMWARE_VERSION=2c8f665254899a52260788dd902083bb57a99738
ENV RPI_FIRMWARE_URL=https://github.com/RPi-Distro/firmware-nonfree/archive
ADD ${RPI_FIRMWARE_URL}/${RPI_FIRMWARE_VERSION}.tar.gz /rpifirmware.tar.gz
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
    mkdir /rpi-firmware &&\
    tar -xz --strip-components=1 -C /rpi-firmware -f /rpifirmware.tar.gz &&\
    cp -a /rpi-firmware/debian/config/brcm80211/brcm/brcmfmac43436* /lib/firmware/brcm ;\
    fi

ENV RPI_BT_FIRMWARE_VERSION=e7fd166981ab4bb9a36c2d1500205a078a35714d
ENV RPI_BT_FIRMWARE_URL=https://github.com/RPi-Distro/bluez-firmware/raw

WORKDIR /lib/firmware/brcm
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM43430A1.hcd .
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM4345C0.hcd .
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM43430B0.hcd .
ADD ${RPI_BT_FIRMWARE_URL}/${RPI_BT_FIRMWARE_VERSION}/broadcom/BCM4345C5.hcd .

# Hailo 8 GPU firmware
ENV HAILO_FW_VERSION=4.21.0
ADD https://hailo-hailort.s3.eu-west-2.amazonaws.com/Hailo8/${HAILO_FW_VERSION}/FW/hailo8_fw.${HAILO_FW_VERSION}.bin /lib/firmware/hailo/hailo8_fw.bin

# Register firmware packages in the APK DB, mandatory for them to be included in the SBOM.
RUN register-sbom-pkg.sh -n wireless-regdb -v "${WIRELESS_REGDB_VERSION}" -l ISC -u https://wireless.wiki.kernel.org/en/developers/regulatory/wireless-regdb -o /sbom-out
RUN register-sbom-pkg.sh -n linux-firmware -v "${LINUX_FIRMWARE_VERSION}" -l GPL-2.0-only -u https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git -o /sbom-out
RUN register-sbom-pkg.sh -n rtw88-firmware -v "${RTL8822_FW_VERSION:0:8}" -l GPL-2.0-only -u https://github.com/lwfinger/rtw88 -o /sbom-out
RUN register-sbom-pkg.sh -n hailo8-firmware -v "${HAILO_FW_VERSION}" -l proprietary -u https://hailo.ai -o /sbom-out
RUN register-sbom-pkg.sh -n nvidia-l4t-firmware -v "${NVIDIA_FW_TEGRA}" -l proprietary -u https://repo.download.nvidia.com/jetson -o /sbom-out
RUN if [ "${TARGETARCH}" = "arm64" ]; then \
        register-sbom-pkg.sh -n rpi-firmware-nonfree -v "${RPI_FIRMWARE_VERSION:0:8}" -l proprietary -u https://github.com/RPi-Distro/firmware-nonfree -o /sbom-out && \
        register-sbom-pkg.sh -n rpi-bluez-firmware -v "${RPI_BT_FIRMWARE_VERSION:0:8}" -l proprietary -u https://github.com/RPi-Distro/bluez-firmware -o /sbom-out; \
    fi

# generate initrd for Intel's and AMD's microcode
# it makes sense only for x86_64 platform
FROM --platform=${TARGETPLATFORM} lfedge/eve-alpine:${ALPINE_HASH} AS ucode-build-common
RUN mkdir -p /boot /tmp/ucode/intel /tmp/ucode/amd /usr/share/licenses/ucode
# Ensure /sbom-out/lib/apk/db/installed exists for all archs so the COPY in
# compactor-common works even when no ucode registrations run (arm64/riscv64).
RUN register-sbom-pkg.sh -o /sbom-out

FROM ucode-build-common AS ucode-build-amd64
ENV BUILD_PKGS=iucode-tool
RUN eve-alpine-deploy.sh

# build intel microcode
ENV INTEL_UCODE_VERSION=20240813
ADD "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files/archive/microcode-$INTEL_UCODE_VERSION.tar.gz" /tmp/ucode/intel
WORKDIR /tmp/ucode/intel
RUN tar -xf "microcode-$INTEL_UCODE_VERSION.tar.gz" --strip=1
RUN find ./intel-ucode/ -maxdepth 1 -type f -print0 \
    | xargs -0 -r -x iucode_tool -l --write-earlyfw=intel-ucode.img --overwrite

# copy license files to /usr/share/licenses
RUN cp license /usr/share/licenses/ucode/intel-license.txt

#build AMD microcode. We use a separate Linux firmware image for that
ENV AMD_UCODE_VERSION=20240811
ENV LINUX_FIRMWARE_URL=https://cdn.kernel.org/pub/linux/kernel/firmware/linux-firmware
ADD ${LINUX_FIRMWARE_URL}-${AMD_UCODE_VERSION}.tar.gz /linux-firmware-ucode.tar.gz
RUN mkdir /tmp/ucode/amd/linux-firmware \
    && tar -xz --strip-components=1 -C /tmp/ucode/amd/linux-firmware -f /linux-firmware-ucode.tar.gz

RUN mkdir -p /tmp/ucode/amd/kernel/x86/microcode
RUN cat /tmp/ucode/amd/linux-firmware/amd-ucode/* >/tmp/ucode/amd/kernel/x86/microcode/AuthenticAMD.bin
WORKDIR /tmp/ucode/amd
RUN echo kernel/x86/microcode/AuthenticAMD.bin \
    | cpio -o -H newc -R 0:0 >./amd-ucode.img

# copy license files to /usr/share/licenses
RUN cp /tmp/ucode/amd/linux-firmware/LICENSE.amd-ucode /usr/share/licenses/ucode/amd-license.txt

# merge intel and amd microcode
RUN cat /tmp/ucode/intel/intel-ucode.img /tmp/ucode/amd/amd-ucode.img >/boot/ucode.img

# Register intel-ucode and amd-ucode in the APK DB, mandatory for them to be included in the SBOM.
RUN register-sbom-pkg.sh -n intel-ucode -v "${INTEL_UCODE_VERSION}" -l proprietary -u https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files -o /sbom-out
RUN register-sbom-pkg.sh -n amd-ucode -v "${AMD_UCODE_VERSION}" -l proprietary -u https://www.amd.com -o /sbom-out

FROM ucode-build-common AS ucode-build-arm64
FROM ucode-build-common AS ucode-build-riscv64
FROM ucode-build-${TARGETARCH} AS ucode-build

FROM lfedge/eve-alpine:${ALPINE_HASH} AS compactor-common
ENTRYPOINT []
WORKDIR /
# Reset the APK DB so the final image only reports source-built/firmware packages
RUN rm -f /lib/apk/db/installed && register-sbom-pkg.sh -o /
COPY --from=build /sbom-out/lib/apk/db/installed /tmp/sbom-fw
COPY --from=ucode-build /sbom-out/lib/apk/db/installed /tmp/sbom-ucode
RUN cat /tmp/sbom-fw /tmp/sbom-ucode >> /lib/apk/db/installed && rm -f /tmp/sbom-fw /tmp/sbom-ucode
COPY --from=build /lib/firmware/regulatory* /lib/firmware/
COPY --from=build /lib/firmware/bnx2x/* /lib/firmware/bnx2x/
COPY --from=build /lib/firmware/mrvl/*.bin /lib/firmware/mrvl/
COPY --from=build /lib/firmware/rt2870.bin /lib/firmware/rt2870.bin
COPY --from=build /lib/firmware/rtlwifi/*.bin /lib/firmware/rtlwifi/
COPY --from=build /lib/firmware/iwlwifi-3168* /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-8265* /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-7260* /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-9260* /lib/firmware/
# AX210 160MHZ
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0-72.ucode /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0-89.ucode /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0.pnvm /lib/firmware/
COPY --from=build /lib/firmware/intel/ibt-0041-0041* /lib/firmware/intel/
# Intel AX211NGW
COPY --from=build /lib/firmware/iwlwifi-so-a0-gf-a0* /lib/firmware/
COPY --from=build /lib/firmware/intel/ibt-0040-0041* /lib/firmware/intel/
# Intel Wi-Fi 6E AX1690i/AX211 (gf4 variant) on Intel-NUC12SNKi7
COPY --from=build /lib/firmware/iwlwifi-so-a0-gf4-a0-89.ucode /lib/firmware/
COPY --from=build /lib/firmware/iwlwifi-so-a0-gf4-a0.pnvm /lib/firmware/
# Intel AX201NGW
COPY --from=build /lib/firmware/iwlwifi-so-a0-hr-b0* /lib/firmware/
# Intel Wi-Fi 6E AX211 160MHz on ASUS-NUC14SRK (Meteor Lake PCH CNVi)
COPY --from=build /lib/firmware/iwlwifi-ma-b0-gf4-a0* /lib/firmware/
# Dell Edge Gateway 300x firmware
COPY --from=build /lib/firmware/rsi* /lib/firmware/rsi/
# Intel Corporation Cannon Point-LP CNVi [Wireless-AC] (rev 30)
COPY --from=build /lib/firmware/iwlwifi-9000-* /lib/firmware/
# Intel Wireless 22000 series (AX200 on NUC9VXQNX)
COPY --from=build /lib/firmware/iwlwifi-cc-a0* /lib/firmware/
# Intel Wireless 22000 series (AX201 on NUC10i7FNH)
COPY --from=build /lib/firmware/iwlwifi-QuZ-a0-hr-b0* /lib/firmware/
# RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
COPY --from=build /lib/firmware/rtl_nic/* /lib/firmware/rtl_nic/
# Firmware for Raspberry Pi4 and Broadcom wifi
COPY --from=build /lib/firmware/brcm /lib/firmware/brcm
COPY --from=build /lib/firmware/cypress /lib/firmware/cypress
# ath10k firmware
COPY --from=build /lib/firmware/ath10k /lib/firmware/ath10k
# firmware for HiKey
COPY --from=build /lib/firmware/ti-connectivity /lib/firmware/ti-connectivity
# to keep compatibility with the current layout
RUN cp --symbolic-link /lib/firmware/brcm/* /lib/firmware
# Nvidia Jetson related firmwares
COPY --from=build /nvidia-firmware/lib/firmware/ /lib/firmware/
COPY --from=build /lib/firmware/nvidia/tegra210 /lib/firmware/nvidia/tegra210
COPY --from=build /rtw88/*.bin /lib/firmware/rtw88/
# Intel ICE firmware.
COPY --from=build /lib/firmware/intel/ice /lib/firmware/intel/ice
COPY --from=build /lib/firmware/hailo /lib/firmware/hailo

ARG TARGETARCH

# Remove unnecessary firmware based on TARGETARCH and print freed space
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    initial_size=$(du -sm /lib/firmware | cut -f1); \
    rm -rf /lib/firmware/nvidia \
           /lib/firmware/ti-connectivity \
           /lib/broadcom \
           /lib/firmware/*t234* \
           /lib/firmware/*t194* \
           /lib/firmware/nvpva* ; \
    final_size=$(du -sm /lib/firmware | cut -f1); \
    freed_space=$((initial_size - final_size)); \
    echo "Freed space: ${freed_space} MB"; \
    fi

RUN if [ "$TARGETARCH" = "arm64" ]; then \
    initial_size=$(du -s /lib/firmware | cut -f1); \
    rm -rf /lib/firmware/ice; \
    final_size=$(du -s /lib/firmware | cut -f1); \
    freed_space=$((initial_size - final_size)); \
    echo "Freed space: ${freed_space} KB"; \
    fi


FROM lfedge/eve-alpine:${ALPINE_HASH} AS compactor-full
# Reset the APK DB so the final image only reports source-built/firmware packages
RUN rm -f /lib/apk/db/installed && register-sbom-pkg.sh -o /
COPY --from=build /sbom-out/lib/apk/db/installed /tmp/sbom-fw
COPY --from=ucode-build /sbom-out/lib/apk/db/installed /tmp/sbom-ucode
RUN cat /tmp/sbom-fw /tmp/sbom-ucode >> /lib/apk/db/installed && rm -f /tmp/sbom-fw /tmp/sbom-ucode
# get all possible FW
COPY --from=build /lib/firmware/ /lib/firmware/

FROM compactor-common AS compactor-generic
FROM compactor-common AS compactor-nvidia-jp5
FROM compactor-common AS compactor-nvidia-jp6
FROM compactor-common AS compactor-nvidia-jp7

FROM compactor-${PLATFORM} AS compactor

# =============================================================================
# Ubuntu firmware variant (FW_SOURCE=ubuntu) — used by HV=k builds.
# Ships the FULL Ubuntu linux-firmware set (no per-device filtering), plus
# firmware that is not part of Ubuntu's linux-firmware package: wireless-regdb
# (regulatory.db — a separate Ubuntu package) and the Hailo-8 accelerator blob
# (third-party, not in any Ubuntu package). The Ubuntu .deb packages are
# unpacked with "dpkg -x", so this variant stays Alpine-based like every other
# EVE package.
# =============================================================================
FROM lfedge/eve-alpine:${ALPINE_HASH} AS alpine
# eve-alpine with dpkg, so the Ubuntu .debs below can be unpacked with "dpkg -x".
# dpkg-deb decompresses the payloads by execing zstd: they are data.tar.zst.
# perl runs deb-licenses.pl to extract the packages' licenses for the SBOM.
ENV BUILD_PKGS="dpkg tar zstd perl"
RUN eve-alpine-deploy.sh

# Ubuntu 24.04 (noble) wireless-regdb version, as currently published in
# noble-updates. linux-firmware and firmware-sof-signed are pinned by the full
# .deb URLs in the per-arch stages below.
ENV UBUNTU_WIRELESS_REGDB_VERSION=2026.02.04-0ubuntu1~24.04.1

# amd64 .debs come from archive.ubuntu.com, every other architecture from ports.
FROM alpine AS alpine-base-amd64
ENV UBUNTU_POOL=archive.ubuntu.com/ubuntu/pool/main
ADD http://archive.ubuntu.com/ubuntu/pool/main/f/firmware-sof/firmware-sof-signed_2023.12.1-1ubuntu1.11_all.deb /debs/
ADD http://archive.ubuntu.com/ubuntu/pool/main/l/linux-firmware/linux-firmware_20240318.git3b128b60-0ubuntu2.29_amd64.deb /debs/

FROM alpine AS alpine-base-arm64
ENV UBUNTU_POOL=ports.ubuntu.com/ubuntu-ports/pool/main
ADD http://ports.ubuntu.com/ubuntu-ports/pool/main/f/firmware-sof/firmware-sof-signed_2023.12.1-1ubuntu1.11_all.deb /debs/
ADD http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-firmware/linux-firmware_20240318.git3b128b60-0ubuntu2.29_arm64.deb /debs/

FROM alpine AS alpine-base-riscv64
ENV UBUNTU_POOL=ports.ubuntu.com/ubuntu-ports/pool/main
ADD http://ports.ubuntu.com/ubuntu-ports/pool/main/f/firmware-sof/firmware-sof-signed_2023.12.1-1ubuntu1.11_all.deb /debs/
ADD http://ports.ubuntu.com/ubuntu-ports/pool/main/l/linux-firmware/linux-firmware_20240318.git3b128b60-0ubuntu2.29_riscv64.deb /debs/

FROM alpine-base-${TARGETARCH} AS fwsrc-ubuntu
ARG TARGETARCH

ADD https://${UBUNTU_POOL}/w/wireless-regdb/wireless-regdb_${UBUNTU_WIRELESS_REGDB_VERSION}_all.deb /debs/
# Depending on how far Debian's usr-merge has reached a package, its payload
# sits under /lib/firmware or under /usr/lib/firmware — on Ubuntu both are the
# same directory, here they are not, so fold the latter into the former.
# Hardlinks keep that cheap even for the 600MB+ linux-firmware payload.
RUN for deb in /debs/*.deb; do dpkg -x "$deb" /fwroot; done \
 && mkdir -p /fwroot/lib/firmware \
 && if [ -d /fwroot/usr/lib/firmware ]; then \
        cp -al /fwroot/usr/lib/firmware/. /fwroot/lib/firmware/ && \
        rm -rf /fwroot/usr/lib/firmware ; \
    fi

# Hailo-8 AI accelerator firmware — not shipped by Ubuntu, fetched directly.
ENV HAILO_FW_VERSION=4.21.0
ADD https://hailo-hailort.s3.eu-west-2.amazonaws.com/Hailo8/${HAILO_FW_VERSION}/FW/hailo8_fw.${HAILO_FW_VERSION}.bin /fwroot/lib/firmware/hailo/hailo8_fw.bin

COPY deb-licenses.pl /usr/bin/

# Register the unpacked Debian packages in the APK DB, mandatory for them to be
# included in the SBOM. Name, version, pool path and license come from the .deb
# itself, so the records cannot drift from the payload actually shipped. The
# license set comes from deb-licenses.pl: the package's DEP-5 License fields,
# or -- for a free-form copyright file like linux-firmware's -- a LicenseRef
# saying "read /usr/share/doc/<package>/copyright".
RUN for deb in /debs/*.deb; do \
        name="$(dpkg -f "$deb" Package)"; \
        version="$(dpkg -f "$deb" Version)"; \
        src="$(dpkg -f "$deb" Source)"; src="${src%% *}"; src="${src:-$name}"; \
        license="$(deb-licenses.pl "/fwroot/usr/share/doc/${name}")"; \
        echo "$name -> $license"; \
        register-sbom-pkg.sh -n "$name" -v "$version" -l "$license" \
            -u "https://${UBUNTU_POOL}/$(echo "$src" | cut -c1)/${src}" \
            -d "$name (Ubuntu 24.04 package)" -o /sbom-out || exit 1; \
    done
RUN register-sbom-pkg.sh -n hailo8-firmware -v "${HAILO_FW_VERSION}" -l proprietary -u https://hailo.ai -o /sbom-out

# --- Ubuntu microcode (x86_64 only) -----------------------------------------
FROM lfedge/eve-alpine:${ALPINE_HASH} AS ucode-ubuntu-common
RUN mkdir -p /boot /usr/share/licenses/ucode
# Ensure /sbom-out/lib/apk/db/installed exists for all archs so the COPY in
# compactor-ubuntu works even when no ucode registrations run (arm64/riscv64).
RUN register-sbom-pkg.sh -o /sbom-out

FROM ucode-ubuntu-common AS ucode-ubuntu-amd64
ENV BUILD_PKGS="dpkg tar zstd iucode-tool"
RUN eve-alpine-deploy.sh

ENV UBUNTU_POOL=archive.ubuntu.com/ubuntu/pool/main
ENV UBUNTU_INTEL_UCODE_VERSION=3.20260210.0ubuntu0.24.04.1
ENV UBUNTU_AMD_UCODE_VERSION=3.20251202.1ubuntu0.24.04.1
ADD https://${UBUNTU_POOL}/i/intel-microcode/intel-microcode_${UBUNTU_INTEL_UCODE_VERSION}_amd64.deb /debs/
ADD https://${UBUNTU_POOL}/a/amd64-microcode/amd64-microcode_${UBUNTU_AMD_UCODE_VERSION}_amd64.deb /debs/
RUN for deb in /debs/*.deb; do dpkg -x "$deb" /ucode-src; done \
 && mkdir -p /ucode-src/lib/firmware \
 && if [ -d /ucode-src/usr/lib/firmware ]; then \
        cp -al /ucode-src/usr/lib/firmware/. /ucode-src/lib/firmware/ && \
        rm -rf /ucode-src/usr/lib/firmware ; \
    fi

RUN mkdir -p /tmp/ucode/amd/kernel/x86/microcode \
 && iucode_tool -l --write-earlyfw=/tmp/ucode/intel-ucode.img --overwrite \
        /ucode-src/lib/firmware/intel-ucode/ \
 && cat /ucode-src/lib/firmware/amd-ucode/microcode_amd*.bin \
        > /tmp/ucode/amd/kernel/x86/microcode/AuthenticAMD.bin \
 && ( cd /tmp/ucode/amd && echo kernel/x86/microcode/AuthenticAMD.bin \
        | cpio -o -H newc -R 0:0 > /tmp/ucode/amd/amd-ucode.img ) \
 && cat /tmp/ucode/intel-ucode.img /tmp/ucode/amd/amd-ucode.img > /boot/ucode.img \
 && cp /ucode-src/usr/share/doc/intel-microcode/copyright /usr/share/licenses/ucode/intel-license.txt \
 && cp /ucode-src/usr/share/doc/amd64-microcode/copyright /usr/share/licenses/ucode/amd-license.txt

RUN register-sbom-pkg.sh -n intel-microcode -v "${UBUNTU_INTEL_UCODE_VERSION}" -l proprietary -u "https://${UBUNTU_POOL}/i/intel-microcode" -d "intel-microcode (Ubuntu 24.04 package)" -o /sbom-out
RUN register-sbom-pkg.sh -n amd64-microcode -v "${UBUNTU_AMD_UCODE_VERSION}" -l proprietary -u "https://${UBUNTU_POOL}/a/amd64-microcode" -d "amd64-microcode (Ubuntu 24.04 package)" -o /sbom-out

# No microcode on non-x86 — the empty /boot and license dir inherited from
# ucode-ubuntu-common keep the COPYs in out-ubuntu working.
FROM ucode-ubuntu-common AS ucode-ubuntu-arm64
FROM ucode-ubuntu-common AS ucode-ubuntu-riscv64

FROM ucode-ubuntu-${TARGETARCH} AS ucode-ubuntu

FROM lfedge/eve-alpine:${ALPINE_HASH} AS compactor-ubuntu
# Reset the APK DB so the final image only reports the firmware packages it ships
RUN rm -f /lib/apk/db/installed && register-sbom-pkg.sh -o /
COPY --from=fwsrc-ubuntu /sbom-out/lib/apk/db/installed /tmp/sbom-fw
COPY --from=ucode-ubuntu /sbom-out/lib/apk/db/installed /tmp/sbom-ucode
RUN cat /tmp/sbom-fw /tmp/sbom-ucode >> /lib/apk/db/installed && rm -f /tmp/sbom-fw /tmp/sbom-ucode

# Existing (upstream) assembly — unchanged content, now a named stage.
FROM scratch AS out-upstream
ENTRYPOINT []
WORKDIR /
COPY --from=compactor /lib/firmware /lib/firmware
COPY --from=compactor /lib/apk/db/installed /lib/apk/db/installed
COPY --from=ucode-build /boot/ /boot/
COPY --from=ucode-build /usr/share/licenses/ucode /usr/share/licenses/ucode

# Ubuntu assembly — full firmware + Ubuntu ucode.
FROM scratch AS out-ubuntu
ENTRYPOINT []
WORKDIR /
COPY --from=fwsrc-ubuntu /fwroot/lib/firmware /lib/firmware
# The packages' authoritative license statements — the files the SBOM's
# LicenseRef-<package>-copyright records point at.
COPY --parents --from=fwsrc-ubuntu /fwroot/./usr/share/doc/*/copyright /
COPY --from=compactor-ubuntu /lib/apk/db/installed /lib/apk/db/installed
COPY --from=ucode-ubuntu /boot/ /boot/
COPY --from=ucode-ubuntu /usr/share/licenses/ucode /usr/share/licenses/ucode

# Final image = the selected assembly.
FROM out-${FW_SOURCE}
