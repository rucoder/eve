# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
ARG PLATFORM=generic

FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as build-base

ARG TARGETARCH

ENV BUILD_PKGS="tar make binutils zstd rdfind coreutils"
RUN eve-alpine-deploy.sh

ENV WIRELESS_REGDB_VERSION=2024.01.23
ENV WIRELESS_REGDB_REPO=https://mirrors.edge.kernel.org/pub/software/network/wireless-regdb/wireless-regdb
ADD ${WIRELESS_REGDB_REPO}-${WIRELESS_REGDB_VERSION}.tar.gz /wireless-regdb.tar.gz
RUN mkdir /wireless-regdb &&\
    tar -xz --strip-components=1 -C /wireless-regdb -f /wireless-regdb.tar.gz &&\
    cp /wireless-regdb/regulatory.db /wireless-regdb/regulatory.db.p7s /lib/firmware

# Nvidia Firmwares for Jetpack 5.1.3 and Jetpack 6.0
ENV JETPACK5_DEB=nvidia-l4t-firmware_35.5.0-20240219203809_arm64.deb
ENV JETPACK5_URL=https://repo.download.nvidia.com/jetson/t194/pool/main/n/nvidia-l4t-firmware/${JETPACK5_DEB}
ENV JETPACK6_DEB=nvidia-l4t-firmware_36.3.0-20240506102626_arm64.deb
ENV JETPACK6_URL=https://repo.download.nvidia.com/jetson/t234/pool/main/n/nvidia-l4t-firmware/${JETPACK6_DEB}

FROM build-base AS generic
ENV NVIDIA_FW_TEGRA=${JETPACK5_DEB}
ENV NVIDIA_FW_URL=${JETPACK5_URL}

FROM build-base AS evaluation
ENV NVIDIA_FW_TEGRA=${JETPACK5_DEB}
ENV NVIDIA_FW_URL=${JETPACK5_URL}

FROM build-base AS nvidia-jp5
ENV NVIDIA_FW_TEGRA=${JETPACK5_DEB}
ENV NVIDIA_FW_URL=${JETPACK5_URL}

FROM build-base AS nvidia-jp6
ENV NVIDIA_FW_TEGRA=${JETPACK6_DEB}
ENV NVIDIA_FW_URL=${JETPACK6_URL}

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

# generate initrd for Intel's and AMD's microcode
# it makes sense only for x86_64 platform
FROM --platform=${TARGETPLATFORM} lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as ucode-build-common
RUN mkdir -p /boot /tmp/ucode/intel /tmp/ucode/amd /usr/share/licenses/ucode

FROM ucode-build-common as ucode-build-amd64
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

FROM ucode-build-common as ucode-build-arm64
FROM ucode-build-common as ucode-build-riscv64
FROM ucode-build-${TARGETARCH} as ucode-build

FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as compactor-common
ENTRYPOINT []
WORKDIR /
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
COPY --from=build /lib/firmware/iwlwifi-ty-a0-gf-a0-59.ucode /lib/firmware/
COPY --from=build /lib/firmware/intel/ibt-0041-0041* /lib/firmware/intel/
# Intel AX211NGW
COPY --from=build /lib/firmware/iwlwifi-so-a0-gf-a0* /lib/firmware/
COPY --from=build /lib/firmware/intel/ibt-0040-0041* /lib/firmware/intel/
# Intel AX201NGW
COPY --from=build /lib/firmware/iwlwifi-so-a0-hr-b0* /lib/firmware/
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


FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as compactor-full
# get all possible FW
COPY --from=build /lib/firmware/ /lib/firmware/

FROM compactor-common AS compactor-generic
FROM compactor-common AS compactor-nvidia-jp5
FROM compactor-common AS compactor-nvidia-jp6
FROM compactor-full AS compactor-evaluation

FROM compactor-${PLATFORM} as compactor

FROM scratch
ENTRYPOINT []
WORKDIR /

COPY --from=compactor /lib/firmware /lib/firmware
COPY --from=ucode-build /boot/ /boot/
COPY --from=ucode-build /usr/share/licenses/ucode /usr/share/licenses/ucode
