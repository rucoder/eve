# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# This package stages the NVIDIA x86 dGPU USERLAND (driver libraries, CLI
# tools, and the nvidia-container-toolkit pieces needed for CDI) into
# /opt/vendor/nvidia in EVE's rootfs. It is amd64 only: the kernel driver
# module and GSP firmware are built into the eve-kernel image and pkg/fw
# instead (see README.md for why), and there is no NVIDIA dGPU story on
# arm64/riscv64 - those architectures ship an empty package, mirroring the
# no-op stage pattern pkg/nvidia uses for architectures it does not apply to
# (e.g. `FROM build-base AS build-amd64-generic`).


ARG NVIDIA_DRIVER_BRANCH=580
ARG NVIDIA_DRIVER_VERSION=580.173.02-0ubuntu0.24.04.1
ARG UBUNTU_POOL=http://archive.ubuntu.com/ubuntu/pool/restricted/n
ARG NVCT_VERSION=1.20.0-1
ARG NVCT_REPO=https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2404/x86_64

FROM ubuntu:24.04 AS build-base
# Always create /staging/opt so the final COPY succeeds even for the
# no-op arm64/riscv64 stages below, which never populate it further.
RUN mkdir -p /staging/opt

# Nothing to stage on these architectures - empty package.
FROM build-base AS build-arm64
FROM build-base AS build-riscv64

FROM build-base AS build-amd64
ARG NVIDIA_DRIVER_BRANCH
ARG NVIDIA_DRIVER_VERSION
ARG UBUNTU_POOL
ARG NVCT_VERSION
ARG NVCT_REPO

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl ca-certificates binutils xz-utils zstd && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /debs

# NVIDIA driver userland, sourced from Ubuntu's archive (not NVIDIA's own
# repo) so that the kernel module (built into eve-kernel), this userland,
# nvidia-smi, and the GSP firmware (pkg/fw) all land on the exact version
# NVIDIA pins them to each other. NVIDIA_DRIVER_VERSION here must match the
# value used by eve-kernel's Makefile.eve - see README.md.
ENV DRIVER_POOL=${UBUNTU_POOL}/nvidia-graphics-drivers-${NVIDIA_DRIVER_BRANCH}

RUN curl -fsSL -O "${DRIVER_POOL}/libnvidia-compute-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    curl -fsSL -O "${DRIVER_POOL}/libnvidia-cfg1-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    curl -fsSL -O "${DRIVER_POOL}/nvidia-utils-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    curl -fsSL -O "${DRIVER_POOL}/nvidia-compute-utils-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    curl -fsSL -O "${DRIVER_POOL}/libnvidia-common-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_all.deb" && \
    curl -fsSL -O "${DRIVER_POOL}/nvidia-kernel-common-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    curl -fsSL -O "${DRIVER_POOL}/libnvidia-extra-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb"

# Deliberately NOT downloaded - this is a compute-only, headless build:
#   - libnvidia-gl-*: ~519MB OpenGL/display stack, not needed off-screen.
#   - libnvidia-decode-*: pulls libx11-6/libxext6 into an otherwise
#     headless image; only needed for NVDEC video decode pipelines.
#   - xserver-xorg-video-nvidia-*, nvidia-settings, nvidia-xconfig: X11
#     display tooling, not applicable to a headless compute image.

RUN curl -fsSL -O "${NVCT_REPO}/nvidia-container-toolkit-base_${NVCT_VERSION}_amd64.deb" && \
    curl -fsSL -O "${NVCT_REPO}/libnvidia-container1_${NVCT_VERSION}_amd64.deb"

RUN mkdir -p /staging/opt/vendor/nvidia/dist && \
    for deb in *.deb; do \
        dpkg-deb -x "$deb" /staging/opt/vendor/nvidia/dist ; \
    done

# Stable entry points for the tools nv-init.sh and CDI generation need, so
# callers don't have to know the real Ubuntu multiarch path under dist/.
#
# Verified deb -> binary mapping at 580.173.02 (dpkg-deb -c on each):
#   nvidia-utils-580         nvidia-smi, nvidia-debugdump
#   nvidia-compute-utils-580 nvidia-persistenced, nvidia-cuda-mps-{control,server}
#   nvidia-kernel-common-580 /sbin/ub-device-create, lib/udev/rules.d/71-nvidia.rules
#   libnvidia-{compute,cfg1}-580  libraries only, no executables
#   nvidia-container-toolkit-base nvidia-ctk, nvidia-cdi-hook, nvidia-container-runtime*
#
# NOTE there is deliberately no nvidia-modprobe here. It is not published in
# Ubuntu's restricted pool at all (404); Ubuntu carries it only in multiverse at
# 535.54.03, a different and much older branch. Device nodes are created by
# ub-device-create instead, which is what NVIDIA's own 71-nvidia.rules invokes.
RUN mkdir -p /staging/opt/vendor/nvidia/bin && \
    for bin in nvidia-ctk nvidia-cdi-hook nvidia-container-runtime \
               nvidia-container-runtime-hook nvidia-smi nvidia-persistenced \
               ub-device-create; do \
        found=$(find /staging/opt/vendor/nvidia/dist -type f -name "$bin" | head -n1) ; \
        if [ -z "$found" ]; then \
            echo "WARNING: $bin not found in extracted debs, skipping" >&2 ; \
            continue ; \
        fi ; \
        ln -s "${found#/staging}" "/staging/opt/vendor/nvidia/bin/$bin" ; \
    done

# libnvidia-gpucomp is dlopen'd by libcuda (a plain string reference, not
# DT_NEEDED - so its absence does not fail at load time, it fails later when a
# workload needs the GPU compiler). Ubuntu ships it INSIDE libnvidia-gl-580;
# unlike NVIDIA's own repo there is no standalone libnvidia-gpucomp-580 deb here
# (404). So rather than skip the GL package wholesale, take just this one file
# from it and discard the rest - that keeps every component at one version.
#
# Cost: a 165MB download at build time for 68.9MB shipped. The 519MB of actual
# OpenGL/display libraries in that deb are still excluded.
RUN curl -fsSL -o /tmp/gl.deb \
        "${DRIVER_POOL}/libnvidia-gl-${NVIDIA_DRIVER_BRANCH}_${NVIDIA_DRIVER_VERSION}_amd64.deb" && \
    dpkg-deb --fsys-tarfile /tmp/gl.deb \
      | tar -x -C /staging/opt/vendor/nvidia/dist --wildcards './usr/lib/*/libnvidia-gpucomp.so*' && \
    rm -f /tmp/gl.deb && \
    find /staging/opt/vendor/nvidia/dist -name 'libnvidia-gpucomp.so*' -exec ls -l {} \;

# glibc ldconfig for the CDI update-ldcache hook. The hook runs ldconfig against
# the WORKLOAD container's rootfs, which is glibc; Alpine's musl ldconfig cannot
# write a glibc ld.so.cache, and pkg/glibc deliberately harvests only libc6 and
# libgcc-s1 (ldconfig lives in libc-bin). Ubuntu ships /usr/sbin/ldconfig as a
# wrapper script and ldconfig.real as the actual binary - take the binary. This
# mirrors what pkg/nvidia does for Jetson (its ldconfig-glibc), except the path is
# passed to nvidia-ctk at generation time instead of patched into the YAML after.
RUN test -f /usr/sbin/ldconfig.real || { \
        echo "ldconfig.real missing from ubuntu:24.04 - libc-bin layout changed"; exit 1; \
    } && \
    cp /usr/sbin/ldconfig.real /staging/opt/vendor/nvidia/bin/ldconfig-glibc && \
    chmod 0755 /staging/opt/vendor/nvidia/bin/ldconfig-glibc

# Ship NVIDIA's own modprobe.d config, which blacklists the in-tree drivers that
# claim the same PCI IDs: nouveau, lbm-nouveau, and nova/nova_core (the Rust
# successor - present in the 6.18 tree but not enabled in eve-hwe_defconfig yet,
# so this is future-proofing). CONFIG_DRM_NOUVEAU=m in eve-hwe means nouveau
# WOULD autoload by modalias on an NVIDIA GPU and race nvidia for the device.
#
# Scoped to this package on purpose: only ai-generic images need nouveau out of
# the way. Other images keep today's behaviour, where nouveau provides basic
# display on NVIDIA hardware.
#
# We deliberately do NOT ship the deb's nvidia-graphics-drivers-kms.conf
# ("options nvidia_drm modeset=1" plus NVreg_PreserveVideoMemoryAllocations).
# nvidia_drm and nvidia_modeset are not built in this compute-only configuration,
# so it would have nothing to act on. That file is what to add if/when we build
# those modules to get an nvidia-drm console.
RUN mkdir -p /staging/etc/modprobe.d && \
    cp /staging/opt/vendor/nvidia/dist/lib/modprobe.d/nvidia-graphics-drivers.conf \
       /staging/etc/modprobe.d/

# Stage the udev rules where nv-init.sh expects them, mirroring pkg/nvidia.
RUN mkdir -p /staging/opt/vendor/nvidia/etc/udev/rules.d && \
    cp /staging/opt/vendor/nvidia/dist/lib/udev/rules.d/71-nvidia.rules \
       /staging/opt/vendor/nvidia/etc/udev/rules.d/

COPY scripts/nv-init.sh /staging/opt/vendor/nvidia/init.d/nv-init.sh
RUN chmod 0755 /staging/opt/vendor/nvidia/init.d/nv-init.sh

# SBOM registration (register-sbom-pkg.sh, as pkg/nvidia and pkg/fw do) is
# intentionally omitted here: it registers into the apk package DB, and
# EVE's SBOM tooling only understands apk, not dpkg. Giving these
# Ubuntu-sourced .deb packages SBOM coverage is a tracked follow-up.

# NOTE: the stage name needs a literal prefix. linuxkit validates the Dockerfile
# before handing it to buildkit, stripping variables from each FROM's base name and
# rejecting what is left if it is empty - so a bare "FROM ${TARGETARCH}" fails with
# 'base name (${TARGETARCH}) should not be blank'. pkg/glibc and pkg/nvidia both use
# a prefixed form for the same reason.
FROM build-${TARGETARCH} AS build

FROM scratch
COPY --from=build /staging/opt /opt
COPY --from=build /staging/etc /etc

ENTRYPOINT []
CMD []
