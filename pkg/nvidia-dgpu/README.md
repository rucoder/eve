# NVIDIA x86 dGPU Userland Package

## Introduction

This package stages the NVIDIA x86 discrete-GPU (dGPU) **userland** -
`libnvidia-compute`, `libnvidia-cfg1`, `nvidia-utils`, `nvidia-compute-utils`,
`libnvidia-common`, and the `nvidia-container-toolkit` / `libnvidia-container1`
CDI pieces - into `/opt/vendor/nvidia` in EVE's rootfs. It is amd64 only.

## Why the kernel module and firmware live elsewhere

This package intentionally does **not** ship the NVIDIA kernel driver module
or the GSP firmware. The eve-kernel build has `CONFIG_MODULE_SIG_FORCE` set,
which means any kernel module has to be signed by the key that only exists
inside the kernel build itself - a module built or signed anywhere else will
be rejected at `insmod` time. So:

* The NVIDIA open GPU kernel module is built and signed as part of the
  **eve-kernel** image (see `eve-kernel/Makefile.eve`).
* The GSP firmware is shipped by **`pkg/fw`**.
* This package (`pkg/nvidia-dgpu`) ships only the matching **userland**.

## The three pieces must be the exact same version

NVIDIA pins the kernel module, the userland, and the GSP firmware to each
other by exact version equality - mixing versions across these three is not
supported and will generally fail to load or misbehave. Concretely, that
means `NVIDIA_DRIVER_VERSION` (and `NVIDIA_DRIVER_BRANCH`) in this package's
`Dockerfile` **must match** the `NVIDIA_DRIVER_VERSION` / `NVIDIA_DRIVER_BRANCH`
used in `eve-kernel`'s `Makefile.eve`. When bumping one, bump the other in
the same change.

## Compute-only, headless

This build deliberately excludes the display/OpenGL stack:

* No `libnvidia-gl-*` (the ~519MB OpenGL/display library set).
* No `libnvidia-decode-*` (NVDEC video decode; pulls X11 libs we don't want
  in an otherwise headless image).
* No `xserver-xorg-video-nvidia-*`, `nvidia-settings`, or `nvidia-xconfig`.

Only `nvidia` and `nvidia_uvm` kernel modules are loaded by
`init.d/nv-init.sh`; `nvidia_modeset` and `nvidia_drm` (the display/KMS
modules) are never loaded.

## Layout

* `/opt/vendor/nvidia/dist/` - the extracted `usr/` and `etc/` trees from the
  downloaded `.deb` packages, with their original paths preserved.
* `/opt/vendor/nvidia/bin/` - stable entry points (symlinks into `dist/`) for
  `nvidia-ctk`, `nvidia-cdi-hook`, `nvidia-container-runtime`,
  `nvidia-container-runtime-hook`, `nvidia-smi`, `nvidia-persistenced`, and
  `nvidia-modprobe`.
* `/opt/vendor/nvidia/init.d/nv-init.sh` - run by pillar at init; loads the
  compute kernel modules, ensures `/dev/nvidia0` exists, and generates (once)
  the CDI spec at `/run/cdi/nvidia.yaml`.

## SBOM

SBOM registration is intentionally omitted from this package. EVE's SBOM
tooling (`register-sbom-pkg.sh`) understands the apk package DB, not dpkg's -
giving these Ubuntu-sourced `.deb` packages SBOM coverage is a tracked
follow-up, not something this package does today.

## References

* [Container Device Interface](https://github.com/cncf-tags/container-device-interface)
* [NVIDIA Container Toolkit](https://github.com/NVIDIA/nvidia-container-toolkit)
* `eve-kernel/Makefile.eve` - the kernel-side half of the version pin.
* `pkg/fw/Dockerfile` - GSP/other firmware packaging.
* `pkg/nvidia/` - the Jetson (arm64) counterpart of this package.
