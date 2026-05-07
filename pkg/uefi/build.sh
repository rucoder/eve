#!/bin/bash

TARGET=DEBUG

# Debug knob: override OVMF's PcdPlatformBootTimeOut (in seconds).
# Stock value is 0, which makes the UEFI splash / boot-menu phase
# flash by in well under 100 ms — imperceptible on monitors that take
# a moment to wake after the first EDID handshake.  Bump to e.g. 5
# when diagnosing GOP / display paths so the boot menu stays visible
# long enough to confirm which physical output is receiving UEFI
# console frames.  Revert to 0 before shipping — a non-zero value
# delays every boot by that many seconds and exposes a boot menu to
# anyone with a keyboard attached.
UEFI_BOOT_TIMEOUT=${UEFI_BOOT_TIMEOUT:-0}

make -C BaseTools -j "$(nproc)"
OVMF_COMMON_FLAGS="-DNETWORK_TLS_ENABLE"
OVMF_COMMON_FLAGS+=" -DSECURE_BOOT_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DTPM2_CONFIG_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DTPM2_ENABLE=TRUE"
OVMF_COMMON_FLAGS+=" -DFD_SIZE_4MB"

if [ "${UEFI_BOOT_TIMEOUT}" != "0" ]; then
    # Patch the DSC directly.  `build --pcd` is unreliable for
    # DynamicDefault PCDs across EDK2 versions and silently no-ops
    # when the type / syntax does not match exactly; sed-in-place is
    # crude but guaranteed.  Anchored to the exact stock-value line so
    # we no-op if someone has already changed PcdPlatformBootTimeOut
    # away from the default.
    sed -i -E "s@^([[:space:]]*gEfiMdePkgTokenSpaceGuid\.PcdPlatformBootTimeOut)\|0[[:space:]]*\$@\1|${UEFI_BOOT_TIMEOUT}@" \
        OvmfPkg/OvmfPkgX64.dsc
    echo "UEFI_BOOT_TIMEOUT=${UEFI_BOOT_TIMEOUT} applied; DSC now reads:"
    grep "PcdPlatformBootTimeOut" OvmfPkg/OvmfPkgX64.dsc
fi

# shellcheck disable=SC1091
. edksetup.sh

set -e

# shellcheck disable=SC2086
case $(uname -m) in
    riscv64) make -C /opensbi -j "$(nproc)" PLATFORM=generic
             cp /opensbi/build/platform/generic/firmware/fw_payload.elf OVMF_CODE.fd
             cp /opensbi/build/platform/generic/firmware/fw_payload.bin OVMF_VARS.fd
             cp /opensbi/build/platform/generic/firmware/fw_jump.bin OVMF.fd
             ;;
    aarch64) build -b ${TARGET} -t GCC5 -a AARCH64 -n "$(nproc)" -p ArmVirtPkg/ArmVirtQemu.dsc -D TPM2_ENABLE=TRUE -D TPM2_CONFIG_ENABLE=TRUE
             cp Build/ArmVirtQemu-AARCH64/${TARGET}_GCC5/FV/QEMU_EFI.fd OVMF.fd
             cp Build/ArmVirtQemu-AARCH64/${TARGET}_GCC5/FV/QEMU_VARS.fd OVMF_VARS.fd
             # now let's build PVH UEFI kernel
             make -C BaseTools/Source/C -j "$(nproc)"
             build -b ${TARGET} -t GCC5 -a AARCH64 -n "$(nproc)" -p ArmVirtPkg/ArmVirtXen.dsc
             cp Build/ArmVirtXen-AARCH64/${TARGET}_*/FV/XEN_EFI.fd OVMF_PVH.fd
             ;;
     x86_64) build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p OvmfPkg/OvmfPkgX64.dsc ${OVMF_COMMON_FLAGS}
             cp Build/OvmfX64/${TARGET}_*/FV/OVMF*.fd .
             build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p OvmfPkg/OvmfXen.dsc
             cp Build/OvmfXen/${TARGET}_*/FV/OVMF.fd OVMF_PVH.fd
             # Build VfioIgdPkg open-source IGD Option ROM (IgdAssignmentDxe only).
             # Handles Gen11+ 64-bit BDSM at PCI config 0xC0, unlike classic IgdAssignmentDxe.
             #
             # Two upstream-VfioIgdPkg.dsc problems we patch in place:
             #
             # 1. Default MdePkg debug PCDs filter DEBUG_INFO/DEBUG_VERBOSE at
             #    compile time even with -b DEBUG.  Add a [PcdsFixedAtBuild]
             #    block so IgdAssignment.c's "OpRegion @ ..." / "stolen memory
             #    @ ..." lines reach the debugcon (port 0x402, captured via
             #    isa-debugcon when pillar's debug.enable.efi is true).
             #
             #    PcdDebugPropertyMask = 0x0F: ASSERT + PRINT + CODE +
             #    CLEAR_MEMORY enabled, but NOT ASSERT_BREAKPOINT (BIT4) and
             #    NOT ASSERT_DEADLOOP (BIT5).  Asserts print and continue
             #    instead of halting — critical because BaseHobLibNull (see
             #    below) and other Null libs assert on every call.
             #
             # 2. Upstream binds HobLib -> MdeModulePkg/.../BaseHobLibNull,
             #    which is a stub: every function is ASSERT(FALSE) + return 0.
             #    In RELEASE this silently corrupts; in DEBUG with the assert
             #    deadloop enabled it bricks boot.  Replace with the real
             #    DxeHobLib for DXE_DRIVER context.  IgdAssignmentDxe pulls
             #    in HobLib transitively via QemuFwCfgDxeLib /
             #    UefiBootServicesTableLib, so this is load-bearing.
             if ! grep -q PcdFixedDebugPrintErrorLevel VfioIgdPkg/VfioIgdPkg.dsc; then
                 sed -i 's#^\[Components\]#[PcdsFixedAtBuild]\n  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x0F\n  gEfiMdePkgTokenSpaceGuid.PcdFixedDebugPrintErrorLevel|0x804F004F\n\n[Components]#' VfioIgdPkg/VfioIgdPkg.dsc
                 echo "VfioIgdPkg.dsc PcdsFixedAtBuild patched for DEBUG output:"
                 grep -A2 PcdsFixedAtBuild VfioIgdPkg/VfioIgdPkg.dsc
             fi
             # Apply our diagnostic patches to VfioIgdPkg (paths inside
             # patches are a/VfioIgdPkg/...).  Idempotent: re-running the
             # build skips any patch that has already been applied.
             if [ -d /vfio-igd-patches ] && ls /vfio-igd-patches/*.patch >/dev/null 2>&1 ; then
                 for patch in /vfio-igd-patches/*.patch ; do
                     if git apply --check -p1 < "$patch" 2>/dev/null ; then
                         echo "Applying $patch" ; git apply -p1 < "$patch"
                     else
                         echo "Skipping $patch (already applied or stale)"
                     fi
                 done
             fi
             if grep -q 'HobLib|MdeModulePkg/Library/BaseHobLibNull/BaseHobLibNull.inf' VfioIgdPkg/VfioIgdPkg.dsc; then
                 # DxeHobLib drags in UefiLib (for gBS-based protocol lookup)
                 # and UefiLib drags in DevicePathLib.  Add the cascade in
                 # one shot so the link resolves with no further surprises.
                 sed -i 's#^\(\s*HobLib\)|MdeModulePkg/Library/BaseHobLibNull/BaseHobLibNull.inf#\1|MdePkg/Library/DxeHobLib/DxeHobLib.inf\n  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf\n  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf#' VfioIgdPkg/VfioIgdPkg.dsc
                 echo "VfioIgdPkg.dsc HobLib swapped Null -> DxeHobLib (+ UefiLib + DevicePathLib cascade):"
                 grep -E 'HobLib|UefiLib|DevicePathLib' VfioIgdPkg/VfioIgdPkg.dsc
             fi
             build -b ${TARGET} -t GCC5 -a X64 -n "$(nproc)" -p VfioIgdPkg/VfioIgdPkg.dsc
             EfiRom -f 0x8086 -i 0xffff \
                 -e Build/VfioIgdPkg/${TARGET}_GCC5/X64/IgdAssignmentDxe.efi \
                 -o igd.rom
             ;;
          *) echo "Unsupported architecture $(uname). Bailing."
             exit 1
             ;;
esac
