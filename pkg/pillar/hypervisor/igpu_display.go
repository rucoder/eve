// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Quiescing an Intel iGPU before handing it to vfio-pci.
//
// Firmware leaves the display engine scanning out of stolen memory, and EVE
// has no i915 to take over and shut it down. Once vfio-pci binds, it installs
// an empty translated DMA domain and the device's graphics RMRR is dropped
// (IOMMU_RESV_DIRECT_RELAXABLE), so every scanout fetch hits an address the
// IOMMU no longer translates. The result is a permanent DMA fault storm -
// measured at ~1.6M faults/s - on a DMAR unit shared with other devices.
//
// Disabling the planes stops the fetch. Only the planes are touched: the pipe
// then outputs black, and no PLL/DDI/transcoder teardown is needed. Doing the
// full modeset teardown is easy to get wrong and can hang the pipe.
//
// This must run while no driver holds the device. vfio-pci requests its BARs
// exclusively, after which iomem_is_exclusive() makes both the sysfs BAR mmap
// and /dev/mem unavailable.

const (
	igpuBAR0Len = 16 << 20

	// Display register block. i915 derives these by linear extrapolation
	// (_PICK_EVEN) from the pipe A / plane 1 bases, so pipes are 0x1000
	// apart (_PLANE_CTL_1_A 0x70180 -> _PLANE_CTL_1_B 0x71180) and a pipe's
	// universal planes are 0x100 apart (-> _PLANE_CTL_2_A 0x70280).
	// Iterating past what a platform implements is harmless: an absent
	// plane's enable bit is never set.
	igpuPipeStride = 0x1000
	igpuNumPipes   = 4
	igpuNumPlanes  = 5

	igpuPlaneCtlEnable = 1 << 31      // PLANE_CTL_ENABLE
	igpuCurModeMask    = uint32(0x27) // MCURSOR_MODE_MASK
)

func igpuPlaneCtl(pipe, plane int) int {
	return 0x70180 + pipe*igpuPipeStride + (plane-1)*0x100
}

func igpuPlaneSurf(pipe, plane int) int {
	return 0x7019c + pipe*igpuPipeStride + (plane-1)*0x100
}

func igpuCurCtl(pipe int) int  { return 0x70080 + pipe*igpuPipeStride }
func igpuCurBase(pipe int) int { return 0x70084 + pipe*igpuPipeStride }

// sysfsHexAttr reads a sysfs attribute holding a value like "0x8086".
func sysfsHexAttr(long, name string) (uint64, error) {
	b, err := os.ReadFile(filepath.Join(sysfsPciDevices, long, name))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(string(b)), "0x"), 16, 64)
}

// isIntelDisplayDevice reports whether the device is an Intel display-class
// device, i.e. one whose display engine we know how to quiesce.
func isIntelDisplayDevice(long string) bool {
	vendor, err := sysfsHexAttr(long, "vendor")
	if err != nil || vendor != 0x8086 {
		return false
	}
	class, err := sysfsHexAttr(long, "class")
	return err == nil && class>>16 == 0x03
}

// igpuDisableDisplayPlanes turns off every enabled display and cursor plane on
// an Intel iGPU so it stops fetching from stolen memory. It is best-effort:
// every failure is logged and reported, never fatal, since a device we cannot
// quiesce is still a device we want to pass through.
func igpuDisableDisplayPlanes(long string) error {
	if !isIntelDisplayDevice(long) {
		return nil
	}

	path := filepath.Join(sysfsPciDevices, long, "resource0")
	f, err := os.OpenFile(path, os.O_RDWR|unix.O_SYNC, 0)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	bar, err := unix.Mmap(int(f.Fd()), 0, igpuBAR0Len,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		// Expected if something already claimed the BARs exclusively.
		return fmt.Errorf("mmap BAR0 of %s: %w", long, err)
	}
	defer unix.Munmap(bar)

	// These registers must be touched with single 32-bit accesses: byte-wide
	// access to iGPU MMIO is not valid, and an arming write in particular
	// has to land as one store. atomic guarantees exactly one aligned 32-bit
	// operation and doubles as a compiler barrier, which plain dereferences
	// of mapped memory do not.
	reg := func(off int) *uint32 {
		return (*uint32)(unsafe.Pointer(&bar[off]))
	}
	rd := func(off int) uint32 { return atomic.LoadUint32(reg(off)) }
	wr := func(off int, v uint32) { atomic.StoreUint32(reg(off), v) }

	disabled := 0
	for pipe := 0; pipe < igpuNumPipes; pipe++ {
		// An absent pipe reads back as all ones.
		if rd(igpuCurCtl(pipe)) == 0xffffffff {
			continue
		}
		for plane := 1; plane <= igpuNumPlanes; plane++ {
			ctl := rd(igpuPlaneCtl(pipe, plane))
			if ctl == 0xffffffff || ctl&igpuPlaneCtlEnable == 0 {
				continue
			}
			// Same sequence as i915's skl_plane_disable_arm():
			// zero the control register, then write the arming
			// register, which is what makes the change take effect.
			wr(igpuPlaneCtl(pipe, plane), 0)
			wr(igpuPlaneSurf(pipe, plane), 0)
			disabled++
			logrus.Infof("igpu %s: disabled pipe %c plane %d (was 0x%08x)",
				long, 'A'+pipe, plane, ctl)
		}
		// i9xx_cursor_disable_arm() likewise writes a zeroed control
		// register followed by the base register.
		if cur := rd(igpuCurCtl(pipe)); cur&igpuCurModeMask != 0 {
			wr(igpuCurCtl(pipe), 0)
			wr(igpuCurBase(pipe), 0)
			disabled++
			logrus.Infof("igpu %s: disabled pipe %c cursor (was 0x%08x)",
				long, 'A'+pipe, cur)
		}
	}
	logrus.Infof("igpu %s: quiesced display engine, %d planes disabled", long, disabled)
	return nil
}
