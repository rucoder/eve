// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// gpuReleaseTimeout bounds how long domainmgr waits for the console to
// release the GPU before proceeding with the passthrough anyway.
const gpuReleaseTimeout = 5 * time.Second

// waitForRelease polls until the console reports the GPU released or the
// timeout expires. Returns whether it was released.
//
// On timeout the caller proceeds regardless: a console that will not answer
// must not block an application from starting. That is a deliberate choice -
// the device exists to run the workload, not the console - and it is logged.
func waitForRelease(poll func() (found bool, released bool), timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if found, released := poll(); found && released {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// releaseGPUForDomain asks the console (via the monitor agent) to give up the
// GPU so it can be bound to vfio-pci for domain, and waits up to timeout for
// the console's acknowledgement. It always returns; on timeout the caller is
// expected to proceed with the passthrough anyway, since the device exists to
// run the workload, not the console.
func releaseGPUForDomain(ctx *domainContext, domain string, timeout time.Duration) bool {
	cfg := types.GPUConsoleConfig{Domain: domain, Release: true}
	if err := ctx.pubGPUConsoleConfig.Publish(cfg.Key(), cfg); err != nil {
		log.Errorf("releaseGPUForDomain(%s): failed to publish GPUConsoleConfig: %v",
			domain, err)
		return false
	}

	released := waitForRelease(func() (bool, bool) {
		st, err := ctx.subGPUConsoleStatus.Get(cfg.Key())
		if err != nil {
			return false, false
		}
		status, ok := st.(types.GPUConsoleStatus)
		if !ok || status.Domain != domain {
			return false, false
		}
		return true, status.Released
	}, timeout)

	if !released {
		log.Warnf("releaseGPUForDomain(%s): console did not release the GPU "+
			"within %s; proceeding with passthrough anyway", domain, timeout)
	}
	return released
}

// restoreGPUToConsole tells the console it is free to take the GPU back.
func restoreGPUToConsole(ctx *domainContext) {
	cfg := types.GPUConsoleConfig{Release: false}
	if err := ctx.pubGPUConsoleConfig.Publish(cfg.Key(), cfg); err != nil {
		log.Errorf("restoreGPUToConsole: failed to publish GPUConsoleConfig: %v", err)
	}
}

// isBootVGA reports whether ib is the boot VGA device - the one the console
// actually displays on ("console output won't be visible on others anyway",
// per the existing keepInHost check this mirrors). That is the only adapter
// releaseGPUForDomain/restoreGPUToConsole need to care about: taking some
// other GPU away from an app was never something the console held.
func isBootVGA(ib *types.IoBundle) bool {
	if ib == nil || ib.Type != types.IoHDMI {
		return false
	}
	keep, err := types.PCIIsBootVga(log, ib.PciLong)
	if err != nil {
		log.Errorf("isBootVGA: PCIIsBootVga(%s) failed: %v", ib.PciLong, err)
		return false
	}
	return keep
}

// errStartFailed is a placeholder error used by tests exercising the failure
// path of assignWithGPU.
var errStartFailed = errors.New("domain start failed")

// assignWithGPU releases the GPU, starts the domain, and hands the GPU back if
// the start failed. Split out from doAssignIoAdaptersToDomain so the failure
// path is testable without a running hypervisor: a failed start must not
// leave the console permanently without the GPU.
func assignWithGPU(release func() bool, start func() error, restore func()) error {
	release()
	if err := start(); err != nil {
		restore()
		return err
	}
	return nil
}
