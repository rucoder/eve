// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// gpuReleaseTimeout bounds how long domainmgr waits for the console to
// release the GPU before proceeding with the passthrough anyway.
const gpuReleaseTimeout = 5 * time.Second

// gpuRequestID hands out a fresh, monotonically increasing id for every
// GPUConsoleConfig published, release or restore. GPUConsoleConfig and
// GPUConsoleStatus both key to "global" - one shared slot, not a queue - so
// without a changing id a stale status left over from a previous cycle can
// look identical to the answer for a brand new request (Domain is "" on
// every restore and on every updateVgaAccess call, so it cannot tell cycles
// apart). A changing id also keeps pubsub's PublicationImpl.Publish, which
// no-ops on an unchanged value, from swallowing a repeated identical
// request.
var gpuRequestID atomic.Uint64

func nextGPURequestID() uint64 {
	return gpuRequestID.Add(1)
}

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

// drainGPUConsoleStatus processes one pending GPUConsoleStatus change, if any
// arrives within a short window, so a subsequent Get() reflects it.
//
// releaseGPUForDomain runs on the same goroutine that would otherwise service
// subGPUConsoleStatus's channel from Run()'s select loop: doAssignIoAdapters-
// ToDomain <- doActivate <- handleCreate/handleModify, and updateVgaAccess <-
// handleGlobalConfigImpl, both run inline on it, not on a spawned goroutine.
// While that single goroutine is blocked here polling, nothing else can call
// ProcessChange for this subscription, so Get() would otherwise only ever
// see whatever was cached before the wait began. Draining the channel
// ourselves is what lets an ack that arrives during the wait actually be
// observed.
func drainGPUConsoleStatus(ctx *domainContext) {
	select {
	case change := <-ctx.subGPUConsoleStatus.MsgChan():
		ctx.subGPUConsoleStatus.ProcessChange(change)
	case <-time.After(10 * time.Millisecond):
	}
}

// releaseGPUForDomain asks the console (via the monitor agent) to give up the
// GPU so it can be bound to vfio-pci for domain, and waits up to timeout for
// the console's acknowledgement. It always returns; on timeout the caller is
// expected to proceed with the passthrough anyway, since the device exists to
// run the workload, not the console.
func releaseGPUForDomain(ctx *domainContext, domain string, timeout time.Duration) bool {
	id := nextGPURequestID()
	cfg := types.GPUConsoleConfig{Domain: domain, Release: true, RequestID: id}
	if err := ctx.pubGPUConsoleConfig.Publish(cfg.Key(), cfg); err != nil {
		log.Errorf("releaseGPUForDomain(%s): failed to publish GPUConsoleConfig: %v",
			domain, err)
		return false
	}

	released := waitForRelease(func() (bool, bool) {
		drainGPUConsoleStatus(ctx)
		st, err := ctx.subGPUConsoleStatus.Get(cfg.Key())
		if err != nil {
			return false, false
		}
		status, ok := st.(types.GPUConsoleStatus)
		if !ok || status.RequestID != id {
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
// domain identifies whoever just gave it up (the app's domain name, or "" for
// the global vgaAccess knob) purely for tracing - matching is done by the
// monitor agent by request id, not by this. No wait: this is fire-and-forget,
// the same "the caller wins" rule as releaseGPUForDomain - nothing here
// should be able to block on the console either.
func restoreGPUToConsole(ctx *domainContext, domain string) {
	cfg := types.GPUConsoleConfig{Domain: domain, Release: false, RequestID: nextGPURequestID()}
	if err := ctx.pubGPUConsoleConfig.Publish(cfg.Key(), cfg); err != nil {
		log.Errorf("restoreGPUToConsole(%s): failed to publish GPUConsoleConfig: %v", domain, err)
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

// assignWithGPU releases the GPU, starts the domain, and hands the GPU back if
// the start failed. Split out from doAssignIoAdaptersToDomain so the failure
// path is testable without a running hypervisor: a failed start must not
// leave the console permanently without the GPU.
func assignWithGPU(release func(), start func() error, restore func()) error {
	release()
	if err := start(); err != nil {
		restore()
		return err
	}
	return nil
}
