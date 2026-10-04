// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
)

// gpuStatusFor is the answer to a config change. With no console attached
// there is nobody holding DRM master, so a release request is trivially
// satisfied - a device whose console has died must not stop an app from
// starting. A restore with no console attached is answered the same way
// (Released: true) purely because there is nothing to wait for either; it is
// not claiming the GPU was released.
func (ctx *monitor) gpuStatusFor(cfg types.GPUConsoleConfig, clientAttached bool) types.GPUConsoleStatus {
	if !clientAttached {
		return types.GPUConsoleStatus{Domain: cfg.Domain, Released: true, RequestID: cfg.RequestID}
	}
	// A console is attached; it has to answer for itself. The ack arrives
	// later, over IPC, and publishes the real status then.
	return types.GPUConsoleStatus{Domain: cfg.Domain, Released: false, RequestID: cfg.RequestID}
}

// handleGPUConsoleConfig forwards the request to the console and publishes the
// immediate answer. The console's own ack, when it comes, is published by
// handleGPUAck.
func (ctx *monitor) handleGPUConsoleConfig(cfg types.GPUConsoleConfig) {
	attached := ctx.IPCServer.hasClient()
	if attached {
		// Remember the in-flight id so handleGPUAck can drop a late ack for
		// a request this has since superseded, and hand the same id to the
		// console so it has something to echo back.
		ctx.pendingGPURequestID.Store(cfg.RequestID)
		req := monitorapi.NewGPURequest(cfg.Domain, cfg.Release, cfg.RequestID)
		if err := ctx.IPCServer.sendIpcMessage(monitorapi.GPURequestTag, req); err != nil {
			log.Errorf("Failed to forward GPU request to console: %v", err)
		}
	}
	ctx.publishGPUConsoleStatus(ctx.gpuStatusFor(cfg, attached))
}

// handleGPUAck publishes what the console reported, unless it answers a
// request that has since been superseded by a newer one: pendingGPURequestID
// is a single slot, not a queue, so a slow console's ack for an old request
// must not be mistaken for an answer to the current one.
func (ctx *monitor) handleGPUAck(ack monitorapi.GPUAck) {
	if pending := ctx.pendingGPURequestID.Load(); ack.RequestID != pending {
		log.Warnf("handleGPUAck: dropping ack for request %d, %d is pending",
			ack.RequestID, pending)
		return
	}
	ctx.publishGPUConsoleStatus(types.GPUConsoleStatus{
		Domain:    ack.Domain,
		Released:  ack.Released,
		RequestID: ack.RequestID,
	})
}

// publishGPUConsoleStatus publishes the agent's current answer for GPU
// handover.
func (ctx *monitor) publishGPUConsoleStatus(status types.GPUConsoleStatus) {
	if err := ctx.pubGPUConsoleStatus.Publish(status.Key(), status); err != nil {
		log.Errorf("Failed to publish GPUConsoleStatus: %v", err)
	}
}
