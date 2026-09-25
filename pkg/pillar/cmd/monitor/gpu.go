// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
)

// gpuStatusFor is the answer to a release request. With no console attached
// there is nobody holding DRM master, so the GPU is already free and the
// answer is immediate - a device whose console has died must not stop an app
// from starting.
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
		// GPUAck (console -> pillar) only echoes Domain, not RequestID, so
		// remember it here for handleGPUAck to stamp onto the real status.
		ctx.pendingGPURequestID.Store(cfg.RequestID)
		req := monitorapi.NewGPURequest(cfg.Domain, cfg.Release)
		if err := ctx.IPCServer.sendIpcMessage(monitorapi.GPURequestTag, req); err != nil {
			log.Errorf("Failed to forward GPU request to console: %v", err)
		}
	}
	ctx.publishGPUConsoleStatus(ctx.gpuStatusFor(cfg, attached))
}

// handleGPUAck publishes what the console reported.
func (ctx *monitor) handleGPUAck(ack monitorapi.GPUAck) {
	ctx.publishGPUConsoleStatus(types.GPUConsoleStatus{
		Domain:    ack.Domain,
		Released:  ack.Released,
		RequestID: ctx.pendingGPURequestID.Load(),
	})
}

// publishGPUConsoleStatus publishes the agent's current answer for GPU
// handover.
func (ctx *monitor) publishGPUConsoleStatus(status types.GPUConsoleStatus) {
	if err := ctx.pubGPUConsoleStatus.Publish(status.Key(), status); err != nil {
		log.Errorf("Failed to publish GPUConsoleStatus: %v", err)
	}
}
