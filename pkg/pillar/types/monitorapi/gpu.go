// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// The wire tag must match the IpcMessage variant name in
// pkg/monitor/src/ipc/message.rs. It is the contract between the two sides and
// nothing checks it at build time, so it lives in one place.
const (
	GPURequestTag = "GPURequest"
	GPUAckTag     = "GPUAck"
)

// GPURequest asks the console to give up the GPU, or tells it the GPU is
// available again. i915 will not unbind while the console holds DRM master, so
// domainmgr cannot simply take the device: it asks, and waits for GPUAck.
type GPURequest struct {
	// Domain that wants the GPU, for the log. Empty on release-to-console.
	Domain string `json:"domain"`
	// Release is true when the console must let go, false when it may claim
	// the GPU again.
	Release bool `json:"release"`
}

// GPUAck is the console's answer. Released mirrors the request it is
// answering, so a late ack for a superseded request is recognisable.
type GPUAck struct {
	Domain   string `json:"domain"`
	Released bool   `json:"released"`
}

// NewGPURequest builds the request domainmgr sends to ask the console to give
// up the GPU (release=true) or to let it know the GPU is available again
// (release=false).
func NewGPURequest(domain string, release bool) *GPURequest {
	return &GPURequest{Domain: domain, Release: release}
}
