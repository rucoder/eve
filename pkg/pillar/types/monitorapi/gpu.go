// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// These wire tags must match the Rust side in pkg/monitor/src/ipc/message.rs.
// Nothing checks that at build time, so they live in one place. The two
// messages travel in opposite directions and through different envelopes:
//
//   - GPURequestTag: pillar -> console, the "type" discriminator of the
//     adjacently-tagged IpcMessage envelope ({"type":...,"message":...}),
//     decoded straight into an IpcMessage::GPURequest variant.
//   - GPUAckTag: console -> pillar, the "RequestType" discriminator of the
//     request envelope ({"RequestType":...,"RequestData":...,"id":N}) that
//     also carries SetInterfaceConfig/SetServer/RevertManualConfig - it is a
//     Request variant, not a top-level IpcMessage variant, because that is
//     the only envelope pillar's ipc_server.go understands from the console.
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
	// RequestID identifies this request. The console must echo it back
	// unchanged in the GPUAck it sends for this request - pillar uses it to
	// drop a late ack for a request that has since been superseded by a
	// newer one, and has no other way to tell them apart (Domain repeats,
	// e.g. "" on every restore).
	RequestID uint64 `json:"request_id"`
}

// GPUAck is the console's answer. RequestID echoes the GPURequest it is
// answering, so pillar can drop a late ack for a request that has since been
// superseded by a newer one (Released only distinguishes a release-ack from
// a restore-ack, not one release-ack from the next).
type GPUAck struct {
	Domain    string `json:"domain"`
	Released  bool   `json:"released"`
	RequestID uint64 `json:"request_id"`
}

// NewGPURequest builds the request domainmgr sends to ask the console to give
// up the GPU (release=true) or to let it know the GPU is available again
// (release=false). requestID is echoed back in the console's GPUAck.
func NewGPURequest(domain string, release bool, requestID uint64) *GPURequest {
	return &GPURequest{Domain: domain, Release: release, RequestID: requestID}
}
