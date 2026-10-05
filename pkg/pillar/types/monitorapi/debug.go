// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitorapi

// Wire tags for the debug options, like the GPU handover's (see gpu.go):
// DebugOptionsTag travels pillar -> console as the "type" of an IpcMessage,
// SetDebugOptionTag console -> pillar as the "RequestType" of a request.
const (
	DebugOptionsTag   = "DebugOptions"
	SetDebugOptionTag = "SetDebugOption"
)

// DebugOption is one debug option and its current value. Pillar owns the
// catalogue (types.DebugOptionCatalogue); the console draws whatever it is
// sent, so an option is added on the pillar side alone.
type DebugOption struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	// Scope is "console" for an option the console applies itself, as soon
	// as it arrives, or "vm" for one applied when an application starts.
	Scope string `json:"scope"`
	// Kind is "bool" ("true"/"false"), "string" (free text) or "enum" (one
	// of Choices).
	Kind    string   `json:"kind"`
	Choices []string `json:"choices,omitempty"`
	Value   string   `json:"value"`
}

// DebugOptions is every debug option with its current value. Sent when the
// console connects and again after every change, so the console shows what
// pillar holds rather than what it asked for.
type DebugOptions struct {
	Options []DebugOption `json:"options"`
}

// SetDebugOption asks pillar to change one debug option. Pillar validates it
// against the catalogue and answers with DebugOptions either way.
type SetDebugOption struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}
