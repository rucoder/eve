// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
)

// The agent must answer even when no console is connected: a device whose
// console has crashed must not block an app from starting.
func TestGPUReleaseWithNoClientStillAnswers(t *testing.T) {
	ctx := &monitor{}
	st := ctx.gpuStatusFor(types.GPUConsoleConfig{Domain: "vm1", Release: true}, false)
	if !st.Released {
		t.Errorf("with no console connected the GPU is by definition free, got %+v", st)
	}
	if st.Domain != "vm1" {
		t.Errorf("status must name the domain it answers for, got %q", st.Domain)
	}
}

// With a console attached the agent reports what the console said.
func TestGPUReleaseWithClientReportsTheAck(t *testing.T) {
	ctx := &monitor{}
	st := ctx.gpuStatusFor(types.GPUConsoleConfig{Domain: "vm1", Release: true}, true)
	if st.Released {
		t.Error("with a console attached the agent must wait for its ack, not assume")
	}
}
