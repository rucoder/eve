// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/types/monitorapi"
	"github.com/sirupsen/logrus"
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

// pendingGPURequestID is a single slot, not a queue: a slow console's ack for
// a request domainmgr has since superseded (it timed out, restored, and
// released again) must not be republished as an answer to the current one.
func TestGPUAckForASupersededRequestIsDropped(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test", 1234)

	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.GPUConsoleStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := &monitor{pubGPUConsoleStatus: pub}
	ctx.pendingGPURequestID.Store(5)

	ctx.handleGPUAck(monitorapi.GPUAck{Domain: "vm1", Released: true, RequestID: 3})
	if _, err := pub.Get(types.GPUConsoleStatus{}.Key()); err == nil {
		t.Error("an ack for a superseded request id must not be published")
	}

	ctx.handleGPUAck(monitorapi.GPUAck{Domain: "vm1", Released: true, RequestID: 5})
	st, err := pub.Get(types.GPUConsoleStatus{}.Key())
	if err != nil {
		t.Fatalf("expected the ack for the pending request id to be published: %v", err)
	}
	status, ok := st.(types.GPUConsoleStatus)
	if !ok || !status.Released || status.RequestID != 5 {
		t.Errorf("unexpected published status: %+v", st)
	}
}
