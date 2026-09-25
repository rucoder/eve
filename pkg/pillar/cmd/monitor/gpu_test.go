// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"net"
	"testing"

	framed "github.com/getlantern/framed"
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

// Pins the full round trip end to end: the GPURequest actually forwarded
// over IPC must carry the same id the GPUConsoleConfig had (not a
// zero-valued RequestID that was never threaded through NewGPURequest), and
// an ack echoing that real id is accepted while one that doesn't is
// dropped. Testing the two halves separately (as the other tests here do)
// would miss a regression in the wiring between them - which is exactly
// the bug this test was added for: handleGPUConsoleConfig used to forward
// GPURequest without its RequestID at all, so a console could only ever
// echo back 0 while pendingGPURequestID held the real, nonzero id -
// dropping every real ack forever.
func TestGPURequestRoundTripsTheRequestID(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test", 1234)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { serverConn.Close(); clientConn.Close() })

	serverCodec := framed.NewReadWriteCloser(serverConn)
	serverCodec.EnableBigFrames()
	clientCodec := framed.NewReadWriteCloser(clientConn)
	clientCodec.EnableBigFrames()

	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pub, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.GPUConsoleStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := &monitor{pubGPUConsoleStatus: pub}
	ctx.IPCServer = newIPCServer(ctx)
	// Stand in for handleConnection: give the server a live conn/codec
	// (so hasClient() is true and sendIpcMessage has somewhere to write)
	// without the connection-accept machinery this test doesn't need.
	ctx.IPCServer.conn = serverConn
	ctx.IPCServer.codec = serverCodec

	// Read what actually goes out on the wire, playing the console's part,
	// concurrently: net.Pipe is unbuffered and synchronous.
	type forwarded struct {
		req monitorapi.GPURequest
		err error
	}
	got := make(chan forwarded, 1)
	go func() {
		frame, err := clientCodec.ReadFrame()
		if err != nil {
			got <- forwarded{err: err}
			return
		}
		var env struct {
			Type    string          `json:"type"`
			Message json.RawMessage `json:"message"`
		}
		if err := json.Unmarshal(frame, &env); err != nil {
			got <- forwarded{err: err}
			return
		}
		var req monitorapi.GPURequest
		err = json.Unmarshal(env.Message, &req)
		got <- forwarded{req: req, err: err}
	}()

	ctx.handleGPUConsoleConfig(types.GPUConsoleConfig{Domain: "vm1", Release: true, RequestID: 42})

	fwd := <-got
	if fwd.err != nil {
		t.Fatalf("failed to read the forwarded GPURequest: %v", fwd.err)
	}
	if fwd.req.RequestID != 42 {
		t.Fatalf("forwarded GPURequest must carry the config's RequestID 42, got %+v", fwd.req)
	}

	// handleGPUConsoleConfig itself already published the immediate
	// {Released:false} answer (a console is attached, so it has to answer
	// for itself) - that is the baseline a dropped ack must leave alone.
	before, err := pub.Get(types.GPUConsoleStatus{}.Key())
	if err != nil {
		t.Fatalf("expected the immediate status to already be published: %v", err)
	}
	if before.(types.GPUConsoleStatus).Released {
		t.Fatalf("unexpected published status before any ack: %+v", before)
	}

	ctx.handleGPUAck(monitorapi.GPUAck{Domain: "vm1", Released: true, RequestID: fwd.req.RequestID + 1})
	if after, err := pub.Get(types.GPUConsoleStatus{}.Key()); err != nil || after.(types.GPUConsoleStatus).Released {
		t.Errorf("an ack for a different id than what was forwarded must not be published, got %+v (err %v)", after, err)
	}

	ctx.handleGPUAck(monitorapi.GPUAck{Domain: "vm1", Released: true, RequestID: fwd.req.RequestID})
	st, err := pub.Get(types.GPUConsoleStatus{}.Key())
	if err != nil {
		t.Fatalf("an ack echoing the id that was actually forwarded must be accepted: %v", err)
	}
	if status, ok := st.(types.GPUConsoleStatus); !ok || !status.Released {
		t.Errorf("unexpected published status: %+v", st)
	}
}
