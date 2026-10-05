// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	framed "github.com/getlantern/framed"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

// A console that restarts reconnects to an agent that has been running the
// whole time, so nothing upstream has changed and no pubsub handler fires.
// The only state the new client gets is what handleClientConnected pushes -
// and that push used to be swallowed by sendDeviceStatus's dedup, which is
// keyed on the agent's lifetime rather than the connection's. On a live
// device that meant an empty node page after every console restart, until
// something upstream happened to change.
func TestDeviceStatusIsResentToEveryNewClient(t *testing.T) {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "test", 1234)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { serverConn.Close(); clientConn.Close() })

	serverCodec := framed.NewReadWriteCloser(serverConn)
	serverCodec.EnableBigFrames()
	clientCodec := framed.NewReadWriteCloser(clientConn)
	clientCodec.EnableBigFrames()

	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	ctx := &monitor{}
	subApp, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedmanager",
		MyAgentName: agentName,
		TopicImpl:   types.AppInstanceStatus{},
		Activate:    false,
		Ctx:         ctx,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx.subscriptions = map[string]pubsub.Subscription{"AppStatus": subApp}
	ctx.pubDebugOptionValues, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.DebugOptionValues{},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx.IPCServer = newIPCServer(ctx)
	ctx.IPCServer.conn = serverConn
	ctx.IPCServer.codec = serverCodec

	// net.Pipe is unbuffered, so a console has to be reading for the agent's
	// sends to complete at all. One reader for the whole test: on the agent
	// side handleClientConnected always runs on the single process goroutine,
	// so the calls below stay sequential, as they are in production.
	tags := make(chan string, 16)
	go func() {
		for {
			frame, err := clientCodec.ReadFrame()
			if err != nil {
				close(tags)
				return
			}
			var env struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(frame, &env); err != nil {
				close(tags)
				return
			}
			tags <- env.Type
		}
	}()

	sawDeviceStatus := func(t *testing.T, want int) bool {
		t.Helper()
		for i := 0; i < want; i++ {
			select {
			case tag, ok := <-tags:
				if !ok {
					t.Fatal("console side of the pipe closed early")
				}
				if tag == "DeviceStatus" {
					return true
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the agent to push connect-time state")
			}
		}
		return false
	}

	// Each connect pushes DeviceStatus, AppsList and DebugOptions here (no
	// NetworkStatus subscription).
	const perConnect = 3

	// First console: gets the snapshot, which is what primes the dedup.
	ctx.handleClientConnected()
	if !sawDeviceStatus(t, perConnect) {
		t.Fatal("first client must get DeviceStatus")
	}

	// Second console, same agent, nothing upstream changed.
	ctx.handleClientConnected()
	if !sawDeviceStatus(t, perConnect) {
		t.Error("a reconnecting client must get DeviceStatus again, not just AppsList")
	}
}
