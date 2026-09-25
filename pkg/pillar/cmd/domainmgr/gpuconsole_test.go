// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// errStartFailed is a placeholder error used to exercise the failure path of
// assignWithGPU.
var errStartFailed = errors.New("domain start failed")

// A console that never answers - crashed, hung, or stuck in a GL teardown -
// must not stop the workload the device exists to run. domainmgr waits, then
// proceeds.
func TestReleaseProceedsWhenTheConsoleNeverAnswers(t *testing.T) {
	waited := waitForRelease(func() (bool, bool) { return false, false }, 100*time.Millisecond)
	if waited {
		t.Error("expected the wait to time out, not to report success")
	}
}

// If the domain fails to start after the GPU was released, the console must
// get it back. Otherwise one failed app start leaves the device in text mode
// until the next reboot.
func TestFailedDomainStartRestoresTheConsole(t *testing.T) {
	var restored bool
	assignWithGPU(
		func() {},                              // release
		func() error { return errStartFailed }, // domain start fails
		func() { restored = true },             // restore hook
	)
	if !restored {
		t.Error("a failed start must hand the GPU back to the console")
	}
}

// The normal case: the console acks and we go ahead immediately.
func TestReleaseReturnsAsSoonAsTheConsoleAcks(t *testing.T) {
	start := time.Now()
	ok := waitForRelease(func() (bool, bool) { return true, true }, 5*time.Second)
	if !ok {
		t.Error("expected success")
	}
	if time.Since(start) > time.Second {
		t.Error("expected it to return on the ack, not to wait out the timeout")
	}
}

// Turning VGA access back on must tell the console it can take the GPU back,
// once the framebuffer console is itself back in a usable state. Otherwise
// flipping the operator knob back leaves the console permanently without a
// display.
func TestVgaAccessEnableRestoresTheConsole(t *testing.T) {
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pubGPUConsoleConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.GPUConsoleConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := &domainContext{
		assignableAdapters:  &types.AssignableAdapters{},
		pubGPUConsoleConfig: pubGPUConsoleConfig,
		vgaAccess:           true,
	}

	// Simulate VGA access having been turned off earlier.
	vgaSwitch = true
	defer func() { vgaSwitch = false }()

	updateVgaAccess(ctx)

	st, err := pubGPUConsoleConfig.Get(types.GPUConsoleConfig{}.Key())
	if err != nil {
		t.Fatalf("expected GPUConsoleConfig to have been published, got: %v", err)
	}
	cfg, ok := st.(types.GPUConsoleConfig)
	if !ok {
		t.Fatalf("unexpected type %T for GPUConsoleConfig", st)
	}
	if cfg.Release {
		t.Error("enabling VGA access must tell the console it can take the GPU back (Release: false), not ask it to release again")
	}
}

// newGPUConsoleTestContext wires up a domainContext with real (in-memory)
// GPUConsoleConfig/GPUConsoleStatus pub/sub, exactly as Run() does, plus a
// second publication standing in for the monitor agent so tests can answer a
// release request the way the monitor would.
func newGPUConsoleTestContext(t *testing.T) (ctx *domainContext, monitorPub pubsub.Publication) {
	t.Helper()
	ps := pubsub.New(pubsub.NewMemoryDriver(), logger, log)
	pubGPUConsoleConfig, err := ps.NewPublication(pubsub.PublicationOptions{
		AgentName: agentName,
		TopicType: types.GPUConsoleConfig{},
	})
	if err != nil {
		t.Fatal(err)
	}
	monitorPub, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName: "monitor",
		TopicType: types.GPUConsoleStatus{},
	})
	if err != nil {
		t.Fatal(err)
	}
	subGPUConsoleStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "monitor",
		MyAgentName: agentName,
		TopicImpl:   types.GPUConsoleStatus{},
		Activate:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &domainContext{
		pubGPUConsoleConfig: pubGPUConsoleConfig,
		subGPUConsoleStatus: subGPUConsoleStatus,
	}, monitorPub
}

// releaseGPUForDomain runs on the same goroutine that would otherwise drain
// subGPUConsoleStatus's channel from Run()'s select loop, so a real ack that
// arrives while it is waiting must be picked up by its own polling, not left
// uncollected until the wait times out. Before the drain-on-poll fix, this
// test times out and fails.
func TestReleaseObservesAnAckThatArrivesDuringTheWait(t *testing.T) {
	ctx, monitorPub := newGPUConsoleTestContext(t)

	result := make(chan bool, 1)
	resultConsumed := false
	start := time.Now()
	go func() {
		result <- releaseGPUForDomain(ctx, "vm1", 5*time.Second)
	}()
	// If a t.Fatal below fires before the select at the bottom consumes
	// result, the goroutine must not keep running against ctx and the
	// package log past the end of the test - block here until it finishes.
	// resultConsumed guards against double-receiving on the normal path,
	// where the select below already drained the one value this channel
	// ever gets.
	t.Cleanup(func() {
		if !resultConsumed {
			<-result
		}
	})

	// Wait for the request to actually be published, then answer it the way
	// the monitor agent would - after domainmgr has started waiting, not
	// before.
	var cfg types.GPUConsoleConfig
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if v, err := ctx.pubGPUConsoleConfig.Get(types.GPUConsoleConfig{}.Key()); err == nil {
			if c, ok := v.(types.GPUConsoleConfig); ok && c.Domain == "vm1" {
				cfg = c
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if cfg.Domain != "vm1" {
		t.Fatal("release request was never published")
	}
	if err := monitorPub.Publish(types.GPUConsoleStatus{}.Key(), types.GPUConsoleStatus{
		Domain: "vm1", Released: true, RequestID: cfg.RequestID,
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case ok := <-result:
		resultConsumed = true
		if !ok {
			t.Error("expected the release to be observed as successful")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("releaseGPUForDomain did not return after the ack was published")
	}
	if time.Since(start) > time.Second {
		t.Error("expected the ack to be observed quickly, not after waiting it out")
	}
}

// GPUConsoleConfig/GPUConsoleStatus both key to "global" - one shared slot,
// not a queue - so a status left over from an earlier, unrelated cycle must
// not be mistaken for the answer to a brand new request just because Domain
// matches (it is "" on every restore and every updateVgaAccess call). Before
// the request-id fix, this test returns true almost instantly instead of
// timing out.
//
// The planted id is captured from nextGPURequestID() itself, not a fixed
// literal: gpuRequestID is a package-global counter starting at 0, so a
// small literal (e.g. 1) can collide with the real request this test's own
// releaseGPUForDomain call generates when this test happens to run first in
// the process - flaky in isolation, masked by the full package run where
// earlier tests have already bumped the counter. Capturing the id here and
// consuming it before the real call guarantees the real call gets the next
// one instead, so they can never collide regardless of run order - capturing
// the id is collision-proof by construction, unlike a fixed sentinel value.
func TestReleaseIgnoresAStaleStatusFromAPreviousCycle(t *testing.T) {
	ctx, monitorPub := newGPUConsoleTestContext(t)

	staleID := nextGPURequestID()
	if err := monitorPub.Publish(types.GPUConsoleStatus{}.Key(), types.GPUConsoleStatus{
		Domain: "", Released: true, RequestID: staleID,
	}); err != nil {
		t.Fatal(err)
	}
	// Let the subscription cache it before the real call, exactly like a
	// status left over from before this request began.
	change := <-ctx.subGPUConsoleStatus.MsgChan()
	ctx.subGPUConsoleStatus.ProcessChange(change)

	start := time.Now()
	ok := releaseGPUForDomain(ctx, "", 200*time.Millisecond)
	if ok {
		t.Error("a stale status from a previous request must not satisfy a new one")
	}
	if time.Since(start) < 150*time.Millisecond {
		t.Error("expected the wait to actually time out, not return early on stale data")
	}
}

// skipForVirtualGPU is the pure decision behind doAssignIoAdaptersToDomain's
// choice to reserve the boot VGA adapter for passthrough or leave it with
// the host driver. isBootVGA's own hardware check (real sysfs boot_vga) is
// exercised elsewhere; this only covers the mode decision once isBoot is
// known, via an injected gpuModeDir so it never touches /persist/gpu.
func TestSkipForVirtualGPU(t *testing.T) {
	appUUID, err := uuid.FromString("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	if err != nil {
		t.Fatal(err)
	}
	config := types.DomainConfig{UUIDandVersion: types.UUIDandVersion{UUID: appUUID}}

	t.Run("boot VGA, operator opted into a virtual GPU", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, appUUID.String()+".json"), []byte(`{"mode":"virtual"}`), 0644); err != nil {
			t.Fatal(err)
		}
		ctx := &domainContext{gpuModeDir: dir}
		if !skipForVirtualGPU(ctx, config, true) {
			t.Error("boot VGA in virtual mode must be skipped (left with the host driver)")
		}
	})

	t.Run("boot VGA, operator has not opted in (default passthrough)", func(t *testing.T) {
		ctx := &domainContext{gpuModeDir: t.TempDir()}
		if skipForVirtualGPU(ctx, config, true) {
			t.Error("boot VGA defaulting to passthrough must not be skipped")
		}
	})

	t.Run("non-boot-VGA adapter is never skipped, even in virtual mode", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, appUUID.String()+".json"), []byte(`{"mode":"virtual"}`), 0644); err != nil {
			t.Fatal(err)
		}
		ctx := &domainContext{gpuModeDir: dir}
		if skipForVirtualGPU(ctx, config, false) {
			t.Error("an adapter that is not the boot VGA must never be skipped")
		}
	})
}
