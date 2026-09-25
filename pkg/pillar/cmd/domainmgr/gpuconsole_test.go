// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

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
		func() bool { return true },            // release succeeds
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
