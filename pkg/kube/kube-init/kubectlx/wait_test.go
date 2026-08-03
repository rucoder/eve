// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package kubectlx

import (
	"context"
	"testing"
	"time"
)

// A caller managing its own deadline must not have one imposed here.
// Getting this wrong is silent: the helper's timeout fires first, the
// caller's guard never runs, and the only symptom is that the guard
// appears to do nothing.
func TestWaitFromContextImposesNoDeadline(t *testing.T) {
	ctx, cancel := withOptionalTimeout(context.Background(), 0)
	defer cancel()
	if _, ok := ctx.Deadline(); ok {
		t.Fatal("WaitFromContext must leave the ctx without a deadline")
	}
}

func TestWithOptionalTimeoutAppliesRealDeadlines(t *testing.T) {
	ctx, cancel := withOptionalTimeout(context.Background(), time.Minute)
	defer cancel()
	d, ok := ctx.Deadline()
	if !ok {
		t.Fatal("a positive timeout must produce a deadline")
	}
	if time.Until(d) > time.Minute+time.Second {
		t.Fatalf("deadline too far out: %s", time.Until(d))
	}
}

// The sentinel is negative, so it must not fall through to the "zero
// means default" branch anywhere it is rendered or compared.
func TestTimeoutStrDistinguishesSentinelFromDefault(t *testing.T) {
	if got := timeoutStr(WaitFromContext); got != "from ctx" {
		t.Fatalf("timeoutStr(WaitFromContext) = %q", got)
	}
	if got := timeoutStr(0); got != defaultWaitTimeout.String() {
		t.Fatalf("timeoutStr(0) = %q, want the default", got)
	}
	if got := timeoutStr(90 * time.Second); got != "1m30s" {
		t.Fatalf("timeoutStr(90s) = %q", got)
	}
}
