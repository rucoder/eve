// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

func TestParseTransitionMarker(t *testing.T) {
	now := time.Now().Unix()

	cases := []struct {
		name    string
		content string
		wantTS  int64
		wantCnt int
		wantErr bool
	}{
		{
			name:    "valid recent",
			content: fmt.Sprintf("%d 2", now-30),
			wantTS:  now - 30,
			wantCnt: 2,
		},
		{
			name:    "single field rejected",
			content: fmt.Sprintf("%d", now),
			wantErr: true,
		},
		{
			name:    "empty file rejected",
			content: "",
			wantErr: true,
		},
		{
			name:    "non-numeric timestamp rejected",
			content: "notanumber 1",
			wantErr: true,
		},
		{
			name:    "non-numeric count rejected",
			content: fmt.Sprintf("%d bogus", now),
			wantErr: true,
		},
		{
			name:    "zero timestamp rejected",
			content: "0 1",
			wantErr: true,
		},
		{
			name:    "negative timestamp rejected",
			content: "-5 1",
			wantErr: true,
		},
		{
			name:    "more than 60s in the future rejected",
			content: fmt.Sprintf("%d 1", now+120),
			wantErr: true,
		},
		{
			name:    "60s tolerance accepted",
			content: fmt.Sprintf("%d 1", now+30),
			wantTS:  now + 30,
			wantCnt: 1,
		},
		{
			name:    "trailing whitespace tolerated",
			content: fmt.Sprintf("  %d   3  ", now-10),
			wantTS:  now - 10,
			wantCnt: 3,
		},
		{
			name:    "extra fields tolerated (first two win)",
			content: fmt.Sprintf("%d 1 extra-junk", now-5),
			wantTS:  now - 5,
			wantCnt: 1,
		},
	}

	dir := t.TempDir()
	tmp := dir + "/marker"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(tmp, []byte(c.content), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ts, cnt, err := parseTransitionMarker(tmp)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if ts != c.wantTS {
				t.Errorf("ts = %d, want %d", ts, c.wantTS)
			}
			if cnt != c.wantCnt {
				t.Errorf("cnt = %d, want %d", cnt, c.wantCnt)
			}
		})
	}

	// missing file → distinct error surface (os.ReadFile fails before
	// any field parsing runs).
	if _, _, err := parseTransitionMarker(dir + "/does-not-exist"); err == nil {
		t.Errorf("missing file: expected error, got nil")
	}
}

// TestCountReadyNodesWithoutClient pins the no-panic contract the join
// watchdog depends on. It polls from boot, long before the FSM installs
// the default kubeclient — and on the stuck join it exists to catch,
// the client is never installed at all. Default() would panic there;
// "no client" has to read as "nothing is Ready" instead.
func TestCountReadyNodesWithoutClient(t *testing.T) {
	// kubeclient.SetDefault is never called in this package's tests, so
	// the process-wide client is nil here — the state a stuck join sees.
	if got := countReadyNodes(context.Background()); got != 0 {
		t.Errorf("countReadyNodes with no client = %d, want 0", got)
	}
}

// TestStartJoinWatchdogWithoutMarker checks the watchdog stays dormant
// when no join is in flight: no marker, no goroutine, and the
// double-start guard left clear so a later real join can start one.
func TestStartJoinWatchdogWithoutMarker(t *testing.T) {
	if _, err := os.Stat(string(state.TransitionToCluster)); !os.IsNotExist(err) {
		t.Skipf("host has a real %s marker", state.TransitionToCluster)
	}

	StartJoinWatchdog(context.Background())

	if joinWatchdogActive.Load() {
		t.Error("watchdog marked active with no transition marker on disk")
	}
}
