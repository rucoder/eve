// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"time"
)

// WaitItemDir holds the operator breakpoint files. On /persist so a
// breakpoint can be staged and then survive the reboot that reaches
// the point of interest.
var WaitItemDir = "/persist/k3s"

// waitItemPollInterval is how often a held breakpoint re-checks. Long
// on purpose: a held daemon logs one line a minute, which reads as a
// deliberate hold rather than a hang.
var waitItemPollInterval = 60 * time.Second

// WaitForItem blocks while /persist/k3s/wait_<item> exists, so an
// operator can freeze the daemon at a named point and inspect the
// node. Returns immediately when the file is absent, which is the
// normal case — this costs one stat per call site.
//
// The init sequence is long, fast and largely one-way: by the time
// anyone reacts to a failure, later steps have overwritten the state
// that explains it. Staging a breakpoint before the reboot is the only
// way to catch the node at, say, "k3s installed but Longhorn not yet
// applied". Ported from cluster-init.sh's wait_for_item.
//
// Cancelling ctx releases the wait, so a SIGTERM still shuts the
// daemon down cleanly while a breakpoint is held.
func WaitForItem(ctx context.Context, item string) {
	path := filepath.Join(WaitItemDir, "wait_"+item)
	if _, err := os.Stat(path); err != nil {
		return
	}

	log.Printf("BREAKPOINT %q held by %s — remove the file to continue", item, path)
	ticker := time.NewTicker(waitItemPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("BREAKPOINT %q released by shutdown", item)
			return
		case <-ticker.C:
			if _, err := os.Stat(path); err != nil {
				log.Printf("BREAKPOINT %q released, continuing", item)
				return
			}
			log.Printf("BREAKPOINT %q still held by %s", item, path)
		}
	}
}
