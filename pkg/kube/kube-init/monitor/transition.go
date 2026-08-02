// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// transitionTimeout caps how long a non-bootstrap node may sit
	// in the joining state before we reboot to retry.
	transitionTimeout = 5 * time.Minute

	// transitionMaxReboots caps the reboot-retry count before giving
	// up. Three is empirical: by the third attempt either the join
	// has stuck for a fundamental reason or the controller config
	// has changed and we are reading a stale marker.
	transitionMaxReboots = 3

	// transitionReadyNodes is the Ready-node count that defines a
	// successful join. Two is the minimum for an HA pair plus the
	// joining node either ready or in-progress.
	transitionReadyNodes = 2
)

// joinWatchdogActive guards against a second watchdog goroutine: both
// start sites (daemon boot and the end of the transition runner) can
// fire for the same join, and two of them would race to increment the
// marker's reboot count.
var joinWatchdogActive atomic.Bool

// StartJoinWatchdog runs CheckClusterTransitionDone on a ticker for as
// long as the transition-to-cluster marker is on disk, then stops.
// Returns immediately if there is no marker or a watchdog is already
// running.
//
// The watchdog is deliberately not part of the monitor goroutine set:
// those only start once the FSM reaches RUNNING, which requires the
// node to be Ready — the exact thing a stuck join never achieves. Tying
// the watchdog to the marker instead of to an FSM state is what makes
// it reachable in the failure it exists for. ctx must be the daemon's
// long-lived context, not a per-state one.
func StartJoinWatchdog(ctx context.Context) {
	marked, err := state.IsMarked(state.TransitionToCluster)
	if err != nil {
		log.Printf("warning: check transition marker for watchdog: %v", err)
		return
	}
	if !marked {
		return
	}
	if !joinWatchdogActive.CompareAndSwap(false, true) {
		return
	}

	log.Printf("cluster-join watchdog started (checking every %v)",
		clusterJoinRetryInterval)
	go func() {
		defer joinWatchdogActive.Store(false)
		ticker := time.NewTicker(clusterJoinRetryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !CheckClusterTransitionDone(ctx) {
					log.Printf("cluster-join watchdog stopped")
					return
				}
			}
		}
	}()
}

// CheckClusterTransitionDone progresses the cluster-join retry
// state machine for a non-bootstrap node.
//
// Marker file format: "<unix_timestamp> <reboot_count>" — the
// monitor writes the marker when it first observes the cluster-
// transition condition and rewrites it on each reboot retry.
//
// Returns true while the transition is still in progress (the
// marker remains on disk), false when the marker is gone or
// definitively cleared.
//
// On marker-read failure the function returns true so the caller
// keeps polling; treating an unreadable marker as "transition
// complete" would silently terminate the retry loop while the
// join is still half-finished.
func CheckClusterTransitionDone(ctx context.Context) bool {
	marked, err := state.IsMarked(state.TransitionToCluster)
	if err != nil {
		log.Printf("warning: check transition marker, retrying next tick: %v",
			err)
		return true
	}
	if !marked {
		return false
	}

	log.Printf("checking cluster transition status...")

	if countReadyNodes(ctx) >= transitionReadyNodes {
		log.Printf("cluster transition complete: %d+ Ready nodes",
			transitionReadyNodes)
		if err := state.Unmark(state.TransitionToCluster); err != nil {
			log.Printf("warning: remove transition marker: %v", err)
		}
		return false
	}

	transitionTS, rebootCount, err := parseTransitionMarker(string(state.TransitionToCluster))
	if err != nil {
		log.Printf("warning: parse transition marker: %v", err)
		// Malformed marker — treat as still in progress so the
		// next tick can heal it (write a fresh timestamp).
		return true
	}

	elapsed := time.Since(time.Unix(transitionTS, 0))
	if elapsed < transitionTimeout {
		log.Printf("still waiting for cluster transition: %v elapsed (timeout: %v)",
			elapsed.Truncate(time.Second), transitionTimeout)
		return true
	}

	rebootCount++
	if rebootCount > transitionMaxReboots {
		log.Printf("cluster transition: giving up after %d reboot attempts",
			transitionMaxReboots)
		if err := state.Unmark(state.TransitionToCluster); err != nil {
			log.Printf("warning: remove transition marker: %v", err)
		}
		return false
	}

	// AtomicWriteFile so a power-loss between mark and reboot
	// leaves the marker file consistent (the file is read again
	// after the reboot).
	newContent := fmt.Sprintf("%d %d", time.Now().Unix(), rebootCount)
	if err := state.AtomicWriteFile(string(state.TransitionToCluster),
		[]byte(newContent), 0644); err != nil {
		log.Printf("warning: update transition marker: %v", err)
		return true
	}

	reason := fmt.Sprintf("Reboot after retry cluster transition attempt %d",
		rebootCount)
	log.Printf("cluster transition: %s", reason)
	if err := state.RebootWithReason(reason); err != nil {
		log.Printf("warning: reboot failed: %v", err)
	}
	// RebootWithReason blocks until reboot; if it returns we are
	// in a degraded state but still mid-transition.
	return true
}

// countReadyNodes runs `k3s kubectl get nodes` and counts rows
// whose Ready condition is True. Cordoned nodes (spec.unschedulable=true)
// count too — they're still Ready for control-plane counting purposes.
// Non-True Ready collapses to "not counted".
func countReadyNodes(ctx context.Context) int {
	// The watchdog runs from boot, before the FSM reaches the state
	// that installs the default client — and on a join that never
	// completes, that state is never reached at all. No client means
	// the API was never usable, which is the same answer as an empty
	// node list, so report it rather than panicking in Default().
	c := kubeclient.DefaultOrNil()
	if c == nil {
		return 0
	}
	nodes, err := c.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	return countReady(nodes.Items)
}

// countReady is the pure half of countReadyNodes, factored out for
// unit tests. Counts nodes whose Ready condition is True.
func countReady(nodes []corev1.Node) int {
	count := 0
	for i := range nodes {
		if kubectlx.IsNodeReady(&nodes[i]) {
			count++
		}
	}
	return count
}

// parseTransitionMarker reads path and returns (unix_timestamp,
// reboot_count, err). A wildly-wrong timestamp (≤0 or more than
// 60s in the future) is rejected as corrupt — we don't want to
// immediately trigger a reboot on garbage data.
//
// Takes path as a parameter (rather than reading state.TransitionToCluster
// directly) so tests can point it at a tmp fixture.
func parseTransitionMarker(path string) (int64, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("read transition marker: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("transition marker unexpected format: %q", string(data))
	}
	ts, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse transition timestamp %q: %w", fields[0], err)
	}
	if ts <= 0 || ts > time.Now().Unix()+60 {
		return 0, 0, fmt.Errorf("transition timestamp %d out of range", ts)
	}
	count, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, 0, fmt.Errorf("parse reboot count %q: %w", fields[1], err)
	}
	return ts, count, nil
}
