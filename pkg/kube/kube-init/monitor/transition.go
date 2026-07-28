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
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubeclient"
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
	nodes, err := kubeclient.Default().Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0
	}
	return countReady(nodes.Items)
}

// countReady is the pure half of countReadyNodes, factored out for
// unit tests. Counts nodes whose Ready condition is True.
func countReady(nodes []corev1.Node) int {
	count := 0
	for _, n := range nodes {
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
				count++
				break
			}
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
