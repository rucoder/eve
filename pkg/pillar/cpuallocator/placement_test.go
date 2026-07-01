// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	uuid "github.com/satori/go.uuid"
)

func u(s string) uuid.UUID { return uuid.NewV5(uuid.NamespaceOID, s) }

// two physical cores, SMT2, single socket/NUMA/L3
func twoCoresSMT2() *cputopology.Topology {
	return cputopology.BuildTopology([]cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 4, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 5, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
	})
}

func TestPlacer_FreeAndDedicatedSet(t *testing.T) {
	p := NewPlacer(twoCoresSMT2(), 0)
	if len(p.DedicatedSet()) != 0 {
		t.Fatalf("fresh placer must have empty dedicated set, got %v", p.DedicatedSet())
	}
	p.Free(u("nobody")) // must not panic on unknown uuid
	if len(p.DedicatedSet()) != 0 {
		t.Fatalf("still empty after Free of unknown uuid")
	}
}
