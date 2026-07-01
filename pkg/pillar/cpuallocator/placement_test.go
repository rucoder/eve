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

// 2 sockets x 4 physical cores x SMT2, distinct L3/NUMA per socket.
func twoSocketTopo() *cputopology.Topology {
	var infos []cputopology.CoreInfo
	lc := uint(0)
	for socket := uint(0); socket < 2; socket++ {
		for core := uint(0); core < 4; core++ {
			for thread := 0; thread < 2; thread++ {
				infos = append(infos, cputopology.CoreInfo{
					LCore: lc, Socket: socket, CoreID: core, NUMA: socket, L3ID: socket,
				})
				lc++
			}
		}
	}
	return cputopology.BuildTopology(infos)
}

// one physical core per NUMA node (forces NeedsRebalance for a 2-core request).
func twoNodesOneCoreEach() *cputopology.Topology {
	return cputopology.BuildTopology([]cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 2, Socket: 1, CoreID: 0, NUMA: 1, L3ID: 1},
		{LCore: 3, Socket: 1, CoreID: 0, NUMA: 1, L3ID: 1},
	})
}

func TestAllocate_WholeCoreSMT_NUMALocal(t *testing.T) {
	topo := twoSocketTopo()
	p := NewPlacer(topo, 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if a.Guest != (GuestTopology{Sockets: 1, Cores: 2, Threads: 2}) {
		t.Fatalf("guest topo want 1/2/2, got %+v", a.Guest)
	}
	if len(a.OrderedHostCPUs) != 4 {
		t.Fatalf("want 4 host cpus, got %d", len(a.OrderedHostCPUs))
	}
	n := topo.ByLCPU[a.OrderedHostCPUs[0]].NUMA
	for _, c := range a.OrderedHostCPUs {
		if topo.ByLCPU[c].NUMA != n {
			t.Fatalf("NUMA-local violated: %v", a.OrderedHostCPUs)
		}
	}
	// vCPU pair (0,1) must be SMT siblings (same physical core).
	if topo.ByLCPU[a.OrderedHostCPUs[0]].CoreID != topo.ByLCPU[a.OrderedHostCPUs[1]].CoreID {
		t.Fatalf("vcpu pair 0,1 not sibling-mapped: %v", a.OrderedHostCPUs)
	}
}

func TestAllocate_OddRejectedForSMT(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 3, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != InvalidRequest {
		t.Fatalf("odd vcpu in SMT mode must be InvalidRequest, got %v", r.Status)
	}
}

func TestAllocate_OnePerCore_ParksSiblings(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if r.Assignment.Guest.Threads != 1 {
		t.Fatalf("one-per-core guest threads must be 1, got %d", r.Assignment.Guest.Threads)
	}
	if len(r.Assignment.ParkedCPUs) != 2 {
		t.Fatalf("want 2 parked siblings, got %v", r.Assignment.ParkedCPUs)
	}
	if len(p.DedicatedSet()) != 4 {
		t.Fatalf("dedicated set must include parked siblings (want 4), got %d", len(p.DedicatedSet()))
	}
}

func TestAllocate_NoCrossVMCoreSharing(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("vm1 should succeed, got %v", r.Status)
	}
	r2 := p.Allocate(Request{UUID: u("vm2"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r2.Status != Success {
		t.Fatalf("vm2 should succeed (room remains), got %v (%s)", r2.Status, r2.Message)
	}
	seen := map[cputopology.LCPU]bool{}
	for _, c := range p.dedicated[u("vm1")] {
		seen[c] = true
	}
	for _, c := range p.dedicated[u("vm2")] {
		if seen[c] {
			t.Fatalf("cross-VM core sharing at lcpu %d", c)
		}
	}
}

func TestAllocate_NeedsRebalance(t *testing.T) {
	// Two NUMA nodes, one core each; a 2-core NUMA-local request can't fit in
	// one node even though total free (2) is enough.
	p := NewPlacer(twoNodesOneCoreEach(), 0)
	r := p.Allocate(Request{UUID: u("b"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != NeedsRebalance {
		t.Fatalf("want NeedsRebalance, got %v (%s)", r.Status, r.Message)
	}
}

func TestAllocate_InsufficientTotal(t *testing.T) {
	p := NewPlacer(twoNodesOneCoreEach(), 0)
	// 6 vCPUs = 3 cores, but only 2 physical cores exist anywhere.
	r := p.Allocate(Request{UUID: u("x"), NumVCPUs: 6, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Insufficient {
		t.Fatalf("want Insufficient, got %v (%s)", r.Status, r.Message)
	}
}

func oneCoreTopo() *cputopology.Topology {
	return cputopology.BuildTopology([]cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
	})
}

func TestAllocate_ReservedCPUsExcluded(t *testing.T) {
	// twoCoresSMT2 cores: c0={0,4}, c1={1,5}. Reserve lcpu 0 -> core {0,4}
	// excluded wholesale, leaving 1 free core; a 2-core request must not fit.
	p := NewPlacer(twoCoresSMT2(), 1)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Insufficient {
		t.Fatalf("reserved core must be excluded -> Insufficient, got %v (%s)", r.Status, r.Message)
	}
	r := p.Allocate(Request{UUID: u("vm2"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("1-core request should fit on the non-reserved core, got %v (%s)", r.Status, r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if c == 0 || c == 4 {
			t.Fatalf("allocated a reserved core lcpu %d", c)
		}
	}
}

func TestAllocate_DoubleAllocateRejected(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("first allocate should succeed, got %v", r.Status)
	}
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != InvalidRequest {
		t.Fatalf("re-allocating same UUID must be InvalidRequest, got %v (%s)", r.Status, r.Message)
	}
}

func TestAllocate_AllowCrossSpansNodes(t *testing.T) {
	p := NewPlacer(twoNodesOneCoreEach(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMAAllowCross})
	if r.Status != Success {
		t.Fatalf("allow-cross should span both nodes and succeed, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.NUMANodes) != 2 {
		t.Fatalf("want assignment spanning 2 NUMA nodes, got %v", r.Assignment.NUMANodes)
	}
	if len(r.Assignment.OrderedHostCPUs) != 4 {
		t.Fatalf("want 4 host cpus, got %d", len(r.Assignment.OrderedHostCPUs))
	}
}

func TestAllocate_ParkedSiblingBlocksReuse(t *testing.T) {
	p := NewPlacer(oneCoreTopo(), 0)
	if r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("first one-per-core should succeed, got %v", r.Status)
	}
	r := p.Allocate(Request{UUID: u("vm2"), NumVCPUs: 1, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Insufficient {
		t.Fatalf("parked sibling must block core reuse -> Insufficient, got %v (%s)", r.Status, r.Message)
	}
}
