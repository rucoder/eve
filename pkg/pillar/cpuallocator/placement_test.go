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

func TestAllocateShared_Basic(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	got, err := p.AllocateShared(u("legacy"), 3)
	if err != nil || len(got) != 3 {
		t.Fatalf("want 3 cpus, got %v err %v", got, err)
	}
	if len(p.DedicatedSet()) != 3 {
		t.Fatalf("shared alloc must be in dedicated set")
	}
}

func TestAllocateShared_SkipsReserved(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 2) // reserve lcpus 0,1
	got, _ := p.AllocateShared(u("legacy"), 1)
	if got[0] < 2 {
		t.Fatalf("must skip reserved cpus 0,1, got %v", got)
	}
}

func TestMixed_NoOverlap_TopologyThenShared(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatal(r.Message)
	}
	// collect vm1's cpus
	vm1 := map[uint32]bool{}
	for _, c := range p.dedicated[u("vm1")] {
		vm1[uint32(c)] = true
	}
	got, err := p.AllocateShared(u("legacy"), 8)
	if err != nil {
		t.Fatalf("legacy alloc should fit remaining cores: %v", err)
	}
	for _, c := range got {
		if vm1[uint32(c)] {
			t.Fatalf("shared alloc reused topology-dedicated cpu %d", c)
		}
	}
}

func TestMixed_NoOverlap_SharedThenTopology(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	shared, _ := p.AllocateShared(u("legacy"), 2)
	sharedSet := map[uint32]bool{}
	for _, c := range shared {
		sharedSet[uint32(c)] = true
	}
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatal(r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if sharedSet[uint32(c)] {
			t.Fatalf("topology alloc reused shared cpu %d", c)
		}
	}
}

// hybridTopo mirrors an Intel hybrid part: two SMT2 P-cores (lcpu 0/1 on core
// 0, 2/3 on core 1) plus four single-thread E-cores (lcpu 4..7 on cores 2..5),
// single socket/NUMA/L3.
func hybridTopo() *cputopology.Topology {
	infos := []cputopology.CoreInfo{
		{LCore: 0, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 1, Socket: 0, CoreID: 0, NUMA: 0, L3ID: 0},
		{LCore: 2, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
		{LCore: 3, Socket: 0, CoreID: 1, NUMA: 0, L3ID: 0},
	}
	for i := 0; i < 4; i++ {
		infos = append(infos, cputopology.CoreInfo{
			LCore: uint(4 + i), Socket: 0, CoreID: uint(2 + i), NUMA: 0, L3ID: 0,
		})
	}
	return cputopology.BuildTopology(infos)
}

// whole-core-smt must place a vCPU on each SMT sibling of ONE physical core and
// never satisfy the request with a single-thread (E) core, which cannot present
// threads=2. Regression for the hybrid-CPU count mismatch (ordered < vCPUs).
func TestAllocate_WholeCoreSMT_HybridSkipsSingleThread(t *testing.T) {
	p := NewPlacer(hybridTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if len(a.OrderedHostCPUs) != 2 {
		t.Fatalf("whole-core-smt must map one host CPU per vCPU (2), got %d: %v",
			len(a.OrderedHostCPUs), a.OrderedHostCPUs)
	}
	if a.Guest.Threads != 2 {
		t.Fatalf("guest threads must be 2, got %d", a.Guest.Threads)
	}
	c0 := p.topo.ByLCPU[a.OrderedHostCPUs[0]]
	c1 := p.topo.ByLCPU[a.OrderedHostCPUs[1]]
	if c0.Socket != c1.Socket || c0.CoreID != c1.CoreID {
		t.Fatalf("vCPUs not on one physical core: %v", a.OrderedHostCPUs)
	}
	if len(c0.Siblings) != 2 {
		t.Fatalf("whole-core-smt used a non-SMT core (siblings=%v)", c0.Siblings)
	}
}

// With both SMT cores unavailable and only single-thread E-cores free,
// whole-core-smt must fail cleanly with Insufficient rather than emit an
// assignment with fewer host CPUs than vCPUs.
func TestAllocate_WholeCoreSMT_OnlyECoresFree(t *testing.T) {
	p := NewPlacer(hybridTopo(), 4) // reserve lcpu 0-3 -> both P-cores excluded
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Insufficient {
		t.Fatalf("no full-SMT core free must be Insufficient, got %v (%s)", r.Status, r.Message)
	}
}

// one-per-core may use single-thread E-cores (one vCPU per physical core, no
// sibling to park).
func TestAllocate_OnePerCore_UsesSingleThreadCores(t *testing.T) {
	p := NewPlacer(hybridTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeOnePerCore, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	a := r.Assignment
	if len(a.OrderedHostCPUs) != 4 {
		t.Fatalf("one-per-core must map one host CPU per vCPU (4), got %v", a.OrderedHostCPUs)
	}
	usedECore := false
	for _, c := range a.OrderedHostCPUs {
		if len(p.topo.ByLCPU[c].Siblings) == 1 {
			usedECore = true
		}
	}
	if !usedECore {
		t.Fatalf("one-per-core should be able to use single-thread cores: %v", a.OrderedHostCPUs)
	}
}

// A whole-core-smt VM and a one-per-core VM must coexist on a hybrid host with
// no physical core shared between them.
func TestAllocate_Hybrid_Coexistence(t *testing.T) {
	p := NewPlacer(hybridTopo(), 0)
	if r := p.Allocate(Request{UUID: u("smt"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("whole-core-smt vm should succeed, got %v (%s)", r.Status, r.Message)
	}
	if r := p.Allocate(Request{UUID: u("opc"), NumVCPUs: 4, Mode: ModeOnePerCore, NUMA: NUMALocal}); r.Status != Success {
		t.Fatalf("one-per-core vm should coexist, got %v (%s)", r.Status, r.Message)
	}
	seen := map[cputopology.LCPU]bool{}
	for _, c := range p.dedicated[u("smt")] {
		seen[c] = true
	}
	for _, c := range p.dedicated[u("opc")] {
		if seen[c] {
			t.Fatalf("core sharing between VMs at lcpu %d", c)
		}
	}
}

// best-effort stays within one NUMA node when the request fits.
func TestAllocate_BestEffort_FitsSingleNode(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("want Success, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.NUMANodes) != 1 {
		t.Fatalf("best-effort should stay on one node when it fits, got %v", r.Assignment.NUMANodes)
	}
}

// best-effort falls back to spanning nodes rather than failing when no single
// node fits (contrast NUMALocal, which returns NeedsRebalance here).
func TestAllocate_BestEffort_FallsBackToSpanning(t *testing.T) {
	p := NewPlacer(twoNodesOneCoreEach(), 0)
	r := p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMABestEffort})
	if r.Status != Success {
		t.Fatalf("best-effort must fall back to spanning, got %v (%s)", r.Status, r.Message)
	}
	if len(r.Assignment.NUMANodes) != 2 {
		t.Fatalf("expected spanning 2 nodes, got %v", r.Assignment.NUMANodes)
	}
}

// Reserve seeds a running VM's cores so a fresh Placer (post-restart) does not
// hand them to another VM; Free returns them to the pool.
func TestReserve_BlocksAndFrees(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0) // 16 lcpus
	p.Reserve(u("running"), []uint32{0, 1, 2, 3})
	if len(p.FreeCPUs()) != 16-4 {
		t.Fatalf("reserved cpus must be excluded from FreeCPUs, got %d", len(p.FreeCPUs()))
	}
	r := p.Allocate(Request{UUID: u("new"), NumVCPUs: 2, Mode: ModeWholeCoreSMT, NUMA: NUMALocal})
	if r.Status != Success {
		t.Fatalf("new VM should allocate around reserved cores, got %v (%s)", r.Status, r.Message)
	}
	for _, c := range r.Assignment.OrderedHostCPUs {
		if c <= 3 {
			t.Fatalf("new VM got a reserved core %d", c)
		}
	}
	p.Reserve(u("running"), []uint32{4, 5}) // already known -> no-op
	p.Free(u("running"))
	if len(p.FreeCPUs()) != 16-len(r.Assignment.OrderedHostCPUs) {
		t.Fatalf("after Free, reserved cores must return to the free pool")
	}
}

func TestFreeCPUs_ExcludesBoth(t *testing.T) {
	p := NewPlacer(twoSocketTopo(), 0)                                                            // 16 lcpus total
	_ = p.Allocate(Request{UUID: u("vm1"), NumVCPUs: 4, Mode: ModeWholeCoreSMT, NUMA: NUMALocal}) // 4 lcpus
	_, _ = p.AllocateShared(u("legacy"), 2)                                                       // 2 lcpus
	free := p.FreeCPUs()
	if len(free) != 16-4-2 {
		t.Fatalf("FreeCPUs should exclude both allocations: got %d", len(free))
	}
	p.Free(u("vm1"))
	p.Free(u("legacy"))
	if len(p.FreeCPUs()) != 16 {
		t.Fatalf("after Free all cpus should be free")
	}
}
