// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
	"fmt"
	"sort"
	"sync"

	"github.com/lf-edge/eve/pkg/pillar/cputopology"
	uuid "github.com/satori/go.uuid"
)

// PinMode selects how a pinned VM's vCPUs map onto physical cores.
type PinMode int

const (
	ModeShared       PinMode = iota // not topology-pinned (legacy shared pool)
	ModeWholeCoreSMT                // both SMT siblings of each core are vCPUs (guest threads=2)
	ModeOnePerCore                  // one vCPU per physical core; sibling parked (guest threads=1)
)

// NUMAPolicy selects NUMA placement strictness.
type NUMAPolicy int

const (
	NUMALocal      NUMAPolicy = iota // all cores within one NUMA node (else NeedsRebalance)
	NUMAAllowCross                   // may span NUMA nodes
)

// Request is a single VM's placement request.
type Request struct {
	UUID     uuid.UUID
	NumVCPUs int
	Mode     PinMode
	NUMA     NUMAPolicy
}

// GuestTopology is the guest-visible -smp topology to emit.
type GuestTopology struct {
	Sockets int
	Cores   int
	Threads int
}

// Assignment is the result of a successful placement.
type Assignment struct {
	OrderedHostCPUs []cputopology.LCPU // guest vCPU i -> OrderedHostCPUs[i]
	Guest           GuestTopology
	ParkedCPUs      []cputopology.LCPU // siblings held idle (ModeOnePerCore)
	NUMANodes       []uint
}

// Status is the outcome class of a placement attempt.
type Status int

const (
	Success Status = iota
	NeedsRebalance
	Insufficient
	InvalidRequest
)

// Result carries the outcome of Allocate.
type Result struct {
	Status     Status
	Assignment *Assignment
	Message    string
}

// Placer owns dedicated-core bookkeeping and performs topology-aware
// placement. All methods are safe for concurrent use.
type Placer struct {
	mu                sync.Mutex
	topo              *cputopology.Topology
	numReservedForEVE uint32
	// dedicated maps UUID -> every LCPU it holds (vCPU cores + parked).
	dedicated map[uuid.UUID][]cputopology.LCPU
}

// NewPlacer creates a Placer over the given topology, reserving the lowest
// numReservedForEVE logical CPUs for EVE housekeeping.
func NewPlacer(topo *cputopology.Topology, numReservedForEVE uint32) *Placer {
	return &Placer{
		topo:              topo,
		numReservedForEVE: numReservedForEVE,
		dedicated:         map[uuid.UUID][]cputopology.LCPU{},
	}
}

// Free releases all cores dedicated to id. Safe to call for an unknown id.
func (p *Placer) Free(id uuid.UUID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.dedicated, id)
}

// DedicatedSet returns the union of all dedicated LCPUs (vCPU + parked),
// sorted ascending.
func (p *Placer) DedicatedSet() []cputopology.LCPU {
	p.mu.Lock()
	defer p.mu.Unlock()
	seen := map[cputopology.LCPU]bool{}
	for _, cs := range p.dedicated {
		for _, c := range cs {
			seen[c] = true
		}
	}
	out := make([]cputopology.LCPU, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// coreIsFree reports whether none of a physical core's siblings are already
// dedicated and none fall in the EVE-reserved low range.
func (p *Placer) coreIsFree(pc *cputopology.PhysicalCore, dedicated map[cputopology.LCPU]bool) bool {
	for _, s := range pc.Siblings {
		if uint32(s) < p.numReservedForEVE {
			return false
		}
		if dedicated[s] {
			return false
		}
	}
	return true
}

// dedicatedLookup returns a membership set of all dedicated LCPUs.
func (p *Placer) dedicatedLookup() map[cputopology.LCPU]bool {
	m := map[cputopology.LCPU]bool{}
	for _, cs := range p.dedicated {
		for _, c := range cs {
			m[c] = true
		}
	}
	return m
}

// AllocateShared allocates n lowest-numbered free logical CPUs for a legacy
// (non-topology) pinned VM. Recorded in the same bookkeeping as topology
// allocations, so the two can never overlap. Skips the EVE-reserved low range.
func (p *Placer) AllocateShared(id uuid.UUID, n int) ([]cputopology.LCPU, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.dedicated[id]; ok {
		return nil, fmt.Errorf("multiple allocations for %s", id)
	}
	if n <= 0 {
		return nil, fmt.Errorf("AllocateShared: n must be > 0")
	}
	ded := p.dedicatedLookup()
	var picked []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		if uint32(c) < p.numReservedForEVE || ded[c] {
			continue
		}
		picked = append(picked, c)
		if len(picked) == n {
			break
		}
	}
	if len(picked) < n {
		return nil, fmt.Errorf("insufficient CPUs: need %d, have %d free", n, len(picked))
	}
	p.dedicated[id] = picked
	return picked, nil
}

// FreeCPUs returns all logical CPUs not dedicated to any VM (topology OR
// shared), INCLUDING the EVE-reserved low range — matching the legacy
// GetAllFree semantics used for non-pinned VM cpusets and emulator housekeeping.
func (p *Placer) FreeCPUs() []cputopology.LCPU {
	p.mu.Lock()
	defer p.mu.Unlock()
	ded := p.dedicatedLookup()
	var out []cputopology.LCPU
	for _, c := range p.allLCPUsSorted() {
		if !ded[c] {
			out = append(out, c)
		}
	}
	return out
}

// allLCPUsSorted returns every logical CPU in the topology, ascending.
// Caller must hold p.mu.
func (p *Placer) allLCPUsSorted() []cputopology.LCPU {
	var all []cputopology.LCPU
	for i := range p.topo.Cores {
		all = append(all, p.topo.Cores[i].Siblings...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return all
}

// Allocate performs topology-aware placement for one VM.
func (p *Placer) Allocate(r Request) Result {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.dedicated[r.UUID]; ok {
		return Result{Status: InvalidRequest, Message: fmt.Sprintf("already allocated for %s", r.UUID)}
	}
	if r.NumVCPUs <= 0 {
		return Result{Status: InvalidRequest, Message: "NumVCPUs must be > 0"}
	}

	var coresNeeded, threads int
	switch r.Mode {
	case ModeWholeCoreSMT:
		if r.NumVCPUs%2 != 0 {
			return Result{Status: InvalidRequest, Message: "whole-core-smt requires an even vCPU count"}
		}
		coresNeeded = r.NumVCPUs / 2
		threads = 2
	case ModeOnePerCore:
		coresNeeded = r.NumVCPUs
		threads = 1
	default:
		return Result{Status: InvalidRequest, Message: "Allocate is only for pinned modes"}
	}

	dedicated := p.dedicatedLookup()

	// Free cores grouped by NUMA node, preserving deterministic order.
	freeByNUMA := map[uint][]*cputopology.PhysicalCore{}
	numaOrder := []uint{}
	totalFree := 0
	for i := range p.topo.Cores {
		pc := &p.topo.Cores[i]
		if !p.coreIsFree(pc, dedicated) {
			continue
		}
		if _, ok := freeByNUMA[pc.NUMA]; !ok {
			numaOrder = append(numaOrder, pc.NUMA)
		}
		freeByNUMA[pc.NUMA] = append(freeByNUMA[pc.NUMA], pc)
		totalFree++
	}
	sort.Slice(numaOrder, func(i, j int) bool { return numaOrder[i] < numaOrder[j] })

	if totalFree < coresNeeded {
		return Result{Status: Insufficient, Message: fmt.Sprintf("need %d free cores, have %d", coresNeeded, totalFree)}
	}

	var chosen []*cputopology.PhysicalCore
	if r.NUMA == NUMALocal {
		for _, n := range numaOrder {
			cand := freeByNUMA[n]
			if len(cand) >= coresNeeded {
				chosen = pickCores(cand, coresNeeded)
				break
			}
		}
		if chosen == nil {
			return Result{Status: NeedsRebalance, Message: fmt.Sprintf("need %d cores in one NUMA node; none has enough (total free %d)", coresNeeded, totalFree)}
		}
	} else {
		all := []*cputopology.PhysicalCore{}
		for _, n := range numaOrder {
			all = append(all, freeByNUMA[n]...)
		}
		chosen = pickCores(all, coresNeeded)
	}

	var ordered, parked []cputopology.LCPU
	nodeSet := map[uint]bool{}
	for _, pc := range chosen {
		nodeSet[pc.NUMA] = true
		switch r.Mode {
		case ModeWholeCoreSMT:
			ordered = append(ordered, pc.Siblings...)
		case ModeOnePerCore:
			ordered = append(ordered, pc.Siblings[0])
			if len(pc.Siblings) > 1 {
				parked = append(parked, pc.Siblings[1:]...)
			}
		}
	}

	nodes := make([]uint, 0, len(nodeSet))
	for n := range nodeSet {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i] < nodes[j] })

	full := append(append([]cputopology.LCPU{}, ordered...), parked...)
	p.dedicated[r.UUID] = full

	return Result{
		Status: Success,
		Assignment: &Assignment{
			OrderedHostCPUs: ordered,
			Guest:           GuestTopology{Sockets: 1, Cores: coresNeeded, Threads: threads},
			ParkedCPUs:      parked,
			NUMANodes:       nodes,
		},
	}
}

// pickCores returns the first n cores from an already-deterministic slice.
func pickCores(cores []*cputopology.PhysicalCore, n int) []*cputopology.PhysicalCore {
	out := make([]*cputopology.PhysicalCore, n)
	copy(out, cores[:n])
	return out
}
