// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cpuallocator

import (
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
	WouldStarveHousekeeping
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
