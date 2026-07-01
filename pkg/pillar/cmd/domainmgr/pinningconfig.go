// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"encoding/json"
	"os"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Paths are vars (not consts) so tests can point them at a temp dir.
var (
	pinConfigDir  = "/persist/pinning"
	pinConfigFile = "/persist/pinning/config.json"
)

// PolicyOptions holds the K8s CPUManager policy-option modifiers on the static
// policy that EVE supports.
type PolicyOptions struct {
	// FullPCPUsOnly allocates in whole-physical-core units: both SMT siblings
	// of a core are owned by the VM and never shared with another workload.
	FullPCPUsOnly bool `json:"full-pcpus-only"`
}

// PinningEntry is one VM's operator-editable pinning policy. Field names follow
// the Kubernetes CPUManager / Topology Manager vocabulary so the config carries
// cleanly into the future EVE-K operator port.
type PinningEntry struct {
	DisplayName string `json:"display_name"`
	// UUID duplicates the map key on purpose: it survives display_name reuse and
	// lets operators cross-reference and spot stale entries after redeployment.
	UUID  string `json:"uuid"`
	VCpus int    `json:"vcpus"`
	// CPUPolicy mirrors K8s CPUManager: "none" (shared CFS pool) or "static"
	// (exclusive allocation).
	CPUPolicy string `json:"cpu_policy"`
	// PolicyOptions refine the static policy (K8s CPUManager policy options).
	PolicyOptions *PolicyOptions `json:"policy_options,omitempty"`
	// ThreadsPerCore selects how many SMT threads of each dedicated physical
	// core become vCPUs when full-pcpus-only is set: 2 (default) exposes both
	// siblings (whole-core-smt); 1 parks the sibling for isolation
	// (one-per-core). Not a K8s term -- K8s has no single option for this.
	ThreadsPerCore int `json:"threads_per_core,omitempty"`
	// NUMATopologyPolicy mirrors the K8s Topology Manager:
	// "single-numa-node"/"restricted" (strict), "best-effort" (default), "none".
	NUMATopologyPolicy string `json:"numa_topology_policy"`
	// IOPlacement is EVE-specific (not a K8s CPU-manager concept): "dedicated"
	// (default) keeps the QEMU main-loop + iothread on the VM's dedicated cores;
	// "housekeeping" pins them to the shared non-VM pool (off the hot vCPU cores).
	IOPlacement string `json:"io_placement"`
}

// PinningConfig is the on-disk structure keyed by VM UUID.
type PinningConfig struct {
	Comment string                   `json:"_comment,omitempty"`
	Domains map[string]*PinningEntry `json:"domains"`
}

func newEmptyPinningConfig() *PinningConfig {
	return &PinningConfig{
		Comment: "EVE CPU policy, aligned with Kubernetes CPUManager/Topology Manager. Keys are VM UUIDs. " +
			"cpu_policy: none|static; policy_options.full-pcpus-only reserves whole physical cores; " +
			"threads_per_core: 2=both SMT siblings (whole core), 1=park sibling for isolation; " +
			"numa_topology_policy: single-numa-node|restricted|best-effort|none; io_placement: dedicated|housekeeping.",
		Domains: map[string]*PinningEntry{},
	}
}

func loadPinningConfig() (*PinningConfig, error) {
	data, err := os.ReadFile(pinConfigFile)
	if err != nil {
		if os.IsNotExist(err) {
			return newEmptyPinningConfig(), nil
		}
		return nil, err
	}
	cfg := newEmptyPinningConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	if cfg.Domains == nil {
		cfg.Domains = map[string]*PinningEntry{}
	}
	return cfg, nil
}

func savePinningConfig(cfg *PinningConfig) error {
	if err := os.MkdirAll(pinConfigDir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := pinConfigFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, pinConfigFile)
}

// ensureDomainInPinningConfig adds a default ("shared") entry for the domain
// if none exists. Existing entries are never overwritten so operator edits
// survive reboots/app restarts.
func ensureDomainInPinningConfig(config types.DomainConfig) {
	uuidStr := config.UUIDandVersion.UUID.String()
	cfg, err := loadPinningConfig()
	if err != nil {
		log.Errorf("ensureDomainInPinningConfig: %v (creating fresh)", err)
		cfg = newEmptyPinningConfig()
	}
	if _, exists := cfg.Domains[uuidStr]; exists {
		return
	}
	entry := &PinningEntry{
		DisplayName:        config.DisplayName,
		UUID:               uuidStr,
		VCpus:              config.VCpus,
		NUMATopologyPolicy: "best-effort",
		IOPlacement:        "dedicated",
	}
	// Conservative default that preserves today's behavior: a pinned VM gets
	// static (exclusive) but topology-blind allocation -- no full-pcpus-only,
	// so it maps to the legacy shared-pool pinning; a non-pinned VM is "none".
	if config.VmConfig.CPUsPinned {
		entry.CPUPolicy = "static"
	} else {
		entry.CPUPolicy = "none"
	}
	cfg.Domains[uuidStr] = entry
	if err := savePinningConfig(cfg); err != nil {
		log.Errorf("ensureDomainInPinningConfig: save failed: %v", err)
	}
}

// lookupPinningPolicy returns the topology-pinning policy for a domain. found
// is false when there is no entry, or the policy is "none" / static without
// full-pcpus-only -- in which case legacy exclusive pinning applies.
func lookupPinningPolicy(id uuid.UUID) (cpuallocator.PinMode, cpuallocator.NUMAPolicy, bool) {
	cfg, err := loadPinningConfig()
	if err != nil {
		log.Errorf("lookupPinningPolicy: %v", err)
		return cpuallocator.ModeShared, cpuallocator.NUMABestEffort, false
	}
	entry, ok := cfg.Domains[id.String()]
	if !ok {
		return cpuallocator.ModeShared, cpuallocator.NUMABestEffort, false
	}
	mode, found := mapPinMode(entry)
	return mode, mapNUMAPolicy(entry.NUMATopologyPolicy), found
}

// mapPinMode derives the allocator PinMode from a K8s-aligned entry. Only
// static + full-pcpus-only yields a topology-aware mode (found=true); "none"
// and static-without-full-pcpus-only fall back to legacy exclusive pinning.
func mapPinMode(e *PinningEntry) (cpuallocator.PinMode, bool) {
	fullPCPUsOnly := e.PolicyOptions != nil && e.PolicyOptions.FullPCPUsOnly
	if e.CPUPolicy != "static" || !fullPCPUsOnly {
		return cpuallocator.ModeShared, false
	}
	if e.ThreadsPerCore == 1 {
		return cpuallocator.ModeOnePerCore, true
	}
	return cpuallocator.ModeWholeCoreSMT, true // 2 or unset
}

func mapNUMAPolicy(s string) cpuallocator.NUMAPolicy {
	switch s {
	case "single-numa-node", "restricted":
		return cpuallocator.NUMALocal
	case "none":
		return cpuallocator.NUMAAllowCross
	default: // "best-effort" or unset
		return cpuallocator.NUMABestEffort
	}
}

// lookupIOPlacement returns "housekeeping" or "dedicated" (default) for a VM.
func lookupIOPlacement(id uuid.UUID) string {
	cfg, err := loadPinningConfig()
	if err != nil {
		return "dedicated"
	}
	if e, ok := cfg.Domains[id.String()]; ok && e.IOPlacement == "housekeeping" {
		return "housekeeping"
	}
	return "dedicated"
}
