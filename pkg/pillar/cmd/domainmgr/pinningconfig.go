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

// PinningEntry is one VM's operator-editable pinning policy.
type PinningEntry struct {
	DisplayName string `json:"display_name"`
	UUID        string `json:"uuid"`
	VCpus       int    `json:"vcpus"`
	// Mode: "shared" (default/legacy), "whole-core-smt", or "one-per-core".
	Mode string `json:"mode"`
	// NUMA: "local" (default) or "allow-cross".
	NUMA string `json:"numa"`
}

// PinningConfig is the on-disk structure keyed by VM UUID.
type PinningConfig struct {
	Comment string                   `json:"_comment,omitempty"`
	Domains map[string]*PinningEntry `json:"domains"`
}

func newEmptyPinningConfig() *PinningConfig {
	return &PinningConfig{
		Comment: "EVE CPU pinning policy. Keys are VM UUIDs. mode: shared|whole-core-smt|one-per-core; numa: local|allow-cross.",
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
	cfg.Domains[uuidStr] = &PinningEntry{
		DisplayName: config.DisplayName,
		UUID:        uuidStr,
		VCpus:       config.VCpus,
		Mode:        "shared",
		NUMA:        "local",
	}
	if err := savePinningConfig(cfg); err != nil {
		log.Errorf("ensureDomainInPinningConfig: save failed: %v", err)
	}
}

// lookupPinningPolicy returns the topology-pinning policy for a domain.
// found is false when there is no entry, or the mode is "shared"/unknown
// (legacy behavior applies).
func lookupPinningPolicy(id uuid.UUID) (cpuallocator.PinMode, cpuallocator.NUMAPolicy, bool) {
	cfg, err := loadPinningConfig()
	if err != nil {
		log.Errorf("lookupPinningPolicy: %v", err)
		return cpuallocator.ModeShared, cpuallocator.NUMALocal, false
	}
	entry, ok := cfg.Domains[id.String()]
	if !ok {
		return cpuallocator.ModeShared, cpuallocator.NUMALocal, false
	}
	mode, found := mapPinMode(entry.Mode)
	return mode, mapNUMAPolicy(entry.NUMA), found
}

func mapPinMode(s string) (cpuallocator.PinMode, bool) {
	switch s {
	case "whole-core-smt":
		return cpuallocator.ModeWholeCoreSMT, true
	case "one-per-core":
		return cpuallocator.ModeOnePerCore, true
	default: // "shared" or unknown => legacy
		return cpuallocator.ModeShared, false
	}
}

func mapNUMAPolicy(s string) cpuallocator.NUMAPolicy {
	if s == "allow-cross" {
		return cpuallocator.NUMAAllowCross
	}
	return cpuallocator.NUMALocal
}
