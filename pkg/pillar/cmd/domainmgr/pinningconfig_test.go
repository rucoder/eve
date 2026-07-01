// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package domainmgr

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/cpuallocator"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

func writePinningEntryForTest(t *testing.T, id uuid.UUID, mode, numa string) {
	t.Helper()
	cfg := &PinningConfig{Domains: map[string]*PinningEntry{
		id.String(): {UUID: id.String(), Mode: mode, NUMA: numa},
	}}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(pinConfigFile, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func TestPinningPolicy_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")

	id := uuid.NewV5(uuid.NamespaceOID, "vm1")
	var cfg types.DomainConfig
	cfg.DisplayName = "vm1"
	cfg.UUIDandVersion.UUID = id
	cfg.VmConfig.VCpus = 4

	ensureDomainInPinningConfig(cfg) // creates default "shared" entry
	if _, _, found := lookupPinningPolicy(id); found {
		t.Fatalf("default entry is 'shared' => policy found must be false")
	}

	writePinningEntryForTest(t, id, "whole-core-smt", "local")
	mode, numa, found := lookupPinningPolicy(id)
	if !found || mode != cpuallocator.ModeWholeCoreSMT || numa != cpuallocator.NUMALocal {
		t.Fatalf("want smt/local/found, got mode=%v numa=%v found=%v", mode, numa, found)
	}

	writePinningEntryForTest(t, id, "one-per-core", "allow-cross")
	mode, numa, found = lookupPinningPolicy(id)
	if !found || mode != cpuallocator.ModeOnePerCore || numa != cpuallocator.NUMAAllowCross {
		t.Fatalf("want one-per-core/allow-cross/found, got mode=%v numa=%v found=%v", mode, numa, found)
	}
}

func TestPinningPolicy_AbsentIsLegacy(t *testing.T) {
	dir := t.TempDir()
	pinConfigDir = dir
	pinConfigFile = filepath.Join(dir, "config.json")
	if _, _, found := lookupPinningPolicy(uuid.NewV5(uuid.NamespaceOID, "none")); found {
		t.Fatalf("absent VM must be legacy (found=false)")
	}
}
