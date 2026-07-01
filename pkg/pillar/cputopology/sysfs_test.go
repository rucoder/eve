// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"os"
	"path/filepath"
	"testing"
)

// writeFile creates parent directories as needed and writes content to path.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

// buildFixtureTree builds a fake sysfs tree under dir mimicking a
// 2-physical-core, SMT2, single-socket, single-NUMA box: cpu0 & cpu1 share
// core_id 0; cpu2 & cpu3 share core_id 1. All four logical CPUs share L3
// index3/id=0 and NUMA node0.
func buildFixtureTree(t *testing.T, dir string) {
	t.Helper()

	writeFile(t, filepath.Join(dir, "cpu", "online"), "0-3\n")

	coreIDs := map[int]int{0: 0, 1: 0, 2: 1, 3: 1}
	for cpu, coreID := range coreIDs {
		base := filepath.Join(dir, "cpu", "cpu"+itoa(cpu))
		writeFile(t, filepath.Join(base, "topology", "physical_package_id"), "0\n")
		writeFile(t, filepath.Join(base, "topology", "core_id"), itoa(coreID)+"\n")
		writeFile(t, filepath.Join(base, "cache", "index3", "level"), "3\n")
		writeFile(t, filepath.Join(base, "cache", "index3", "id"), "0\n")
	}

	writeFile(t, filepath.Join(dir, "node", "node0", "cpulist"), "0-3\n")
}

// itoa avoids pulling in strconv just for test fixture path building.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	if neg {
		digits = "-" + digits
	}
	return digits
}

func TestReadSysfsCoreInfos(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	topo := BuildTopology(infos)

	if len(topo.Cores) != 2 {
		t.Fatalf("expected 2 physical cores, got %d", len(topo.Cores))
	}
	if topo.NumLCPUs != 4 {
		t.Fatalf("expected NumLCPUs == 4, got %d", topo.NumLCPUs)
	}

	var core0, core1 *PhysicalCore
	for i := range topo.Cores {
		switch topo.Cores[i].CoreID {
		case 0:
			core0 = &topo.Cores[i]
		case 1:
			core1 = &topo.Cores[i]
		}
	}
	if core0 == nil || core1 == nil {
		t.Fatalf("expected cores with CoreID 0 and 1, got %+v", topo.Cores)
	}
	if len(core0.Siblings) != 2 || core0.Siblings[0] != LCPU(0) || core0.Siblings[1] != LCPU(1) {
		t.Fatalf("expected CoreID 0 siblings {0,1}, got %v", core0.Siblings)
	}
	if len(core1.Siblings) != 2 || core1.Siblings[0] != LCPU(2) || core1.Siblings[1] != LCPU(3) {
		t.Fatalf("expected CoreID 1 siblings {2,3}, got %v", core1.Siblings)
	}

	if len(topo.L3Cores[0]) != 2 {
		t.Fatalf("expected L3Cores[0] to have 2 cores, got %d", len(topo.L3Cores[0]))
	}
	if len(topo.NUMACores[0]) != 2 {
		t.Fatalf("expected NUMACores[0] to have 2 cores, got %d", len(topo.NUMACores[0]))
	}
}

// TestReadSysfsCoreInfos_NoOnlineFile verifies that when <cpuRoot>/online is
// missing, readOnlineCPUs falls back to enumerating cpu/cpuN directories and
// all CPUs are still discovered.
func TestReadSysfsCoreInfos_NoOnlineFile(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	// Remove the online file to force the cpuN directory enumeration
	// fallback path in readOnlineCPUs.
	if err := os.Remove(filepath.Join(dir, "cpu", "online")); err != nil {
		t.Fatalf("Remove(online): %v", err)
	}

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	if len(infos) != 4 {
		t.Fatalf("expected 4 CPUs discovered via directory fallback, got %d", len(infos))
	}
	seen := map[uint]bool{}
	for _, ci := range infos {
		seen[ci.LCore] = true
	}
	for cpu := uint(0); cpu < 4; cpu++ {
		if !seen[cpu] {
			t.Fatalf("expected cpu%d to be discovered, got infos %+v", cpu, infos)
		}
	}
}

// TestReadSysfsCoreInfos_SocketDefault verifies that a missing or literal
// "-1" physical_package_id both fall back to Socket 0.
func TestReadSysfsCoreInfos_SocketDefault(t *testing.T) {
	cases := []struct {
		name          string
		writePkgIDFn  func(t *testing.T, path string)
		wantSocketVal uint
	}{
		{
			name: "missing physical_package_id file",
			writePkgIDFn: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("Remove(%s): %v", path, err)
				}
			},
			wantSocketVal: 0,
		},
		{
			name: "physical_package_id is -1",
			writePkgIDFn: func(t *testing.T, path string) {
				t.Helper()
				writeFile(t, path, "-1\n")
			},
			wantSocketVal: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			buildFixtureTree(t, dir)

			pkgIDPath := filepath.Join(dir, "cpu", "cpu0", "topology", "physical_package_id")
			tc.writePkgIDFn(t, pkgIDPath)

			infos, err := readSysfsCoreInfos(dir)
			if err != nil {
				t.Fatalf("readSysfsCoreInfos: %v", err)
			}

			var found bool
			for _, ci := range infos {
				if ci.LCore == 0 {
					found = true
					if ci.Socket != tc.wantSocketVal {
						t.Fatalf("expected cpu0 Socket == %d, got %d", tc.wantSocketVal, ci.Socket)
					}
				}
			}
			if !found {
				t.Fatalf("expected cpu0 in infos, got %+v", infos)
			}
		})
	}
}

// TestReadSysfsCoreInfos_NoL3Index verifies that when no cache/indexN
// directory has level == 3, L3ID defaults to 0.
func TestReadSysfsCoreInfos_NoL3Index(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	// Replace cpu0's L3 cache index with a non-L3 (e.g. L2) index so no
	// index with level==3 exists for cpu0.
	cacheDir := filepath.Join(dir, "cpu", "cpu0", "cache")
	if err := os.RemoveAll(cacheDir); err != nil {
		t.Fatalf("RemoveAll(%s): %v", cacheDir, err)
	}
	writeFile(t, filepath.Join(cacheDir, "index2", "level"), "2\n")
	writeFile(t, filepath.Join(cacheDir, "index2", "id"), "5\n")

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	var found bool
	for _, ci := range infos {
		if ci.LCore == 0 {
			found = true
			if ci.L3ID != 0 {
				t.Fatalf("expected cpu0 L3ID == 0 when no level==3 cache index exists, got %d", ci.L3ID)
			}
		}
	}
	if !found {
		t.Fatalf("expected cpu0 in infos, got %+v", infos)
	}
}

// TestReadSysfsCoreInfos_NoNodeDir verifies that when the sysfs root has no
// node directory at all, every CPU falls back to NUMA node 0.
func TestReadSysfsCoreInfos_NoNodeDir(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	nodeDir := filepath.Join(dir, "node")
	if err := os.RemoveAll(nodeDir); err != nil {
		t.Fatalf("RemoveAll(%s): %v", nodeDir, err)
	}

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	for _, ci := range infos {
		if ci.NUMA != 0 {
			t.Fatalf("expected NUMA == 0 for cpu%d when node dir is absent, got %d", ci.LCore, ci.NUMA)
		}
	}
}

// TestReadSysfsCoreInfos_MissingCoreID verifies that a missing core_id file
// on an online CPU is treated as a hard error.
func TestReadSysfsCoreInfos_MissingCoreID(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	coreIDPath := filepath.Join(dir, "cpu", "cpu0", "topology", "core_id")
	if err := os.Remove(coreIDPath); err != nil {
		t.Fatalf("Remove(%s): %v", coreIDPath, err)
	}

	_, err := readSysfsCoreInfos(dir)
	if err == nil {
		t.Fatalf("expected readSysfsCoreInfos to return an error when core_id is missing, got nil")
	}
}

// TestParseCPURangeList verifies multi-range parsing, e.g. "0-3,7" expands
// to [0 1 2 3 7]. This is exercised both directly (the helper is in-package
// and exported to the test via the shared package) and indirectly through
// a cpu/online fixture.
func TestParseCPURangeList(t *testing.T) {
	got, err := parseCPURangeList("0-3,7")
	if err != nil {
		t.Fatalf("parseCPURangeList: %v", err)
	}
	want := []uint{0, 1, 2, 3, 7}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

// TestReadSysfsCoreInfos_MultiRangeOnline exercises the "0-3,7" range list
// via the cpu/online fixture file, confirming readOnlineCPUs (and therefore
// parseCPURangeList) is applied correctly end-to-end.
func TestReadSysfsCoreInfos_MultiRangeOnline(t *testing.T) {
	dir := t.TempDir()
	buildFixtureTree(t, dir)

	writeFile(t, filepath.Join(dir, "cpu", "online"), "0-3,7\n")
	// cpu7 needs its own topology/cache files since buildFixtureTree only
	// wires up cpu0-cpu3.
	base := filepath.Join(dir, "cpu", "cpu7")
	writeFile(t, filepath.Join(base, "topology", "physical_package_id"), "0\n")
	writeFile(t, filepath.Join(base, "topology", "core_id"), "2\n")
	writeFile(t, filepath.Join(base, "cache", "index3", "level"), "3\n")
	writeFile(t, filepath.Join(base, "cache", "index3", "id"), "0\n")

	infos, err := readSysfsCoreInfos(dir)
	if err != nil {
		t.Fatalf("readSysfsCoreInfos: %v", err)
	}

	got := make([]uint, 0, len(infos))
	for _, ci := range infos {
		got = append(got, ci.LCore)
	}
	want := []uint{0, 1, 2, 3, 7}
	if len(got) != len(want) {
		t.Fatalf("expected LCores %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected LCores %v, got %v", want, got)
		}
	}
}
