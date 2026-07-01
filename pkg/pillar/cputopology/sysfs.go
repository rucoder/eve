// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cputopology

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// defaultSysfsRoot is the standard Linux sysfs location for CPU and NUMA
// node topology information.
var defaultSysfsRoot = "/sys/devices/system"

// DiscoverTopology reads CPU topology from sysfs; on failure it degrades to a
// flat single-thread-per-core topology so callers always get a usable model.
func DiscoverTopology() (*Topology, error) {
	infos, err := readSysfsCoreInfos(defaultSysfsRoot)
	if err != nil || len(infos) == 0 {
		return flatTopology(runtime.NumCPU()), err
	}
	return BuildTopology(infos), nil
}

// flatTopology builds a degraded topology of n single-thread physical
// cores, all on socket 0 / NUMA node 0. Used when sysfs discovery fails.
func flatTopology(n int) *Topology {
	if n < 1 {
		n = 1
	}
	infos := make([]CoreInfo, n)
	for i := 0; i < n; i++ {
		infos[i] = CoreInfo{LCore: uint(i), Socket: 0, CoreID: uint(i), NUMA: 0, L3ID: 0}
	}
	return BuildTopology(infos)
}

// readSysfsCoreInfos reads per-logical-CPU topology coordinates from a
// sysfs tree rooted at root (normally /sys/devices/system; tests inject a
// temp dir with the same layout).
func readSysfsCoreInfos(root string) ([]CoreInfo, error) {
	cpuRoot := filepath.Join(root, "cpu")

	online, err := readOnlineCPUs(cpuRoot)
	if err != nil {
		return nil, err
	}

	nodeOfCPU, err := readNUMAMapping(root)
	if err != nil {
		return nil, err
	}

	infos := make([]CoreInfo, 0, len(online))
	for _, cpu := range online {
		ci := CoreInfo{LCore: cpu}

		cpuDir := filepath.Join(cpuRoot, fmt.Sprintf("cpu%d", cpu))

		if v, ok := readOptionalUint(filepath.Join(cpuDir, "topology", "physical_package_id")); ok {
			ci.Socket = v
		} else {
			ci.Socket = 0
		}

		coreID, err := readRequiredUint(filepath.Join(cpuDir, "topology", "core_id"))
		if err != nil {
			return nil, fmt.Errorf("cpu%d: missing core_id: %w", cpu, err)
		}
		ci.CoreID = coreID

		ci.L3ID = readL3ID(filepath.Join(cpuDir, "cache"))

		if numa, ok := nodeOfCPU[cpu]; ok {
			ci.NUMA = numa
		} else {
			ci.NUMA = 0
		}

		infos = append(infos, ci)
	}

	return infos, nil
}

// readOnlineCPUs returns the sorted list of online logical CPU ids. It
// reads <cpuRoot>/online (a Linux cpu range list, e.g. "0-7,16") and falls
// back to enumerating <cpuRoot>/cpuN directories if that file is missing.
func readOnlineCPUs(cpuRoot string) ([]uint, error) {
	onlinePath := filepath.Join(cpuRoot, "online")
	data, err := os.ReadFile(onlinePath)
	if err == nil {
		return parseCPURangeList(string(data))
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading %s: %w", onlinePath, err)
	}

	entries, err := os.ReadDir(cpuRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", cpuRoot, err)
	}
	var cpus []uint
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, "cpu") {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(name, "cpu"), 10, 32)
		if err != nil {
			continue
		}
		cpus = append(cpus, uint(n))
	}
	sort.Slice(cpus, func(i, j int) bool { return cpus[i] < cpus[j] })
	return cpus, nil
}

// readNUMAMapping builds a map from logical CPU id to NUMA node id by
// reading <root>/node/node*/cpulist. If the node directory does not
// exist, an empty map is returned (callers fall back to NUMA node 0).
func readNUMAMapping(root string) (map[uint]uint, error) {
	nodeRoot := filepath.Join(root, "node")
	entries, err := os.ReadDir(nodeRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return map[uint]uint{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", nodeRoot, err)
	}

	mapping := map[uint]uint{}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "node") {
			continue
		}
		nodeID, err := strconv.ParseUint(strings.TrimPrefix(name, "node"), 10, 32)
		if err != nil {
			continue
		}
		cpulistPath := filepath.Join(nodeRoot, name, "cpulist")
		data, err := os.ReadFile(cpulistPath)
		if err != nil {
			continue
		}
		cpus, err := parseCPURangeList(string(data))
		if err != nil {
			continue
		}
		for _, cpu := range cpus {
			mapping[cpu] = uint(nodeID)
		}
	}
	return mapping, nil
}

// readL3ID finds the cache index under cacheDir whose level file contains
// "3" and returns its id. Returns 0 if no L3 index exists.
func readL3ID(cacheDir string) uint {
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		return 0
	}
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() || !strings.HasPrefix(name, "index") {
			continue
		}
		levelPath := filepath.Join(cacheDir, name, "level")
		level, ok := readOptionalUint(levelPath)
		if !ok || level != 3 {
			continue
		}
		idPath := filepath.Join(cacheDir, name, "id")
		if id, ok := readOptionalUint(idPath); ok {
			return id
		}
		return 0
	}
	return 0
}

// readOptionalUint reads a single unsigned integer from path, treating
// any error (missing file, parse failure) or a negative value (e.g. "-1"
// for physical_package_id on single-socket systems) as "not present".
func readOptionalUint(path string) (uint, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(data))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return uint(n), true
}

// readRequiredUint reads a single unsigned integer from path, returning
// an error if the file is missing, unparsable, or negative.
func readRequiredUint(path string) (uint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(data))
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parsing %s (%q): %w", path, s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("parsing %s: unexpected negative value %d", path, n)
	}
	return uint(n), nil
}

// parseCPURangeList parses a Linux cpu range list such as "0-3,7" into
// []uint{0,1,2,3,7}. Whitespace/newlines are trimmed before parsing.
func parseCPURangeList(s string) ([]uint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var result []uint
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if idx := strings.Index(part, "-"); idx >= 0 {
			lo, err := strconv.ParseUint(part[:idx], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing range %q: %w", part, err)
			}
			hi, err := strconv.ParseUint(part[idx+1:], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing range %q: %w", part, err)
			}
			for v := lo; v <= hi; v++ {
				result = append(result, uint(v))
			}
		} else {
			v, err := strconv.ParseUint(part, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("parsing cpu id %q: %w", part, err)
			}
			result = append(result, uint(v))
		}
	}
	return result, nil
}
