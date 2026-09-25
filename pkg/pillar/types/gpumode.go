// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

const gpuModeDir = "/persist/gpu"

// GPUMode names how an app that has a GPU assigned should get it.
const (
	GPUModePassthrough = "passthrough"
	GPUModeVirtual     = "virtual"
)

type gpuModeFile struct {
	Mode string `json:"mode"`
}

// GPUModeFor reports whether this domain takes the GPU by passthrough or
// gets a virtual one. It only reads - it never creates or modifies
// anything - so every reader of the operator's choice (hypervisor,
// cmd/monitor's status reporting) stays side-effect-free; see
// GPUModeEnsureDefault for the write, which domainmgr calls explicitly.
func GPUModeFor(key string) string { return GPUModeRead(gpuModeDir, key) }

// GPUModeRead is GPUModeFor with the directory overridable for tests.
func GPUModeRead(dir, key string) string {
	path := filepath.Join(dir, key+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return GPUModePassthrough
	}
	var f gpuModeFile
	// Anything unreadable - truncated by a power cut, hand-edited to
	// nonsense - falls back to the default rather than guessing. Guessing
	// the other way round would hand an operator's GPU to a VM silently.
	if err := json.Unmarshal(b, &f); err == nil && f.Mode == GPUModeVirtual {
		return GPUModeVirtual
	}
	return GPUModePassthrough
}

// GPUModeEnsureDefault creates <production dir>/key.json with the
// passthrough default if it does not already exist, so an operator has a
// discoverable place to flip a domain into virtual mode without knowing the
// path or the schema. It never touches an existing file, including a
// malformed one - self-healing a hand-edited file could destroy operator
// intent. domainmgr calls this explicitly at the one place that decides
// whether to reserve the GPU; readers (GPUModeFor/GPUModeRead) never do.
func GPUModeEnsureDefault(key string) { GPUModeEnsureDefaultAt(gpuModeDir, key) }

// GPUModeEnsureDefaultAt is GPUModeEnsureDefault with the directory
// overridable for tests.
func GPUModeEnsureDefaultAt(dir, key string) {
	path := filepath.Join(dir, key+".json")
	if _, err := os.Stat(path); err == nil {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		logrus.Warnf("GPUModeEnsureDefaultAt(%s): MkdirAll(%s): %v", key, dir, err)
		return
	}
	b, _ := json.Marshal(gpuModeFile{Mode: GPUModePassthrough})
	if err := os.WriteFile(path, b, 0644); err != nil {
		logrus.Warnf("GPUModeEnsureDefaultAt(%s): WriteFile(%s): %v", key, path, err)
	}
}
