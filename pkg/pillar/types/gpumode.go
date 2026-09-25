// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"encoding/json"
	"os"
	"path/filepath"
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

// GPUModeFor reports whether this domain takes the GPU by passthrough or gets
// a virtual one, creating the file with the default if it does not exist so
// the operator never has to know the UUID or the schema.
func GPUModeFor(domain string) string { return GPUModeAt(gpuModeDir, domain) }

// GPUModeAt is GPUModeFor with the directory overridable for tests.
func GPUModeAt(dir, domain string) string {
	path := filepath.Join(dir, domain+".json")
	if b, err := os.ReadFile(path); err == nil {
		var f gpuModeFile
		// Anything unreadable - truncated by a power cut, hand-edited to
		// nonsense - falls back to the default rather than guessing. Guessing
		// the other way round would hand an operator's GPU to a VM silently.
		if err := json.Unmarshal(b, &f); err == nil && f.Mode == GPUModeVirtual {
			return GPUModeVirtual
		}
		return GPUModePassthrough
	}
	// Default is passthrough: an app that has the iGPU assigned today keeps
	// behaving exactly as it does today.
	if err := os.MkdirAll(dir, 0755); err == nil {
		b, _ := json.Marshal(gpuModeFile{Mode: GPUModePassthrough})
		_ = os.WriteFile(path, b, 0644)
	}
	return GPUModePassthrough
}
