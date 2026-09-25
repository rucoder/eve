// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"os"
	"path/filepath"
	"testing"
)

// Absent file: domainmgr writes the default so the operator never has to know
// the path or the schema, and the default preserves today's behaviour.
func TestGPUModeCreatesTheFileWithPassthroughDefault(t *testing.T) {
	dir := t.TempDir()
	mode := GPUModeAt(dir, "vm1.1.1")
	if mode != "passthrough" {
		t.Errorf("default must be passthrough for backward compatibility, got %q", mode)
	}
	if _, err := os.Stat(filepath.Join(dir, "vm1.1.1.json")); err != nil {
		t.Errorf("the file should have been created: %v", err)
	}
}

// The operator flipped it.
func TestGPUModeReadsVirtual(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "vm1.1.1.json"), []byte(`{"mode":"virtual"}`), 0644)
	if got := GPUModeAt(dir, "vm1.1.1"); got != "virtual" {
		t.Errorf("got %q, want virtual", got)
	}
}

// Hand-edited to nonsense, or truncated by a power cut. Fall back to the
// documented default and keep running; do not crash domainmgr and do not
// silently pick the other mode.
func TestGPUModeFallsBackOnGarbage(t *testing.T) {
	for _, body := range []string{`{"mode":`, `{"mode":"banana"}`, ``, `null`} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "vm1.1.1.json"), []byte(body), 0644)
		if got := GPUModeAt(dir, "vm1.1.1"); got != "passthrough" {
			t.Errorf("body %q: got %q, want passthrough", body, got)
		}
	}
}
