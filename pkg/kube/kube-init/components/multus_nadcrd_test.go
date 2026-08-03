// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package components

import (
	"os"
	"strings"
	"testing"
)

// TestNADCRDNameMatchesManifest ties nadCRDName to the shipped manifest. If the
// CRD is ever renamed there, ApplyMultusCNI would otherwise wait out
// nadCRDTimeout on a CRD that never appears and fail the multus component.
func TestNADCRDNameMatchesManifest(t *testing.T) {
	const manifest = "../../multus-daemonset.yaml"
	b, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read %s: %v", manifest, err)
	}
	if !strings.Contains(string(b), "name: "+nadCRDName) {
		t.Errorf("%s declares no CRD named %q", manifest, nadCRDName)
	}
	// The wait only earns its keep if the manifest really does ship an instance
	// of the kind alongside the CRD that defines it.
	if !strings.Contains(string(b), "kind: NetworkAttachmentDefinition") {
		t.Errorf("%s no longer declares a NetworkAttachmentDefinition instance; "+
			"the establish-then-reapply step in ApplyMultusCNI may be obsolete", manifest)
	}
}
