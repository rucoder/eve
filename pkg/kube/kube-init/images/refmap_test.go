// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizeRef(t *testing.T) {
	cases := map[string]string{
		"quay.io/kubevirt/virt-operator:v1.7.3":        "quay.io_kubevirt_virt-operator_v1.7.3",
		"docker.io/longhornio/longhorn-manager:v1.9.1": "docker.io_longhornio_longhorn-manager_v1.9.1",
	}
	for in, want := range cases {
		if got := sanitizeRef(in); got != want {
			t.Errorf("sanitizeRef(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLoadRefMapMissingFileIsEmpty(t *testing.T) {
	m, err := loadRefMap(filepath.Join(t.TempDir(), "nope.list"))
	if err != nil {
		t.Fatalf("want nil err for missing catalog, got %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("want empty map, got %d entries", len(m))
	}
}

func TestLoadRefMap(t *testing.T) {
	dir := t.TempDir()
	list := filepath.Join(dir, "upstream-images.list")
	if err := os.WriteFile(list, []byte(
		"# pinned catalog\n"+
			"quay.io/kubevirt/virt-operator:v1.7.3@sha256:176c2c36cd1def7794f52eb08e05010ebf17885debb109a72b4d91bd8da06bea\n"+
			"\n"+
			"docker.io/longhornio/longhorn-ui:v1.9.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	m, err := loadRefMap(list)
	if err != nil {
		t.Fatal(err)
	}
	// The digest pin is stripped from both the sanitized key and the
	// real ref: kubelet resolves by name:tag.
	if m["quay.io_kubevirt_virt-operator_v1.7.3"] != "quay.io/kubevirt/virt-operator:v1.7.3" {
		t.Errorf("bad map: %+v", m)
	}
	if m["docker.io_longhornio_longhorn-ui_v1.9.1"] != "docker.io/longhornio/longhorn-ui:v1.9.1" {
		t.Errorf("bad map: %+v", m)
	}
	if len(m) != 2 {
		t.Errorf("want 2 entries, got %d: %+v", len(m), m)
	}
}
