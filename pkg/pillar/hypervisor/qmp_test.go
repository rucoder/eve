// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import "testing"

func TestParseVcpuThreadIDs(t *testing.T) {
	raw := []byte(`{"return":[{"cpu-index":0,"thread-id":101},{"cpu-index":1,"thread-id":102}]}`)
	got, err := parseVcpuThreadIDs(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 101 || got[1] != 102 {
		t.Fatalf("got %v", got)
	}
	// out-of-range cpu-index must error
	if _, err := parseVcpuThreadIDs([]byte(`{"return":[{"cpu-index":5,"thread-id":9}]}`)); err == nil {
		t.Fatal("expected error for out-of-range cpu-index")
	}
	if _, err := parseVcpuThreadIDs([]byte(`{"return":[{"cpu-index":0,"thread-id":1},{"cpu-index":0,"thread-id":2}]}`)); err == nil {
		t.Fatal("expected error for duplicate cpu-index")
	}
	if _, err := parseVcpuThreadIDs([]byte(`{"return":[{"cpu-index":0,"thread-id":0}]}`)); err == nil {
		t.Fatal("expected error for zero thread-id")
	}
}
