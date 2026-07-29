// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package prereqs

import "testing"

// countCPUList feeds the Apply concurrency cap, so a misparse silently
// changes how much work a first boot runs at once.
func TestCountCPUList(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0", 1},
		{"0-7", 8},
		{"0-0", 1},
		{"0,2-4", 4},
		{"0,1,2", 3},
		{"2-4,8,10-11", 6},
		{"", 0},
		{"garbage", 0},
		{"4-2", 0},   // reversed range contributes nothing
		{"0-3,x", 4}, // malformed segment skipped, valid one kept
	}
	for _, c := range cases {
		if got := countCPUList(c.in); got != c.want {
			t.Errorf("countCPUList(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// Restore must tolerate the nil loan WidenKubeCPUs returns when there is
// nothing to widen, since the FSM calls it unconditionally.
func TestCPUSetLoanRestoreIsSafeWhenNil(t *testing.T) {
	var loan *CPUSetLoan
	loan.Restore()
	loan.Restore()

	empty := &CPUSetLoan{saved: map[string]string{}}
	empty.Restore()
}
