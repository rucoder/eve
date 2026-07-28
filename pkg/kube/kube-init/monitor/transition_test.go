// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// TestParseTransitionMarker covers the timestamp+counter parse +
// sanity-check used by CheckClusterTransitionDone. The validation
// we own:
//   - Two whitespace-separated fields required.
//   - Timestamp must be > 0.
//   - Timestamp must not be >60s in the future.
//   - Reboot count must parse as an int.
//
// Restored from the pre-migration test file after the code review
// noted that parseTransitionMarker is still live but its coverage
// was dropped along with kubectl-stdout parsers.
func TestParseTransitionMarker(t *testing.T) {
	now := time.Now().Unix()

	cases := []struct {
		name    string
		content string
		wantTS  int64
		wantCnt int
		wantErr bool
	}{
		{
			name:    "valid recent",
			content: fmt.Sprintf("%d 2", now-30),
			wantTS:  now - 30,
			wantCnt: 2,
		},
		{
			name:    "single field rejected",
			content: fmt.Sprintf("%d", now),
			wantErr: true,
		},
		{
			name:    "empty file rejected",
			content: "",
			wantErr: true,
		},
		{
			name:    "non-numeric timestamp rejected",
			content: "notanumber 1",
			wantErr: true,
		},
		{
			name:    "non-numeric count rejected",
			content: fmt.Sprintf("%d bogus", now),
			wantErr: true,
		},
		{
			name:    "zero timestamp rejected",
			content: "0 1",
			wantErr: true,
		},
		{
			name:    "negative timestamp rejected",
			content: "-5 1",
			wantErr: true,
		},
		{
			name:    "more than 60s in the future rejected",
			content: fmt.Sprintf("%d 1", now+120),
			wantErr: true,
		},
		{
			name:    "60s tolerance accepted",
			content: fmt.Sprintf("%d 1", now+30),
			wantTS:  now + 30,
			wantCnt: 1,
		},
		{
			name:    "trailing whitespace tolerated",
			content: fmt.Sprintf("  %d   3  ", now-10),
			wantTS:  now - 10,
			wantCnt: 3,
		},
		{
			name:    "extra fields tolerated (first two win)",
			content: fmt.Sprintf("%d 1 extra-junk", now-5),
			wantTS:  now - 5,
			wantCnt: 1,
		},
	}

	dir := t.TempDir()
	tmp := dir + "/marker"
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(tmp, []byte(c.content), 0644); err != nil {
				t.Fatalf("seed: %v", err)
			}
			ts, cnt, err := parseTransitionMarker(tmp)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, c.wantErr)
			}
			if c.wantErr {
				return
			}
			if ts != c.wantTS {
				t.Errorf("ts = %d, want %d", ts, c.wantTS)
			}
			if cnt != c.wantCnt {
				t.Errorf("cnt = %d, want %d", cnt, c.wantCnt)
			}
		})
	}

	// missing file → distinct error surface (os.ReadFile fails before
	// any field parsing runs).
	if _, _, err := parseTransitionMarker(dir + "/does-not-exist"); err == nil {
		t.Errorf("missing file: expected error, got nil")
	}
}
