// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// TestFileExistsClassification covers the "definitely absent" vs.
// "we cannot tell" split in fileExists. Restored from the pre-
// migration test file after the code review noted these helpers
// are still live but their coverage was dropped along with the
// retired stdout parsers.
func TestFileExistsClassification(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	absent := filepath.Join(dir, "absent")
	if err := os.WriteFile(present, []byte("x"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ok, err := fileExists(present)
	if err != nil || !ok {
		t.Errorf("present: ok=%v err=%v", ok, err)
	}
	ok, err = fileExists(absent)
	if err != nil || ok {
		t.Errorf("absent: ok=%v err=%v", ok, err)
	}

	// EACCES path: unreadable parent must surface as error, not "absent".
	if os.Geteuid() == 0 {
		return
	}
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0700) })
	ok, err = fileExists(filepath.Join(blocked, "target"))
	if err == nil {
		t.Errorf("unreadable parent should surface error; got (%v, nil)", ok)
	}
}

// TestCopyKubeconfig verifies the destination-side semantics of
// copyKubeconfig: on a missing source it fails without leaving a
// partial destination; on success it produces a 0600-mode copy.
func TestCopyKubeconfig(t *testing.T) {
	dir := t.TempDir()
	dstDir := filepath.Join(dir, "dst")
	dstFile := filepath.Join(dstDir, "k3s.yaml")

	origDir, origFile := KubeconfigCopyDir, KubeconfigCopy
	KubeconfigCopyDir = dstDir
	KubeconfigCopy = dstFile
	t.Cleanup(func() {
		KubeconfigCopyDir, KubeconfigCopy = origDir, origFile
	})

	// state.K3sKubeconfig is a const path (/etc/rancher/k3s/k3s.yaml)
	// that most CI hosts don't have. When it's absent, copyKubeconfig
	// must fail cleanly with no partial dst leak.
	if _, err := os.Stat(state.K3sKubeconfig); errors.Is(err, os.ErrNotExist) {
		err := copyKubeconfig()
		if err == nil {
			t.Fatal("copyKubeconfig should fail when source is absent")
		}
		if _, err := os.Stat(dstFile); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("dst should not exist after failed copy; stat err=%v", err)
		}
		return
	}
	// If state.K3sKubeconfig happens to exist (CI machine with k3s),
	// verify the destination has correct permissions.
	if err := copyKubeconfig(); err != nil {
		t.Fatalf("copyKubeconfig: %v", err)
	}
	info, err := os.Stat(dstFile)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("dst perm = %o, want 0600", info.Mode().Perm())
	}
}

// TestWaitKubeconfigTimeoutsCleanly verifies WaitKubeconfig
// respects ctx timeout when the kubeconfig never appears.
func TestWaitKubeconfigTimeoutsCleanly(t *testing.T) {
	orig := kubeconfigPollInterval
	kubeconfigPollInterval = 5 * time.Millisecond
	t.Cleanup(func() { kubeconfigPollInterval = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	err := WaitKubeconfig(ctx)
	if err == nil {
		t.Skip("state.K3sKubeconfig exists on this host; cannot test the timeout path")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded in chain, got %v", err)
	}
}
