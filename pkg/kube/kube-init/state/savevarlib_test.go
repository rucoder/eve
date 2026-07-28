// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyTreeRoundTrip(t *testing.T) {
	srcRoot := t.TempDir()
	dstRoot := t.TempDir()

	if err := os.MkdirAll(filepath.Join(srcRoot, "a/b"), 0755); err != nil {
		t.Fatalf("mkdir src tree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "a/b/file.txt"),
		[]byte("payload"), 0640); err != nil {
		t.Fatalf("write fixture file: %v", err)
	}
	if err := os.Symlink("b/file.txt", filepath.Join(srcRoot, "a/link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if err := copyTree(srcRoot+"/.", dstRoot+"/", "test"); err != nil {
		t.Fatalf("copyTree: %v", err)
	}

	// File content preserved.
	got, err := os.ReadFile(filepath.Join(dstRoot, "a/b/file.txt"))
	if err != nil {
		t.Fatalf("read copied file: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("copied file content = %q, want %q", string(got), "payload")
	}

	// Permission bits preserved (cp -a).
	info, err := os.Stat(filepath.Join(dstRoot, "a/b/file.txt"))
	if err != nil {
		t.Fatalf("stat copied file: %v", err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("copied file perm = %o, want 0640", info.Mode().Perm())
	}

	// Symlink preserved as a symlink AND its target string survived.
	linkPath := filepath.Join(dstRoot, "a/link")
	li, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat copied symlink: %v", err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink was not preserved as a symlink: mode=%v", li.Mode())
	}
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if target != "b/file.txt" {
		t.Errorf("symlink target = %q, want %q", target, "b/file.txt")
	}
}

func TestCopyTreeMissingSource(t *testing.T) {
	dst := t.TempDir()
	err := copyTree("/nonexistent/path/.", dst+"/", "test")
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
}

func TestCopyTreeMkdirFailure(t *testing.T) {
	// dst is *under* an existing regular file — MkdirAll must fail.
	parent := t.TempDir()
	regular := filepath.Join(parent, "regular-file")
	if err := os.WriteFile(regular, []byte("x"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	dst := filepath.Join(regular, "child", "dst")
	err := copyTree("/tmp/.", dst+"/", "test")
	if err == nil {
		t.Fatal("expected mkdir error when parent is a regular file, got nil")
	}
}

func TestSaveAndRestoreRoundTrip(t *testing.T) {
	varLib := t.TempDir()
	backupParent := t.TempDir()
	backup := filepath.Join(backupParent, "kube-save-var-lib")
	restored := t.TempDir()

	if err := os.MkdirAll(filepath.Join(varLib, "rancher/k3s"), 0755); err != nil {
		t.Fatalf("seed varLib: %v", err)
	}
	if err := os.WriteFile(filepath.Join(varLib, "rancher/k3s/server-token"),
		[]byte("topsecret"), 0600); err != nil {
		t.Fatalf("seed token: %v", err)
	}

	if err := saveVarLibTo(varLib, backup); err != nil {
		t.Fatalf("saveVarLibTo: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(backup, "rancher/k3s/server-token"))
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(got) != "topsecret" {
		t.Errorf("backup content = %q, want %q", string(got), "topsecret")
	}

	// Staging dir must NOT linger after a successful save.
	if _, err := os.Stat(backup + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected staging dir to be gone, stat err = %v", err)
	}

	if err := restoreVarLibFrom(backup, restored); err != nil {
		t.Fatalf("restoreVarLibFrom: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(restored, "rancher/k3s/server-token"))
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != "topsecret" {
		t.Errorf("restored content = %q, want %q", string(got), "topsecret")
	}
}

func TestSaveReplacesPriorBackupAtomically(t *testing.T) {
	varLib := t.TempDir()
	backup := filepath.Join(t.TempDir(), "kube-save-var-lib")

	// Stage 1: save with one payload.
	if err := os.WriteFile(filepath.Join(varLib, "f"), []byte("v1"), 0600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := saveVarLibTo(varLib, backup); err != nil {
		t.Fatalf("first saveVarLibTo: %v", err)
	}

	// Stage 2: change payload + leave a stale extra file in the
	// previous backup that must NOT survive the second save.
	if err := os.WriteFile(filepath.Join(backup, "stale"), []byte("old"), 0600); err != nil {
		t.Fatalf("seed stale: %v", err)
	}
	if err := os.WriteFile(filepath.Join(varLib, "f"), []byte("v2"), 0600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := saveVarLibTo(varLib, backup); err != nil {
		t.Fatalf("second saveVarLibTo: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(backup, "f"))
	if err != nil {
		t.Fatalf("read backup f: %v", err)
	}
	if string(got) != "v2" {
		t.Errorf("backup f = %q, want %q (second save did not replace contents)",
			string(got), "v2")
	}
	if _, err := os.Stat(filepath.Join(backup, "stale")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale file from prior backup survived: stat err = %v", err)
	}
}

func TestSaveSourceMissingWrapsNotFound(t *testing.T) {
	backup := filepath.Join(t.TempDir(), "kube-save-var-lib")
	err := saveVarLibTo("/nonexistent/"+t.Name(), backup)
	if err == nil {
		t.Fatal("expected error for missing source, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist in chain, got %v", err)
	}
	// The backup dir must NOT have been created when the source is
	// missing — otherwise a future RestoreVarLib would silently apply
	// an empty backup to /var/lib.
	if _, statErr := os.Stat(backup); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("backup dir was created despite missing source: stat err = %v", statErr)
	}
}

func TestRestoreMissingBackupWrapsNotFound(t *testing.T) {
	err := restoreVarLibFrom("/nonexistent/path/"+t.Name(), t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing backup, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist in chain, got %v", err)
	}
}

func TestRestoreBackupStatPermissionError(t *testing.T) {
	// A permission-denied stat must NOT be misclassified as
	// os.ErrNotExist — callers rely on that distinction to decide
	// "nothing to restore" vs "broken backup".
	if os.Geteuid() == 0 {
		t.Skip("root bypasses dir-exec permissions")
	}
	parent := t.TempDir()
	blocked := filepath.Join(parent, "blocked")
	if err := os.Mkdir(blocked, 0000); err != nil {
		t.Fatalf("mkdir blocked: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0700); err != nil {
			t.Logf("chmod restore: %v", err)
		}
	})

	err := restoreVarLibFrom(filepath.Join(blocked, "backup"), t.TempDir())
	if err == nil {
		t.Fatal("expected stat error, got nil")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("permission error misclassified as os.ErrNotExist: %v", err)
	}
}

// A file that disappears between readdir and open must not fail the
// whole snapshot. On a real node one multus result file vanishing during
// pod teardown lost the entire backup while the caller went on to write
// the initialized marker.
func TestCopyTreeToleratesVanishedEntry(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")

	if err := os.WriteFile(filepath.Join(src, "keep"), []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	// A dangling symlink is the stable stand-in for the race: WalkDir
	// reports the entry, and anything resolving the target gets ENOENT.
	if err := os.Symlink(filepath.Join(src, "gone"), filepath.Join(src, "dangling")); err != nil {
		t.Fatal(err)
	}

	if err := copyTree(src+"/.", dst+"/", "test"); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dst, "keep")); err != nil || string(b) != "data" {
		t.Errorf("keep = %q, %v; want \"data\", nil", b, err)
	}
	// The dangling link is reproduced as a link, not followed.
	if fi, err := os.Lstat(filepath.Join(dst, "dangling")); err != nil {
		t.Errorf("dangling link not reproduced: %v", err)
	} else if fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("dangling entry copied as %v, want a symlink", fi.Mode())
	}
}

// Sockets cannot be copied and are recreated by whatever owns them, so
// their presence must not fail a snapshot. /var/lib had 8 on a live node.
func TestCopyTreeSkipsSockets(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")

	ln, err := net.Listen("unix", filepath.Join(src, "s.sock"))
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer ln.Close()
	if err := os.WriteFile(filepath.Join(src, "f"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := copyTree(src+"/.", dst+"/", "test"); err != nil {
		t.Fatalf("copyTree with a socket present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "f")); err != nil {
		t.Errorf("regular file alongside the socket was not copied: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dst, "s.sock")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("socket should be skipped, stat err = %v", err)
	}
}

// The multus result cache is regenerated per pod, so snapshotting it is
// pointless and it is the likeliest source of the vanish race.
func TestCopyTreeSkipsVolatilePaths(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")

	vol := filepath.Join(src, "cni", "multus", "results")
	if err := os.MkdirAll(vol, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vol, "cbr0-abc-eth0"), []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "cni", "keep.conf"), []byte("k"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := copyTree(src+"/.", dst+"/", "test"); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "cni", "keep.conf")); err != nil {
		t.Errorf("non-volatile sibling not copied: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "cni", "multus", "results", "cbr0-abc-eth0")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("volatile result file should be skipped, stat err = %v", err)
	}
}

// Modes and symlink targets must survive, or a restored /var/lib hands
// k3s tokens back with the wrong permissions.
func TestCopyTreePreservesModesAndSymlinks(t *testing.T) {
	src := t.TempDir()
	dst := filepath.Join(t.TempDir(), "out")

	if err := os.WriteFile(filepath.Join(src, "secret"), []byte("t"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(src, "sub"), 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("secret", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}

	if err := copyTree(src+"/.", dst+"/", "test"); err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(dst, "secret")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0600 {
		t.Errorf("secret perm = %o, want 600", fi.Mode().Perm())
	}
	if fi, err := os.Stat(filepath.Join(dst, "sub")); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0710 {
		t.Errorf("sub perm = %o, want 710", fi.Mode().Perm())
	}
	if got, err := os.Readlink(filepath.Join(dst, "link")); err != nil || got != "secret" {
		t.Errorf("link target = %q, %v; want \"secret\", nil", got, err)
	}
}
