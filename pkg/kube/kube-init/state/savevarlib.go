// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// KubeSaveVarLib is the backup location on the persistent volume
// where /var/lib/ is snapshotted before a destructive cluster-mode
// transition. Lives under /persist/vault so the contents are
// encrypted at rest alongside the rest of kube state. Older EVE
// images wrote to /persist/kube-save-var-lib — MigrateVarLib
// relocates it on first boot after upgrade.
const KubeSaveVarLib = "/persist/vault/kube-save-var-lib"

// legacyKubeSaveVarLib is the pre-vault location. Read-only —
// MigrateVarLib copies its contents to KubeSaveVarLib and removes
// the source. New writes go straight to KubeSaveVarLib.
const legacyKubeSaveVarLib = "/persist/kube-save-var-lib"

// MigrateVarLib relocates a pre-vault kube-save-var-lib backup to
// the new vault-backed location, then removes the legacy directory.
// No-op when either (a) the legacy directory does not exist or (b)
// the new location already has content (a prior boot already
// migrated). Vault must be available before this is called.
//
// The copy is recursive because src and dst may sit on different
// filesystems (legacy ext4 vs vault). copyTree preserves symlinks
// and permission bits.
//
// Addresses upstream commit 647a03b2d ("Move kube-save-var-lib
// under vault").
func MigrateVarLib() error {
	if _, err := os.Stat(legacyKubeSaveVarLib); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", legacyKubeSaveVarLib, err)
	}
	// If the vault location already exists, the migration ran on a
	// prior boot. Just remove the legacy directory so we don't keep
	// rechecking it forever.
	if _, err := os.Stat(KubeSaveVarLib); err == nil {
		log.Printf("state: legacy and vault kube-save-var-lib both present; "+
			"removing legacy %s", legacyKubeSaveVarLib)
		return os.RemoveAll(legacyKubeSaveVarLib)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s: %w", KubeSaveVarLib, err)
	}

	log.Printf("state: migrating kube-save-var-lib %s -> %s",
		legacyKubeSaveVarLib, KubeSaveVarLib)
	if err := copyTree(legacyKubeSaveVarLib+"/.",
		KubeSaveVarLib+"/", "migrate"); err != nil {
		return err
	}
	if err := os.RemoveAll(legacyKubeSaveVarLib); err != nil {
		// Migration succeeded; legacy cleanup failure is
		// recoverable (next boot will see both and re-clean).
		log.Printf("WARNING: state: remove legacy %s after migrate: %v",
			legacyKubeSaveVarLib, err)
	}
	return nil
}

// SaveVarLib snapshots /var/lib/ to KubeSaveVarLib so a destructive
// cluster-mode transition can be rolled back. The contents are
// staged into a `<dst>.tmp` directory and renamed into place on
// success — a failed cp does not leave a half-populated backup that
// a later RestoreVarLib could silently apply.
//
// Returns an error wrapping os.ErrNotExist if /var/lib itself is
// missing — callers should treat that as "nothing to save".
func SaveVarLib() error {
	return saveVarLibTo("/var/lib", KubeSaveVarLib)
}

// RestoreVarLib copies the contents of KubeSaveVarLib back into
// /var/lib/. Returns an error that unwraps to os.ErrNotExist if the
// backup directory does not exist — callers should treat that as
// "nothing to restore" rather than a hard failure.
func RestoreVarLib() error {
	return restoreVarLibFrom(KubeSaveVarLib, "/var/lib")
}

// saveVarLibTo / restoreVarLibFrom are the inner halves of the
// public pair, with paths injected so tests can run against temp
// dirs.
func saveVarLibTo(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("save /var/lib: source %s missing: %w",
				src, err)
		}
		return fmt.Errorf("stat source %s: %w", src, err)
	}
	staging := dst + ".tmp"
	// Wipe any prior staging dir so a previous failed run doesn't
	// contaminate this one.
	if err := os.RemoveAll(staging); err != nil {
		return fmt.Errorf("save: clean staging %s: %w", staging, err)
	}
	if err := copyTree(src+"/.", staging+"/", "save"); err != nil {
		// Make sure we don't leak a half-populated staging dir on
		// failure — RestoreVarLib must never see one.
		_ = os.RemoveAll(staging)
		return err
	}
	// Atomic-ish swap: remove old backup, rename staging into place.
	if err := os.RemoveAll(dst); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("save: remove prior backup %s: %w", dst, err)
	}
	if err := os.Rename(staging, dst); err != nil {
		_ = os.RemoveAll(staging)
		return fmt.Errorf("save: rename %s -> %s: %w", staging, dst, err)
	}
	return nil
}

func restoreVarLibFrom(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("restore /var/lib: backup %s missing: %w",
				src, err)
		}
		return fmt.Errorf("stat backup dir %s: %w", src, err)
	}
	return copyTree(src+"/.", dst+"/", "restore")
}

// volatileVarLibPaths are trees whose contents are recreated at runtime
// and are worthless in a snapshot. multus writes one result file per pod
// interface, so entries appear and vanish continuously — copying that
// directory is both pointless and the likeliest source of a
// vanished-file race.
var volatileVarLibPaths = []string{
	"cni/multus/results",
	"cni/results",
}

// copyTree recursively copies src's contents into dst, preserving mode,
// ownership, timestamps and symlinks. src is given with a trailing `/.`
// by callers, matching the cp(1) content-only idiom; it is trimmed here.
//
// /var/lib is live while the snapshot runs, so an entry can disappear
// between readdir and open. Such an entry is skipped rather than failing
// the whole copy — `cp -a` treated it as fatal, which meant a single pod
// teardown mid-snapshot lost the entire backup while the caller went on
// to write the initialized marker.
//
// Sockets, fifos and device nodes are skipped: their content cannot be
// copied meaningfully and whatever owns them recreates them on restore.
//
// op is "save" / "restore" — it ends up in log lines so the two call
// sites are distinguishable in journalctl.
//
// The destination root is created at mode 0700 because /var/lib carries
// secrets (k3s tokens, kubeconfigs) and the backup must not be more
// permissive than the live tree.
func copyTree(src, dst, op string) error {
	src = strings.TrimSuffix(strings.TrimSuffix(src, "."), "/")
	dst = strings.TrimSuffix(dst, "/")
	log.Printf("state: %s tree %s -> %s", op, src, dst)
	if err := os.MkdirAll(dst, 0700); err != nil {
		return fmt.Errorf("%s: mkdir %s: %w", op, dst, err)
	}

	skipped := 0
	err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// Only a descendant may legitimately vanish. A missing root
			// means the caller asked to copy something that is not
			// there, and reporting success would have
			// restoreVarLibFrom claim it restored an absent backup.
			if errors.Is(err, fs.ErrNotExist) && path != src {
				skipped++
				return nil
			}
			return err
		}
		rel, relErr := filepath.Rel(src, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		if slices.Contains(volatileVarLibPaths, filepath.ToSlash(rel)) {
			return fs.SkipDir
		}

		target := filepath.Join(dst, rel)
		copied, cErr := copyEntry(path, target, d)
		if cErr != nil {
			if errors.Is(cErr, fs.ErrNotExist) {
				// Vanished under us; nothing to preserve.
				skipped++
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return fmt.Errorf("%s: %w", rel, cErr)
		}
		if !copied && d.IsDir() {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("%s: copy %s -> %s: %w", op, src, dst, err)
	}
	if skipped > 0 {
		log.Printf("state: %s tree %s -> %s done (%d entry/entries vanished mid-copy)",
			op, src, dst, skipped)
		return nil
	}
	log.Printf("state: %s tree %s -> %s done", op, src, dst)
	return nil
}

// copyEntry reproduces one directory entry at target. The bool reports
// whether the entry was reproduced; false means it was deliberately
// skipped (a socket, fifo or device node).
func copyEntry(path, target string, d fs.DirEntry) (bool, error) {
	info, err := d.Info()
	if err != nil {
		return false, err
	}

	switch {
	case d.IsDir():
		if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
			return false, err
		}
	case info.Mode()&fs.ModeSymlink != 0:
		link, err := os.Readlink(path)
		if err != nil {
			return false, err
		}
		// A stale target from an earlier pass must not make this fail.
		if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
		if err := os.Symlink(link, target); err != nil {
			return false, err
		}
		// Timestamps and mode do not apply to the link itself; only
		// ownership is preserved, and lchown needs the raw syscall.
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			_ = os.Lchown(target, int(st.Uid), int(st.Gid))
		}
		return true, nil
	case info.Mode().IsRegular():
		if err := copyFileContents(path, target, info.Mode().Perm()); err != nil {
			return false, err
		}
	default:
		// Socket, fifo or device node.
		return false, nil
	}

	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if err := os.Lchown(target, int(st.Uid), int(st.Gid)); err != nil &&
			!errors.Is(err, fs.ErrNotExist) {
			return false, err
		}
	}
	if err := os.Chtimes(target, info.ModTime(), info.ModTime()); err != nil &&
		!errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}

func copyFileContents(src, dst string, perm fs.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// O_CREATE honours umask, so set the mode explicitly.
	return os.Chmod(dst, perm)
}
