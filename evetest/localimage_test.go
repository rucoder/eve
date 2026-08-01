// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lf-edge/eve/evetest/constants"
	"github.com/spf13/viper"
)

// writeFakeBuild lays out a dist tree like `make live` produces and returns
// the version directory it created.
func writeFakeBuild(t *testing.T, root, version string, cfgSize int) string {
	t.Helper()
	verDir := filepath.Join(root, "amd64", version)
	fw := filepath.Join(verDir, "installer", "firmware")
	if err := os.MkdirAll(fw, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if err := os.WriteFile(filepath.Join(fw, f), []byte("x"), 0o600); err != nil {
			t.Fatalf("write firmware: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(verDir, "live.qcow2"), []byte("qcow"), 0o600); err != nil {
		t.Fatalf("write image: %v", err)
	}
	cfg := filepath.Join(verDir, "installer", "config.img")
	if err := os.WriteFile(cfg, make([]byte, cfgSize), 0o600); err != nil {
		t.Fatalf("write config.img: %v", err)
	}
	link := filepath.Join(root, "amd64", "current")
	os.Remove(link)
	if err := os.Symlink(verDir, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return verDir
}

func TestResolveLocalLiveImageDisabled(t *testing.T) {
	img, err := resolveLocalLiveImageIn(t.TempDir(), "amd64", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if img != nil {
		t.Fatalf("expected nil when the feature is off, got %+v", img)
	}
}

func TestResolveLocalLiveImageCurrent(t *testing.T) {
	root := t.TempDir()
	const version = "0.0.0-branch-abcd1234-k-amd64-v6.12.49-gcc"
	verDir := writeFakeBuild(t, root, version, 5<<20)

	img, err := resolveLocalLiveImageIn(root, "amd64", "current", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.DiskPath != filepath.Join(verDir, "live.qcow2") {
		t.Errorf("DiskPath = %q", img.DiskPath)
	}
	if img.ConfigImgPath != filepath.Join(verDir, "installer", "config.img") {
		t.Errorf("ConfigImgPath = %q", img.ConfigImgPath)
	}
	if img.FirmwareDir != filepath.Join(verDir, "installer", "firmware") {
		t.Errorf("FirmwareDir = %q", img.FirmwareDir)
	}
	if img.Version != version {
		t.Errorf("Version = %q, want %q", img.Version, version)
	}
}

func TestResolveLocalLiveImageExplicitPath(t *testing.T) {
	root := t.TempDir()
	verDir := writeFakeBuild(t, root, "0.0.0-x-1111-k-amd64-v1-gcc", 5<<20)
	explicit := filepath.Join(verDir, "live.qcow2")

	img, err := resolveLocalLiveImageIn(root, "amd64", explicit, "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.DiskPath != explicit {
		t.Errorf("DiskPath = %q, want %q", img.DiskPath, explicit)
	}
}

func TestResolveLocalLiveImageFirmwareOverride(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-2222-k-amd64-v1-gcc", 5<<20)
	other := t.TempDir()
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		if err := os.WriteFile(filepath.Join(other, f), []byte("y"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	img, err := resolveLocalLiveImageIn(root, "amd64", "current", other)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.FirmwareDir != other {
		t.Errorf("FirmwareDir = %q, want the override %q", img.FirmwareDir, other)
	}
}

func TestResolveLocalLiveImageRequiresDistDir(t *testing.T) {
	viper.Set(constants.EVELiveImageEnv, liveImageCurrent)
	viper.Set(constants.EVEDistDirEnv, "")
	defer func() {
		viper.Set(constants.EVELiveImageEnv, "")
		viper.Set(constants.EVEDistDirEnv, "")
	}()

	_, err := resolveLocalLiveImage("amd64")
	if err == nil {
		t.Fatal("expected an error when EVE_LIVE_IMAGE=current and EVE_DIST_DIR is unset")
	}
	if !strings.Contains(err.Error(), constants.EVEDistDirEnv) {
		t.Fatalf("expected the error to name %s, got: %v", constants.EVEDistDirEnv, err)
	}
}

func TestResolveLocalLiveImageMissingImage(t *testing.T) {
	_, err := resolveLocalLiveImageIn(t.TempDir(), "amd64", "current", "")
	if err == nil {
		t.Fatal("expected an error when no local build exists")
	}
}

func TestResolveLocalLiveImageWrongConfigSize(t *testing.T) {
	root := t.TempDir()
	writeFakeBuild(t, root, "0.0.0-x-3333-k-amd64-v1-gcc", 1024)
	_, err := resolveLocalLiveImageIn(root, "amd64", "current", "")
	if err == nil {
		t.Fatal("expected an error for a config.img that is not 5 MiB")
	}
}

func TestResolveLocalLiveImageUnversionedDir(t *testing.T) {
	dir := t.TempDir()
	fw := filepath.Join(dir, "installer", "firmware")
	if err := os.MkdirAll(fw, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, f := range []string{"OVMF.fd", "OVMF_CODE.fd", "OVMF_VARS.fd"} {
		os.WriteFile(filepath.Join(fw, f), []byte("x"), 0o600)
	}
	os.WriteFile(filepath.Join(dir, "live.qcow2"), []byte("qcow"), 0o600)
	os.WriteFile(filepath.Join(dir, "installer", "config.img"), make([]byte, 5<<20), 0o600)

	img, err := resolveLocalLiveImageIn(dir, "amd64", filepath.Join(dir, "live.qcow2"), "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if img.Version != "" {
		t.Errorf("Version = %q, want empty for a non-version-shaped dir", img.Version)
	}
}

func TestLiveImageSHA256IsStable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// sha256("hello")
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	got, err := liveImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if got != want {
		t.Fatalf("sha256 = %q, want %q", got, want)
	}
	sidecar := filepath.Join(filepath.Dir(f), "image-sha")
	if _, err := os.Stat(sidecar); err != nil {
		t.Fatalf("expected sidecar %q to be written: %v", sidecar, err)
	}
	again, err := liveImageSHA256(f)
	if err != nil || again != want {
		t.Fatalf("cached read = %q, %v", again, err)
	}
}

// TestLiveImageSHA256SidecarIsWorldReadable guards against the sidecar
// landing 0600 root:root when the harness runs as root inside the evetest
// container against the developer's bind-mounted dist tree -- a plain hash
// file the developer cannot read is strictly worse than the opaque cache it
// replaced.
func TestLiveImageSHA256SidecarIsWorldReadable(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := liveImageSHA256(f); err != nil {
		t.Fatalf("hash: %v", err)
	}
	sidecar := filepath.Join(filepath.Dir(f), "image-sha")
	info, err := os.Stat(sidecar)
	if err != nil {
		t.Fatalf("expected sidecar %q to be written: %v", sidecar, err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o644); got != want {
		t.Fatalf("sidecar mode = %o, want %o", got, want)
	}
}

// TestLiveImageSHA256InvalidatesOnChange covers a rebuilt image: the cache is
// keyed on the recorded size, so content of a different length must not
// return the old hash.
func TestLiveImageSHA256InvalidatesOnChange(t *testing.T) {
	f := filepath.Join(t.TempDir(), "live.qcow2")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	first, err := liveImageSHA256(f)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if err := os.WriteFile(f, []byte("goodbye"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	second, err := liveImageSHA256(f)
	if err != nil {
		t.Fatalf("rehash: %v", err)
	}
	if first == second {
		t.Fatal("hash did not change after the file changed; the cache is stale")
	}
}
