// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package images makes the pre-packaged container images available to
// the k3s user-containerd that kubelet consumes, without a first-boot
// network pull and without copying gigabytes of layer blobs onto
// /persist.
//
// The images ship as a single self-contained EROFS image
// (kube-images.erofs) holding a standard OCI image layout of every
// pre-packaged image (the upstream images plus the EVE-authored
// external-boot-image folded in at build time). The linuxkit rootfs
// binds the eve-kube-images volume at /images inside the kube
// container (images/modifiers/hv/k.yq), so kube-init sees
// /images/kube-images.erofs. At the IMPORTING phase kube-init:
//
//  1. mounts the file read-only at its mount dir (plain
//     `mount -t erofs`, no loop device — CONFIG_EROFS_FS_BACKED_BY_FILE),
//     exposing the OCI layout (index.json, oci-layout, blobs/sha256/*);
//  2. stages the read-only blobs into containerd's content store by
//     symlink, so registering the images writes metadata only — the
//     blob bytes are never copied to /persist;
//  3. registers the layout directly against the containerd content and
//     image services (registerLayout), renaming each image from its
//     build-time-sanitised OCI ref to the real registry ref kubelet's
//     pod specs reference (and the external-boot-image to the running
//     EVE release) — no intermediate `ctr images import` tar stream.
package images

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

const (
	// KubeImagesErofs is the EROFS image bound in by the linuxkit
	// rootfs (kube-images:/images:ro). It contains an OCI image
	// layout of every pre-packaged image.
	KubeImagesErofs = "/images/kube-images.erofs"

	// KubeImagesMount is where KubeImagesErofs is mounted read-only.
	// After the mount this directory is a browsable OCI image layout.
	KubeImagesMount = "/run/kube-images"

	// ExternalBootImageName is the fully-qualified image name kubelet
	// pod specs reference; the tag is the running EVE release.
	ExternalBootImageName = "docker.io/lfedge/eve-external-boot-image"

	// contentStoreBlobs is the digest dir of the user-containerd
	// content store (root from pkg/kube/config-k3s.toml).
	contentStoreBlobs = "/persist/vault/containerd/io.containerd.content.v1.content/blobs/sha256"

	// catalogInErofs is the real-ref list shipped inside the layout.
	catalogInErofs = KubeImagesMount + "/upstream-images.list"
)

// ImportAll makes the pre-packaged images available to the k3s user
// containerd with no blob copy to /persist. Best-effort: any failure
// logs and returns nil, leaving kubelet's network pull as the fallback.
func ImportAll(ctx context.Context, eveRelease string, installKubevirt bool) error {
	log.Printf("importing images (release=%s, kubevirt=%v)", eveRelease, installKubevirt)

	if err := EnsureMounted(); err != nil {
		log.Printf("WARNING: mount kube-images: %v; kubelet will pull upstream", err)
		return nil
	}
	// Blobs are staged per-blob just before each WriteBlob (in registerLayout),
	// so containerd's GC can't reap a pre-staged, not-yet-referenced symlink
	// before registration reaches it.
	externalBootRef := ""
	if installKubevirt {
		externalBootRef = ExternalBootImageName + ":" + eveRelease
	}
	if err := registerLayout(ctx, state.ContainerdSocket, KubeImagesMount, catalogInErofs, externalBootRef); err != nil {
		log.Printf("WARNING: register kube-images: %v", err)
	}
	log.Printf("image import phase complete")
	return nil
}

// EnsureMounted (re-)mounts the kube-images EROFS payload read-only at
// KubeImagesMount. It MUST run on every boot, not just first boot:
// registerLayout stages each content-store blob as a symlink into
// KubeImagesMount, which lives on tmpfs (/run) and so vanishes across
// reboot. The registration metadata (and the symlinks) persist in the
// vault, but their target disappears — so unless this mount is
// re-established, every content-store blob dangles and any fresh unpack
// fails with "blob not found" (ImagePullBackOff). Idempotent: a no-op
// if already mounted, so first boot's ImportAll and every subsequent
// boot can both call it.
func EnsureMounted() error {
	return mountErofs(KubeImagesErofs, KubeImagesMount)
}

// mountErofs mounts the EROFS payload at erofs read-only at mountDir.
// Idempotent: a no-op if already mounted. Uses a plain `mount -t erofs`
// — with CONFIG_EROFS_FS_BACKED_BY_FILE the file is mounted directly,
// no loop device.
func mountErofs(erofs, mountDir string) error {
	if _, err := os.Stat(erofs); err != nil {
		return fmt.Errorf("stat %s: %w", erofs, err)
	}
	if mounted, err := isMounted(mountDir); err != nil {
		return err
	} else if mounted {
		return nil
	}
	if err := os.MkdirAll(mountDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", mountDir, err)
	}
	cmd := exec.Command("mount", "-t", "erofs", "-o", "ro", erofs, mountDir)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mount erofs %s -> %s: %w (output: %s)",
			erofs, mountDir, err, strings.TrimSpace(string(out)))
	}
	log.Printf("mounted %s at %s (ro, erofs)", erofs, mountDir)
	return nil
}

// linkBlob symlinks a single content-store blob at dst to the read-only
// EROFS-mounted src, unless dst already exists. Symlink because src is on
// a read-only EROFS on a different filesystem (hardlink impossible) and a
// copy is exactly what we avoid. content.Store.Info os.Stats the path
// (following the link), which enables the shared-mode zero-copy
// short-circuit. Returns true if a new link was created.
//
// Staged per-blob immediately before WriteBlob (not in bulk up front):
// a symlink for a blob no registered image references yet is unreferenced
// on-disk content that containerd's GC reaps, so a bulk pre-stage loses
// every blob registration hasn't reached by the time GC runs.
func linkBlob(src, dst string) (linked bool, err error) {
	if _, statErr := os.Lstat(dst); statErr == nil {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return false, fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	if err := os.Symlink(src, dst); err != nil {
		return false, fmt.Errorf("symlink %s -> %s: %w", dst, src, err)
	}
	return true, nil
}

// isMounted reports whether mountpoint appears in /proc/mounts.
func isMounted(mountpoint string) (bool, error) {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false, fmt.Errorf("read /proc/mounts: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == mountpoint {
			return true, nil
		}
	}
	return false, nil
}
