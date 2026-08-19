// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package images makes the pre-packaged container images available to
// the k3s user-containerd that kubelet consumes, without a first-boot
// network pull and without copying gigabytes of layer blobs onto
// /persist.
//
// The upstream images (KubeVirt, CDI, Longhorn, Multus, kube-vip) ship
// as a standard OCI image layout (index.json, oci-layout,
// blobs/sha256/*); the EVE-authored external-boot-image is instead
// assembled on the device from rootfs content (bootimage.go) and
// registered alongside them. The linuxkit rootfs binds the eve-kube-images volume at
// /images inside the kube container (images/modifiers/hv/k.yq), so the
// layout is directly readable there for the life of every boot — no
// mount step. At the IMPORTING phase kube-init:
//
//  1. stages the read-only blobs into containerd's content store by
//     symlink, so registering the images writes metadata only — the
//     blob bytes are never copied to /persist;
//  2. registers the layout directly against the containerd content and
//     image services (registerLayout), renaming each image from its
//     build-time-sanitised OCI ref to the real registry ref kubelet's
//     pod specs reference (and the external-boot-image to the running
//     EVE release) — no intermediate `ctr images import` tar stream.
package images

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

const (
	// KubeImagesLayout is the OCI image layout bound in by the linuxkit
	// rootfs (kube-images:/images:ro). It holds every pre-packaged
	// image. The bind is established by linuxkit init before any
	// service starts, so it is valid on every boot with no
	// (re-)mounting for kube-init to do — but the content-store blob
	// symlinks registered against it resolve only inside the kube
	// container's mount namespace, which is where the user containerd
	// and its shims run.
	KubeImagesLayout = "/images"

	// ExternalBootImageName is the fully-qualified image name kubelet
	// pod specs reference; the tag is the running EVE release.
	ExternalBootImageName = "docker.io/lfedge/eve-external-boot-image"

	// contentStoreBlobs is the digest dir of the user-containerd
	// content store (root from pkg/kube/config-k3s.toml).
	contentStoreBlobs = "/persist/vault/containerd/io.containerd.content.v1.content/blobs/sha256"

	// catalogInLayout is the real-ref list shipped inside the layout.
	catalogInLayout = KubeImagesLayout + "/upstream-images.list"
)

// ImportAll makes the pre-packaged images available to the k3s user
// containerd with no blob copy to /persist. Best-effort: any failure
// logs and returns nil, leaving kubelet's network pull as the fallback.
func ImportAll(ctx context.Context, eveRelease string, installKubevirt bool) error {
	log.Printf("importing images (release=%s, kubevirt=%v)", eveRelease, installKubevirt)

	if _, err := os.Stat(filepath.Join(KubeImagesLayout, "index.json")); err != nil {
		log.Printf("WARNING: kube-images layout: %v; kubelet will pull upstream", err)
		return nil
	}
	// Blobs are staged per-blob just before each WriteBlob (in registerLayout),
	// so containerd's GC can't reap a pre-staged, not-yet-referenced symlink
	// before registration reaches it.
	externalBootRef := ""
	if installKubevirt {
		externalBootRef = ExternalBootImageName + ":" + eveRelease
	}
	if err := registerLayout(ctx, state.ContainerdSocket, KubeImagesLayout, catalogInLayout, externalBootRef); err != nil {
		log.Printf("WARNING: register kube-images: %v", err)
	}
	log.Printf("image import phase complete")
	return nil
}

// linkBlob symlinks a single content-store blob at dst to the read-only
// volume src, unless dst already exists. Symlink because src is on a
// read-only filesystem (hardlink impossible) and a copy is exactly what
// we avoid. content.Store.Info os.Stats the path (following the link),
// which enables the shared-mode zero-copy short-circuit. Returns true
// if a new link was created.
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
