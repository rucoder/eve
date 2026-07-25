// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	ctrdimages "github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/lf-edge/eve/pkg/kube/kube-init/kubectlx"
)

// gcRefLabels builds the containerd.io/gc.ref.content.* labels naming a
// manifest's children (config + layers) so the GC keeps the whole image
// graph reachable from the image record.
func gcRefLabels(children []ocispec.Descriptor) map[string]string {
	labels := make(map[string]string, len(children))
	for i, c := range children {
		labels[fmt.Sprintf("containerd.io/gc.ref.content.%d", i)] = c.Digest.String()
	}
	return labels
}

// externalBootLayoutRef is the ref-name the build assigns to the
// EVE-authored external-boot-image inside the layout.
const externalBootLayoutRef = "eve-external-boot-image"

// erofsSnapshotter is the snapshotter kube-init pre-converts images into.
// Must match snapshotter in pkg/kube/config-k3s.toml.
const erofsSnapshotter = "erofs"

// registerLayout registers every image in the mounted OCI layout into
// the k8s.io containerd namespace: content refs (metadata-only when the
// blobs were staged into the store and the sharing policy is "shared";
// a correct copy otherwise) plus image records named with the real
// registry refs. Best-effort per image.
func registerLayout(ctx context.Context, socket, layoutDir, listPath, externalBootRef string) error {
	imgs, err := parseLayout(layoutDir)
	if err != nil {
		return fmt.Errorf("parse layout: %w", err)
	}
	refMap, err := loadRefMap(listPath)
	if err != nil {
		return fmt.Errorf("load ref map: %w", err)
	}

	client, err := containerd.New(socket)
	if err != nil {
		return fmt.Errorf("containerd client: %w", err)
	}
	ctx = namespaces.WithNamespace(ctx, kubectlx.K8sContainerdNamespace)

	// Probe reachability once up front: a dead or not-yet-listening socket
	// would otherwise fail every image's first RPC individually, producing
	// a wall of per-image warnings instead of one clear setup error.
	if serving, err := client.IsServing(ctx); err != nil || !serving {
		_ = client.Close()
		if err == nil {
			err = fmt.Errorf("health check reports not serving")
		}
		return fmt.Errorf("containerd not reachable: %w", err)
	}
	defer func() { _ = client.Close() }()

	// Hold a lease across the whole import so each blob is GC-protected the
	// moment WriteBlob records it (the shared short-circuit adds leased
	// content), and stays protected until every image record is created and
	// references it. Without this, containerd's GC reaps freshly written but
	// not-yet-referenced content mid-import.
	ctx, done, err := client.WithLease(ctx)
	if err != nil {
		return fmt.Errorf("create lease: %w", err)
	}
	defer func() { _ = done(ctx) }()

	cs := client.ContentStore()
	is := client.ImageService()

	importStart := time.Now()
	var registered, converted int
	var convertTotal time.Duration
	for _, img := range imgs {
		name := resolveName(img.RefName, refMap, externalBootRef)
		if name == "" {
			if img.RefName == externalBootLayoutRef && externalBootRef == "" {
				// Deliberate skip: external-boot-image is only registered
				// when KubeVirt is enabled and a target ref is supplied.
				log.Printf("kube-images: external-boot-image not requested (kubevirt disabled), skipping")
			} else {
				log.Printf("WARNING: no name mapping for %q, skipping", img.RefName)
			}
			continue
		}
		if err := registerOne(ctx, cs, is, layoutDir, img, name); err != nil {
			log.Printf("WARNING: register %s: %v", name, err)
			continue
		}
		registered++
		// Pre-convert into the erofs snapshotter now, sequentially, so the
		// deploy waves find a ready snapshot at CreateContainer. Lazy per-pod
		// conversion otherwise herds: a wave bringing up several images at once
		// converts them concurrently and starves a CPU-constrained node past the
		// CreateContainer deadline. Best-effort — kubelet converts on demand if
		// this is skipped.
		cimg, gerr := client.GetImage(ctx, name)
		if gerr != nil {
			log.Printf("WARNING: get image %s for pre-unpack: %v", name, gerr)
			continue
		}
		t0 := time.Now()
		if uerr := cimg.Unpack(ctx, erofsSnapshotter); uerr != nil {
			log.Printf("WARNING: pre-unpack %s: %v", name, uerr)
			continue
		}
		d := time.Since(t0)
		convertTotal += d
		converted++
		log.Printf("kube-images: pre-converted %s -> %s in %s (%d/%d)",
			name, erofsSnapshotter, d.Round(time.Millisecond), converted, len(imgs))
	}
	log.Printf("kube-images: registerLayout done: %d registered, %d pre-converted, "+
		"convert-time %s, wall %s",
		registered, converted, convertTotal.Round(time.Second),
		time.Since(importStart).Round(time.Second))
	return nil
}

// blobKind reports how a blob (given by its digest hex) is materialised
// in the containerd content store on disk: "symlink" (staged, zero-copy),
// "regular" (copied), or "absent" — used for the per-image zero-copy tally.
func blobKind(hex string) string {
	fi, err := os.Lstat(filepath.Join(contentStoreBlobs, hex))
	if err != nil {
		return "absent"
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return "symlink"
	}
	return "regular"
}

// resolveName maps a layout ref-name to the real image ref. The
// external-boot-image entry maps to externalBootRef (skipped if empty).
func resolveName(refName string, refMap map[string]string, externalBootRef string) string {
	if refName == externalBootLayoutRef {
		return externalBootRef
	}
	return refMap[refName]
}

func registerOne(ctx context.Context, cs content.Store, is ctrdimages.Store,
	layoutDir string, img layoutImage, name string) error {
	var zerocopy, copied int
	for _, b := range img.Blobs {
		// Stage this blob into the content store right before writing it, so
		// its symlink exists for at most one WriteBlob before it becomes
		// referenced — too short a window for GC to reap it.
		src := blobPath(layoutDir, b)
		dst := filepath.Join(contentStoreBlobs, b.Digest.Encoded())
		if _, lerr := linkBlob(src, dst); lerr != nil {
			log.Printf("WARNING: stage %s %s: %v", name, b.Digest, lerr)
		}
		f, err := os.Open(src)
		if err != nil {
			return fmt.Errorf("open blob %s: %w", b.Digest, err)
		}
		// The manifest carries containerd.io/gc.ref.content.* labels naming
		// its config + layers. Without them GC can't see the manifest's
		// children and reaps every config/layer once our lease releases,
		// leaving image records whose content is incomplete.
		var opts []content.Opt
		if b.Digest == img.Manifest.Digest {
			opts = append(opts, content.WithLabels(gcRefLabels(img.Blobs[1:])))
		}
		// WriteBlob short-circuits to metadata-only when the staged symlink
		// resolves in the backend store (shared policy); otherwise it copies
		// from f. Either way correct.
		writeErr := content.WriteBlob(ctx, cs, "kube-images-"+b.Digest.String(), f, b, opts...)
		_ = f.Close()
		if writeErr != nil {
			return fmt.Errorf("write blob %s: %w", b.Digest, writeErr)
		}
		// symlink still present => zero-copy; regular file => copied.
		if blobKind(b.Digest.Encoded()) == "symlink" {
			zerocopy++
		} else {
			copied++
		}
	}
	image := ctrdimages.Image{Name: name, Target: img.Manifest}
	if _, err := is.Create(ctx, image); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return fmt.Errorf("create image: %w", err)
		}
		// Already exists -> update to point at our manifest (idempotent).
		if _, uerr := is.Update(ctx, image); uerr != nil {
			return fmt.Errorf("create/update image: create=%w update=%w", err, uerr)
		}
	}
	log.Printf("kube-images: registered %s (%d blobs, %d zero-copy, %d copied)",
		name, len(img.Blobs), zerocopy, copied)
	return nil
}
