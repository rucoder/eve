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
	sn := client.SnapshotService(erofsSnapshotter)

	importStart := time.Now()
	var registered, staged, unpacked int
	var stageTotal time.Duration
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
		// The external-boot-image must also be reachable as :latest.
		// pillar's kubevirt hypervisor hardcodes that tag in every
		// container-as-VM VMIRS (with imagePullPolicy: Never) precisely
		// so the reference survives a baseOS upgrade, which prunes the
		// versioned tag — see lf-edge/eve#6100. Registering only the
		// versioned ref leaves virt-launcher wedged in ErrImageNeverPull.
		if img.RefName == externalBootLayoutRef {
			latestRef := ExternalBootImageName + ":latest"
			if err := putImage(ctx, is, latestRef, img.Manifest); err != nil {
				log.Printf("WARNING: alias %s -> %s: %v", name, latestRef, err)
			} else {
				log.Printf("kube-images: aliased %s as %s", name, latestRef)
			}
		}
		// Make the layers available as erofs snapshots now, so the deploy
		// waves find one ready at CreateContainer instead of unpacking
		// under a CPU-constrained node past the CreateContainer deadline.
		// The layers are already erofs images inside the payload, so this
		// only writes snapshot metadata and a symlink per layer -- see
		// placeLayers. Best-effort: on any failure fall back to
		// containerd's own unpack, which copies the blobs but works.
		t0 := time.Now()
		if perr := placeLayers(ctx, sn, cs, layoutDir, img); perr != nil {
			log.Printf("WARNING: place snapshots for %s: %v; falling back to unpack", name, perr)
			cimg, gerr := client.GetImage(ctx, name)
			if gerr != nil {
				log.Printf("WARNING: get image %s for unpack: %v", name, gerr)
				continue
			}
			if uerr := cimg.Unpack(ctx, erofsSnapshotter); uerr != nil {
				log.Printf("WARNING: unpack %s: %v", name, uerr)
				continue
			}
			unpacked++
		}
		d := time.Since(t0)
		stageTotal += d
		staged++
		log.Printf("kube-images: staged %s for %s in %s (%d/%d)",
			name, erofsSnapshotter, d.Round(time.Millisecond), staged, len(imgs))
	}
	log.Printf("kube-images: registerLayout done: %d registered, %d staged "+
		"(%d needed a copying unpack), stage-time %s, wall %s",
		registered, staged, unpacked, stageTotal.Round(time.Second),
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
	if err := putImage(ctx, is, name, img.Manifest); err != nil {
		return err
	}
	log.Printf("kube-images: registered %s (%d blobs, %d zero-copy, %d copied)",
		name, len(img.Blobs), zerocopy, copied)
	return nil
}

// putImage creates the image record for name, or repoints an existing
// record at target. The update path is what makes re-tagging safe: the
// content store lives on /persist and survives upgrades, so a stable
// alias like :latest already exists pointing at the previous release,
// and a plain Create would fail with AlreadyExists (the equivalent of
// `ctr image tag --force`).
func putImage(ctx context.Context, is ctrdimages.Store, name string, target ocispec.Descriptor) error {
	image := ctrdimages.Image{Name: name, Target: target}
	if _, err := is.Create(ctx, image); err != nil {
		if !errdefs.IsAlreadyExists(err) {
			return fmt.Errorf("create image: %w", err)
		}
		// Already exists -> update to point at our manifest (idempotent).
		if _, uerr := is.Update(ctx, image); uerr != nil {
			return fmt.Errorf("create/update image: create=%w update=%w", err, uerr)
		}
	}
	return nil
}
