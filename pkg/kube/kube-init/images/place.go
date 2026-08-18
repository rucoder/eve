// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/mount"
	"github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/identity"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// erofsLayerFile is the per-snapshot blob the erofs snapshotter
	// mounts as that layer's lower dir.
	erofsLayerFile = "layer.erofs"

	// erofsLayerMarker is written into every snapshot directory the
	// erofs snapshotter prepares. Its presence is how the differ
	// confirms a directory belongs to that snapshotter, and we use it
	// the same way before writing into one.
	erofsLayerMarker = ".erofslayer"

	// snapshotRefLabel names the chainID a prepared snapshot will be
	// committed as; set for parity with containerd's own unpacker.
	snapshotRefLabel = "containerd.io/snapshot.ref"

	// gcSnapshotRefLabel, set on an image's MANIFEST blob, is how
	// containerd's GC reaches the snapshots belonging to that image
	// (core/metadata/gc.go follows this prefix). Without it the
	// snapshots placed here are unreferenced and get reaped.
	gcSnapshotRefLabel = "containerd.io/gc.ref.snapshot." + erofsSnapshotter
)

// placeLayers makes an image's layers available as erofs snapshots
// without writing their bytes anywhere.
//
// containerd would otherwise reach the same state by unpacking: its
// erofs differ recognises our pre-built layers as native and copies each
// blob into the snapshot directory (differ_linux.go). That copy is pure
// overhead here — the payload is a read-only mount that stays for the
// life of the boot, so the snapshot can simply point at it. Commit only
// converts an upperdir when layer.erofs is MISSING, so a layer.erofs we
// placed ourselves is accepted as-is and mounted directly.
//
// chainIDs are derived from the config's diff_ids exactly as the
// unpacker derives them, so the snapshots land under the names CRI looks
// up at CreateContainer.
func placeLayers(ctx context.Context, sn snapshots.Snapshotter, cs content.Store,
	layoutDir string, img layoutImage) error {
	man, err := readManifest(layoutDir, img.Manifest)
	if err != nil {
		return err
	}
	cfg, err := readImageConfig(layoutDir, man.Config)
	if err != nil {
		return err
	}
	if len(cfg.RootFS.DiffIDs) != len(man.Layers) {
		return fmt.Errorf("%d layers but %d diff_ids", len(man.Layers), len(cfg.RootFS.DiffIDs))
	}
	if len(man.Layers) == 0 {
		return fmt.Errorf("no layers")
	}

	chain := identity.ChainIDs(append([]digest.Digest{}, cfg.RootFS.DiffIDs...))
	var parent string
	for i, layer := range man.Layers {
		chainID := chain[i].String()
		if _, serr := sn.Stat(ctx, chainID); serr == nil {
			// Already placed by an earlier image (shared base layer) or
			// by a previous run: nothing to do, but it is still the
			// parent of the next layer.
			parent = chainID
			continue
		}
		if !isErofsLayer(layer.MediaType) {
			return fmt.Errorf("layer %d is %q, not a native erofs layer", i, layer.MediaType)
		}
		if err := placeOne(ctx, sn, chainID, parent, blobPath(layoutDir, layer)); err != nil {
			return fmt.Errorf("layer %d (%s): %w", i, layer.Digest, err)
		}
		parent = chainID
	}

	// Point the GC at the top of the chain before the caller's lease
	// expires, or every snapshot placed above is unreferenced.
	info := content.Info{
		Digest: img.Manifest.Digest,
		Labels: map[string]string{gcSnapshotRefLabel: parent},
	}
	if _, err := cs.Update(ctx, info, "labels."+gcSnapshotRefLabel); err != nil {
		return fmt.Errorf("label manifest with snapshot ref: %w", err)
	}
	return nil
}

// placeOne prepares one snapshot, points its layer blob at the payload
// and commits it under chainID.
func placeOne(ctx context.Context, sn snapshots.Snapshotter, chainID, parent, blob string) error {
	key := fmt.Sprintf(snapshots.UnpackKeyFormat, uniquePart(), chainID)
	mounts, err := sn.Prepare(ctx, key, parent,
		snapshots.WithLabels(map[string]string{snapshotRefLabel: chainID}))
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("prepare: %w", err)
	}
	abort := func() {
		if rerr := sn.Remove(ctx, key); rerr != nil && !errdefs.IsNotFound(rerr) {
			log.Printf("WARNING: cleanup snapshot %s: %v", key, rerr)
		}
	}
	dir, err := mountsToLayer(mounts)
	if err != nil {
		abort()
		return err
	}
	if err := os.Symlink(blob, filepath.Join(dir, erofsLayerFile)); err != nil {
		abort()
		return fmt.Errorf("link layer blob: %w", err)
	}
	if err := sn.Commit(ctx, chainID, key); err != nil {
		if errdefs.IsAlreadyExists(err) {
			return nil
		}
		abort()
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// mountsToLayer returns the snapshot directory that holds layer.erofs,
// mirroring containerd's internal erofsutils.MountsToLayer (which we
// cannot import). The .erofslayer marker confirms the directory really
// belongs to the erofs snapshotter before we write into it.
func mountsToLayer(mounts []mount.Mount) (string, error) {
	if len(mounts) == 0 {
		return "", fmt.Errorf("no mounts returned")
	}
	var dir string
	switch m := mounts[0]; m.Type {
	case "bind", "rbind", "erofs":
		dir = filepath.Dir(m.Source)
	case "overlay":
		for _, o := range m.Options {
			if v, ok := strings.CutPrefix(o, "upperdir="); ok {
				dir = filepath.Dir(v)
			}
		}
	default:
		return "", fmt.Errorf("unexpected mount type %q", m.Type)
	}
	if dir == "" {
		return "", fmt.Errorf("no layer dir in mounts %v", mounts)
	}
	if _, err := os.Stat(filepath.Join(dir, erofsLayerMarker)); err != nil {
		return "", fmt.Errorf("%s is not an erofs snapshot dir: %w", dir, err)
	}
	return dir, nil
}

// isErofsLayer reports whether a media type selects containerd's native
// erofs handling: it must end in ".erofs" and carry no "+suffix"
// (differ_linux.go, isErofsMediaType).
func isErofsLayer(mt string) bool {
	base, _, hasExt := strings.Cut(mt, "+")
	return !hasExt && strings.HasSuffix(base, ".erofs")
}

func uniquePart() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "kube-init"
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// readImageConfig reads an image config blob out of the layout.
func readImageConfig(layoutDir string, d ocispec.Descriptor) (*ocispec.Image, error) {
	b, err := os.ReadFile(blobPath(layoutDir, d))
	if err != nil {
		return nil, err
	}
	var cfg ocispec.Image
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", d.Digest, err)
	}
	return &cfg, nil
}
