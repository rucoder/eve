// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	ctrdimages "github.com/containerd/containerd/v2/core/images"
	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	// erofsLayerMediaType selects containerd's native-erofs differ path:
	// any media type ending in ".erofs" with no "+suffix" is copied into
	// the snapshot as-is instead of being converted.
	erofsLayerMediaType = "application/vnd.oci.image.layer.v1.erofs"

	// The two files the external-boot-image consists of, as shipped in
	// every EVE rootfs and reachable through the kube container's
	// /:/hostfs bind (pkg/kube/build.yml): the kernel grub boots, and
	// runx-initrd from the xen-tools service. Building the image from
	// them here, on the device, keeps the running kernel and the booted
	// image in lockstep by construction.
	hostKernel     = "/hostfs/boot/kernel"
	hostRunxInitrd = "/hostfs/containers/services/xen-tools/lower/usr/lib/xen/boot/runx-initrd"

	// ebiStageParent hosts the temporary build dir: staged copies plus
	// the layer are a few hundred MB, too big for tmpfs.
	ebiStageParent = "/persist/tmp"
)

// registerExternalBoot builds and registers the EVE-authored
// external-boot-image — the kernel+initrd image KubeVirt's kernelBoot
// boots container-as-VM apps from. KubeVirt's API only accepts a
// container image there, never host paths, so the two files must exist
// as a registered image even though both already sit in the rootfs.
//
// The image is a single native-EROFS layer (diff_id == layer digest, so
// no tar round-trip and nothing for the differ to convert), registered
// under ref (tagged with the running EVE release) and aliased :latest —
// pillar's VMIRS hardcodes that tag with imagePullPolicy Never so the
// reference survives a baseOS upgrade (see lf-edge/eve#6100).
// Idempotent: if ref is already registered, only the alias is refreshed.
func registerExternalBoot(ctx context.Context, client *containerd.Client,
	cs content.Store, is ctrdimages.Store, ref string) error {
	latestRef := ExternalBootImageName + ":latest"
	if img, err := is.Get(ctx, ref); err == nil {
		log.Printf("kube-images: %s already registered", ref)
		return putImage(ctx, is, latestRef, img.Target)
	}

	if err := os.MkdirAll(ebiStageParent, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", ebiStageParent, err)
	}
	tmp, err := os.MkdirTemp(ebiStageParent, "ebi-build-*")
	if err != nil {
		return fmt.Errorf("mkdtemp under %s: %w", ebiStageParent, err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	layerPath, err := buildEbiLayer(ref, tmp)
	if err != nil {
		return err
	}
	layerDigest, layerSize, err := digestFile(layerPath)
	if err != nil {
		return err
	}
	configBytes, manifestBytes, manifestDesc, err := ebiImageJSON(layerDigest, layerSize)
	if err != nil {
		return err
	}

	f, err := os.Open(layerPath)
	if err != nil {
		return fmt.Errorf("open layer: %w", err)
	}
	defer func() { _ = f.Close() }()
	layerDesc := ocispec.Descriptor{
		MediaType: erofsLayerMediaType, Digest: layerDigest, Size: layerSize}
	configDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageConfig,
		Digest:    digest.FromBytes(configBytes), Size: int64(len(configBytes))}
	if err := content.WriteBlob(ctx, cs, "ebi-"+layerDigest.String(), f, layerDesc); err != nil {
		return fmt.Errorf("write layer blob: %w", err)
	}
	if err := content.WriteBlob(ctx, cs, "ebi-"+configDesc.Digest.String(),
		bytes.NewReader(configBytes), configDesc); err != nil {
		return fmt.Errorf("write config blob: %w", err)
	}
	if err := content.WriteBlob(ctx, cs, "ebi-"+manifestDesc.Digest.String(),
		bytes.NewReader(manifestBytes), manifestDesc); err != nil {
		return fmt.Errorf("write manifest blob: %w", err)
	}
	if err := setManifestRefs(ctx, cs, manifestDesc.Digest,
		[]ocispec.Descriptor{configDesc, layerDesc}); err != nil {
		return err
	}

	for _, name := range []string{ref, latestRef} {
		if err := putImage(ctx, is, name, manifestDesc); err != nil {
			return fmt.Errorf("register %s: %w", name, err)
		}
	}
	cimg, err := client.GetImage(ctx, ref)
	if err != nil {
		return fmt.Errorf("get %s for unpack: %w", ref, err)
	}
	if err := cimg.Unpack(ctx, erofsSnapshotter); err != nil {
		return fmt.Errorf("unpack %s: %w", ref, err)
	}
	log.Printf("kube-images: built and registered %s (layer %s, %d bytes)",
		ref, layerDigest, layerSize)
	return nil
}

// buildEbiLayer stages the kernel and runx-initrd and packs them into a
// single EROFS layer under tmp, returning its path. Modes matter:
// KubeVirt runs the container-disk container as non-root, so the files
// must be world-readable and the layer root traversable.
func buildEbiLayer(ref, tmp string) (string, error) {
	staged := filepath.Join(tmp, "root")
	if err := os.Mkdir(staged, 0755); err != nil {
		return "", fmt.Errorf("mkdir staging root: %w", err)
	}
	// Paths inside the layer are the ones pillar's VMIRS references
	// (kernelPath /kernel, initrdPath /runx-initrd).
	for src, name := range map[string]string{
		hostKernel:     "kernel",
		hostRunxInitrd: "runx-initrd",
	} {
		if err := copyFile(src, filepath.Join(staged, name), 0666); err != nil {
			return "", err
		}
	}
	out := filepath.Join(tmp, "layer.erofs")
	// --quiet -Enoinline_data mirrors containerd's own ConvertErofs.
	// -U/-T pin run-to-run variance (random UUID, timestamps) so
	// identical inputs always produce the identical blob digest and a
	// re-registration dedups instead of accumulating layers.
	cmd := exec.Command("mkfs.erofs", "--quiet", "-Enoinline_data",
		"--force-uid=0", "--force-gid=0",
		"-U", uuid.NewSHA1(uuid.NameSpaceURL, []byte("erofs:"+ref)).String(),
		"-T", "0", "-zlz4hc", out, staged)
	if o, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("mkfs.erofs: %w (output: %s)", err, strings.TrimSpace(string(o)))
	}
	return out, nil
}

// ebiImageJSON builds the config and manifest for the one-layer image.
// The config's diff_id is the EROFS blob digest itself: that is what
// containerd's unpacker checks a native layer against.
func ebiImageJSON(layerDigest digest.Digest, layerSize int64) (
	configBytes, manifestBytes []byte, manifestDesc ocispec.Descriptor, err error) {
	config := ocispec.Image{
		Platform: ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"},
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{layerDigest}},
	}
	configBytes, err = json.Marshal(config)
	if err != nil {
		return nil, nil, ocispec.Descriptor{}, fmt.Errorf("marshal config: %w", err)
	}
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    digest.FromBytes(configBytes),
			Size:      int64(len(configBytes)),
		},
		Layers: []ocispec.Descriptor{{
			MediaType: erofsLayerMediaType,
			Digest:    layerDigest,
			Size:      layerSize,
		}},
	}
	manifestBytes, err = json.Marshal(manifest)
	if err != nil {
		return nil, nil, ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestDesc = ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.FromBytes(manifestBytes),
		Size:      int64(len(manifestBytes)),
	}
	return configBytes, manifestBytes, manifestDesc, nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return out.Close()
}

func digestFile(path string) (digest.Digest, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	d, err := digest.SHA256.FromReader(f)
	if err != nil {
		return "", 0, fmt.Errorf("digest %s: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return d, fi.Size(), nil
}
