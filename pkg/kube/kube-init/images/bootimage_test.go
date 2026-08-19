// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package images

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The mkfs.erofs -U value must be stable across rebuilds so identical
// inputs yield the identical blob digest. The expected value is
// python's uuid.uuid5(uuid.NAMESPACE_URL, "erofs:<ref>") — what the
// build-time script generated, kept as the fixed reference.
func TestEbiLayerUUIDDeterministic(t *testing.T) {
	got := uuid.NewSHA1(uuid.NameSpaceURL,
		[]byte("erofs:docker.io/lfedge/eve-external-boot-image:1.2.3")).String()
	want := "b17350ee-a2f7-5210-a337-749a42726307"
	if got != want {
		t.Errorf("uuid5 mismatch: got %s want %s", got, want)
	}
}

func TestEbiImageJSON(t *testing.T) {
	layerDigest := digest.FromString("fake erofs layer")
	configBytes, manifestBytes, manifestDesc, err := ebiImageJSON(layerDigest, 42)
	if err != nil {
		t.Fatal(err)
	}

	var config ocispec.Image
	if err := json.Unmarshal(configBytes, &config); err != nil {
		t.Fatal(err)
	}
	// Native erofs layers are not tar round-tripped: the unpacker
	// checks the applied digest against the config's diff_id, and for
	// a native layer that digest IS the layer digest.
	if len(config.RootFS.DiffIDs) != 1 || config.RootFS.DiffIDs[0] != layerDigest {
		t.Errorf("diff_ids = %v, want [%s]", config.RootFS.DiffIDs, layerDigest)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) != 1 {
		t.Fatalf("want 1 layer, got %d", len(manifest.Layers))
	}
	l := manifest.Layers[0]
	if l.MediaType != erofsLayerMediaType || !isErofsLayer(l.MediaType) {
		t.Errorf("layer media type %q not native erofs", l.MediaType)
	}
	if l.Digest != layerDigest || l.Size != 42 {
		t.Errorf("layer desc = %+v", l)
	}
	if manifest.Config.Digest != digest.FromBytes(configBytes) {
		t.Errorf("manifest config digest %s != config bytes digest", manifest.Config.Digest)
	}
	if manifestDesc.Digest != digest.FromBytes(manifestBytes) ||
		manifestDesc.Size != int64(len(manifestBytes)) {
		t.Errorf("manifest descriptor %+v does not describe manifest bytes", manifestDesc)
	}
	if manifestDesc.MediaType != ocispec.MediaTypeImageManifest {
		t.Errorf("manifest media type %q", manifestDesc.MediaType)
	}
}
