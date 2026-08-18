# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for pkg/kube-images/oci-add-erofs-image.py.

Runs the real mkfs.erofs against a small source tree and checks the
invariants the device depends on: the layer blob is a genuine EROFS image
holding the source files, its media type selects containerd's native
(no-mkfs) differ path, and the config's diff_id equals the layer digest --
which is the only thing containerd's unpacker verifies. Also checks that
re-running replaces the ref rather than duplicating it, and that identical
input yields identical digests (fixed mkfs UUID).
"""
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

TOOL = os.path.join(os.path.dirname(__file__), "..", "..",
                    "pkg", "kube-images", "oci-add-erofs-image.py")

EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"  # at offset 1024 of the superblock


def run_tool(layout, ref, srcdir, *extra):
    subprocess.run(["python3", TOOL, layout, ref, srcdir, *extra],
                   check=True, capture_output=True)


def read_blob(root, digest):
    with open(os.path.join(root, "blobs", "sha256", digest.split(":")[1]), "rb") as f:
        return f.read()


def read_index(root):
    with open(os.path.join(root, "index.json")) as f:
        return json.load(f)


def only_manifest(root, ref):
    entries = [m for m in read_index(root)["manifests"]
               if m["annotations"]["org.opencontainers.image.ref.name"] == ref]
    assert len(entries) == 1, f"expected exactly one {ref} entry, got {len(entries)}"
    return entries[0]


class TestAddErofsImage(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.layout = os.path.join(self.tmp.name, "layout")
        self.src = os.path.join(self.tmp.name, "src")
        os.makedirs(self.src)
        for name, data in (("kernel", b"vmlinuz-ish"), ("runx-initrd", b"initrd-ish")):
            p = os.path.join(self.src, name)
            with open(p, "wb") as f:
                f.write(data)
            os.chmod(p, 0o666)
        run_tool(self.layout, "eve-external-boot-image", self.src)

    def tearDown(self):
        self.tmp.cleanup()

    def extract_layer(self, man, name):
        """Unpack a manifest's single EROFS layer, preserving modes."""
        img = os.path.join(self.tmp.name, name + ".erofs")
        with open(img, "wb") as f:
            f.write(read_blob(self.layout, man["layers"][0]["digest"]))
        out = os.path.join(self.tmp.name, name)
        subprocess.run(["fsck.erofs", "--extract=" + out, "--preserve-perms", img],
                       check=True, capture_output=True)
        return out

    def manifest(self):
        entry = only_manifest(self.layout, "eve-external-boot-image")
        return entry, json.loads(read_blob(self.layout, entry["digest"]))

    def test_layout_is_well_formed(self):
        with open(os.path.join(self.layout, "oci-layout")) as f:
            self.assertEqual(json.load(f)["imageLayoutVersion"], "1.0.0")
        entry, man = self.manifest()
        self.assertEqual(entry["size"], len(read_blob(self.layout, entry["digest"])))
        self.assertEqual(entry["platform"], {"architecture": "amd64", "os": "linux"})
        self.assertEqual(man["mediaType"], "application/vnd.oci.image.manifest.v1+json")

    def test_layer_media_type_selects_native_path(self):
        # containerd: isErofsMediaType() -- must end in ".erofs" and carry no
        # "+suffix", else the differ falls through to mkfs/tar handling.
        _, man = self.manifest()
        mt = man["layers"][0]["mediaType"]
        self.assertTrue(mt.endswith(".erofs"), mt)
        self.assertNotIn("+", mt)

    def test_diff_id_equals_layer_digest(self):
        # The unpacker compares Apply()'s returned digest to config.diff_ids[i];
        # the native path returns the layer descriptor unchanged.
        _, man = self.manifest()
        cfg = json.loads(read_blob(self.layout, man["config"]["digest"]))
        self.assertEqual(cfg["rootfs"]["diff_ids"], [man["layers"][0]["digest"]])
        self.assertEqual(cfg["architecture"], "amd64")
        self.assertEqual(cfg["os"], "linux")

    def test_blob_digest_and_size_match_content(self):
        _, man = self.manifest()
        layer = man["layers"][0]
        blob = read_blob(self.layout, layer["digest"])
        self.assertEqual("sha256:" + hashlib.sha256(blob).hexdigest(), layer["digest"])
        self.assertEqual(len(blob), layer["size"])

    def test_layer_root_is_traversable(self):
        # BuildKit's COPY --chmod stamps the mode on the parent directories
        # it creates, so the source root arrives with the file mode (0664 in
        # the kube-images build, run as root). Whatever it is, the layer root
        # must come out traversable, or the non-root user KubeVirt runs
        # container-disk as cannot read the files. 0700 stands in for that
        # here: same defect, still readable by the unprivileged test.
        os.chmod(self.src, 0o700)
        run_tool(self.layout, "tight-root", self.src)
        entry = only_manifest(self.layout, "tight-root")
        man = json.loads(read_blob(self.layout, entry["digest"]))
        out = self.extract_layer(man, "tight-root-extract")
        self.assertEqual(os.stat(out).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(os.path.join(out, "kernel")).st_mode & 0o777, 0o666)

    def test_layer_is_a_real_erofs_holding_the_files(self):
        _, man = self.manifest()
        blob = read_blob(self.layout, man["layers"][0]["digest"])
        self.assertEqual(blob[1024:1028], EROFS_MAGIC)
        out = self.extract_layer(man, "extracted")
        with open(os.path.join(out, "kernel"), "rb") as f:
            self.assertEqual(f.read(), b"vmlinuz-ish")
        with open(os.path.join(out, "runx-initrd"), "rb") as f:
            self.assertEqual(f.read(), b"initrd-ish")

    def test_rerun_replaces_and_is_deterministic(self):
        before = only_manifest(self.layout, "eve-external-boot-image")
        run_tool(self.layout, "eve-external-boot-image", self.src)
        after = only_manifest(self.layout, "eve-external-boot-image")
        self.assertEqual(before["digest"], after["digest"])

    def test_other_refs_are_left_alone(self):
        run_tool(self.layout, "some-other-image", self.src)
        self.assertEqual(len(read_index(self.layout)["manifests"]), 2)
        only_manifest(self.layout, "eve-external-boot-image")

    def test_arch_override(self):
        run_tool(self.layout, "arm-image", self.src, "--arch", "arm64")
        entry = only_manifest(self.layout, "arm-image")
        man = json.loads(read_blob(self.layout, entry["digest"]))
        cfg = json.loads(read_blob(self.layout, man["config"]["digest"]))
        self.assertEqual(cfg["architecture"], "arm64")
        self.assertEqual(entry["platform"]["architecture"], "arm64")


if __name__ == "__main__":
    unittest.main()
