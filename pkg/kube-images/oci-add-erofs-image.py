#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Add a directory to an OCI image layout as a single-layer image whose
layer is a ready-made EROFS filesystem.

containerd's EROFS differ treats any layer media type ending in ".erofs"
as a native layer: it copies the blob straight into the snapshot instead
of running mkfs.erofs (plugins/diff/erofs/differ_linux.go, isErofsMediaType).
The unpacker's only check is that the applied digest equals the config's
diff_id, and for a native layer that digest IS the layer digest -- so the
config written here records the EROFS blob digest as the diff_id.

Used for EVE-authored images (external-boot-image), which are a handful of
files rather than a registry pull, so they never need the tar round-trip.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

# Any media type ending in ".erofs" (no "+suffix") selects the differ's
# native path; this is the name containerd's own docs use.
EROFS_LAYER_MT = "application/vnd.oci.image.layer.v1.erofs"
MANIFEST_MT = "application/vnd.oci.image.manifest.v1+json"
CONFIG_MT = "application/vnd.oci.image.config.v1+json"
INDEX_MT = "application/vnd.oci.image.index.v1+json"
REF_ANNOTATION = "org.opencontainers.image.ref.name"


def blob_path(root, digest):
    return os.path.join(root, "blobs", "sha256", digest.split(":", 1)[1])


def write_blob(root, data):
    d = "sha256:" + hashlib.sha256(data).hexdigest()
    p = blob_path(root, d)
    if not os.path.exists(p):
        with open(p, "wb") as f:
            f.write(data)
    return d, len(data)


def add_file_blob(root, src):
    h = hashlib.sha256()
    with open(src, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    d = "sha256:" + h.hexdigest()
    p = blob_path(root, d)
    if not os.path.exists(p):
        os.replace(src, p)
    return d, os.path.getsize(p)


def ensure_layout(root):
    os.makedirs(os.path.join(root, "blobs", "sha256"), exist_ok=True)
    lp = os.path.join(root, "oci-layout")
    if not os.path.exists(lp):
        with open(lp, "w") as f:
            json.dump({"imageLayoutVersion": "1.0.0"}, f, separators=(",", ":"))
    ip = os.path.join(root, "index.json")
    if not os.path.exists(ip):
        with open(ip, "w") as f:
            json.dump({"schemaVersion": 2, "mediaType": INDEX_MT, "manifests": []},
                      f, separators=(",", ":"))


ROOT_MODE = 0o755


def stage(srcdir, dest):
    """Link srcdir's contents under a root with a sane image-root mode.

    mkfs.erofs takes the source directory's own mode for the layer root,
    and a build step can easily leave that unusable: BuildKit's
    `COPY --chmod=666` stamps the mode on the parent directories it
    creates too, yielding a root without +x that no non-root process can
    traverse -- which is exactly how KubeVirt runs container-disk
    containers. Staging pins the root at 0755 while per-file modes ride
    along on the hardlinked inodes.
    """
    os.mkdir(dest, ROOT_MODE)
    for entry in os.listdir(srcdir):
        src, dst = os.path.join(srcdir, entry), os.path.join(dest, entry)
        if os.path.isdir(src) and not os.path.islink(src):
            shutil.copytree(src, dst, symlinks=True, copy_function=os.link)
            continue
        try:
            os.link(src, dst)
        except OSError:
            shutil.copy2(src, dst, follow_symlinks=False)
    os.chmod(dest, ROOT_MODE)


def mkfs_erofs(srcdir, out, ref, compression, timestamp):
    # --quiet -Enoinline_data mirrors containerd's own ConvertErofs so the
    # blob is byte-comparable with what the on-device differ would produce.
    # -U and -T pin the two sources of run-to-run variance (random UUID,
    # per-file and build timestamps); without them identical input yields a
    # different digest every build, which would re-register the image on the
    # device after a no-op rebuild. --force-uid/gid make the layer root-owned
    # regardless of who ran the build.
    args = ["mkfs.erofs", "--quiet", "-Enoinline_data",
            "--force-uid=0", "--force-gid=0",
            "-U", str(uuid.uuid5(uuid.NAMESPACE_URL, "erofs:" + ref)),
            "-T", str(timestamp)]
    if compression != "none":
        args.append("-z" + compression)
    args += [out, srcdir]
    subprocess.run(args, check=True)


def upsert_index_entry(root, entry):
    """Replace any entry carrying the same ref name, else append."""
    ip = os.path.join(root, "index.json")
    with open(ip) as f:
        index = json.load(f)
    ref = entry["annotations"][REF_ANNOTATION]
    manifests = [m for m in index.get("manifests", [])
                 if m.get("annotations", {}).get(REF_ANNOTATION) != ref]
    manifests.append(entry)
    index["manifests"] = manifests
    with open(ip, "w") as f:
        json.dump(index, f, separators=(",", ":"))


def add_image(root, ref, srcdir, arch, osname, compression, timestamp):
    ensure_layout(root)
    with tempfile.TemporaryDirectory(dir=root) as tmp:
        staged = os.path.join(tmp, "root")
        stage(srcdir, staged)
        raw = os.path.join(tmp, "layer.erofs")
        mkfs_erofs(staged, raw, ref, compression, timestamp)
        ldigest, lsize = add_file_blob(root, raw)

    config = {
        "architecture": arch,
        "os": osname,
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [ldigest]},
    }
    cdigest, csize = write_blob(root, json.dumps(config, separators=(",", ":")).encode())

    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST_MT,
        "config": {"mediaType": CONFIG_MT, "digest": cdigest, "size": csize},
        "layers": [{"mediaType": EROFS_LAYER_MT, "digest": ldigest, "size": lsize}],
    }
    mdigest, msize = write_blob(root, json.dumps(manifest, separators=(",", ":")).encode())

    upsert_index_entry(root, {
        "mediaType": MANIFEST_MT,
        "digest": mdigest,
        "size": msize,
        "annotations": {REF_ANNOTATION: ref},
        "platform": {"architecture": arch, "os": osname},
    })
    return mdigest, ldigest, lsize


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("layout", help="OCI image layout directory")
    ap.add_argument("ref", help="ref name recorded in index.json")
    ap.add_argument("srcdir", help="directory to pack as the image's only layer")
    ap.add_argument("--arch", default="amd64")
    ap.add_argument("--os", dest="osname", default="linux")
    ap.add_argument("--compression", default="lz4hc",
                    help="mkfs.erofs -z algorithm, or 'none'")
    ap.add_argument("--timestamp", type=int, default=0,
                    help="fixed UNIX timestamp for all files (mkfs.erofs -T)")
    a = ap.parse_args(argv)
    md, ld, lsz = add_image(a.layout, a.ref, a.srcdir, a.arch, a.osname,
                            a.compression, a.timestamp)
    print(f"[erofs-image] {a.ref} manifest={md} layer={ld} ({lsz} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
