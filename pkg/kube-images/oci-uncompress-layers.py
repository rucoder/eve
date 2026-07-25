#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Rewrite an OCI image layout in place so gzip layers become uncompressed
tar. containerd then untars without gunzip at container start. The config
blob is never touched: a layer's diffID is already its uncompressed digest,
so after decompression layer.digest == diffID and the config still matches."""
import gzip, hashlib, json, os, sys

REF_ANNOTATION = "org.opencontainers.image.ref.name"

def blob_path(root, digest): return os.path.join(root, "blobs", "sha256", digest.split(":", 1)[1])

def read_json(root, digest):
    with open(blob_path(root, digest), "rb") as f: return json.load(f)

def write_blob(root, data):
    d = "sha256:" + hashlib.sha256(data).hexdigest()
    p = blob_path(root, d)
    if not os.path.exists(p):
        with open(p, "wb") as f: f.write(data)
    return d, len(data)

def uncompressed_mt(mt):
    if mt.endswith("+gzip"): return mt[: -len("+gzip")]
    if mt.endswith(".gzip"): return mt[: -len(".gzip")]
    return mt

def rewrite_manifest(root, digest):
    man = read_json(root, digest)
    changed = False
    for lyr in man.get("layers", []):
        p = blob_path(root, lyr["digest"])
        with open(p, "rb") as f:
            head = f.read(2)
        mt = lyr.get("mediaType", "")
        if head == b"\x1f\x8b":
            # Genuinely gzip (magic bytes): decompress to a new uncompressed
            # blob and relabel. Sniff the content, never trust the mediaType —
            # docker-save layers arrive as plain tar yet are labeled tar.gzip.
            with open(p, "rb") as f:
                raw = gzip.decompress(f.read())
            nd, nsz = write_blob(root, raw)
            lyr["digest"], lyr["size"], lyr["mediaType"] = nd, nsz, uncompressed_mt(mt)
            changed = True
        elif "gzip" in mt:
            # Already-uncompressed tar mislabeled as gzip: fix only the
            # mediaType; the blob (and its digest/size) is already correct.
            lyr["mediaType"] = uncompressed_mt(mt)
            changed = True
        # else: uncompressed and correctly labeled — leave it.
    if not changed:
        return digest, os.path.getsize(blob_path(root, digest)), False
    data = json.dumps(man, separators=(",", ":")).encode()
    nd, nsz = write_blob(root, data)
    return nd, nsz, True

def rewrite_descriptor(root, desc):
    """Returns True if desc was updated (digest/size changed)."""
    mt = desc.get("mediaType", "")
    if mt.endswith("index.v1+json") or mt.endswith("manifest.list.v2+json"):
        idx = read_json(root, desc["digest"]); changed = False
        for sub in idx.get("manifests", []):
            if rewrite_descriptor(root, sub): changed = True
        if not changed: return False
        data = json.dumps(idx, separators=(",", ":")).encode()
        nd, nsz = write_blob(root, data)
        desc["digest"], desc["size"] = nd, nsz
        return True
    nd, nsz, changed = rewrite_manifest(root, desc["digest"])
    if changed: desc["digest"], desc["size"] = nd, nsz
    return changed

def reachable_digests(root, desc, out):
    """Walk a manifests-list entry (index.json descriptor or a nested one),
    collecting every digest still referenced: the descriptor's own blob,
    and — for a manifest — its config and every layer digest."""
    out.add(desc["digest"])
    mt = desc.get("mediaType", "")
    if mt.endswith("index.v1+json") or mt.endswith("manifest.list.v2+json"):
        idx = read_json(root, desc["digest"])
        for sub in idx.get("manifests", []):
            reachable_digests(root, sub, out)
        return
    man = read_json(root, desc["digest"])
    if "config" in man:
        out.add(man["config"]["digest"])
    for lyr in man.get("layers", []):
        out.add(lyr["digest"])

def prune_unreachable_blobs(root, index):
    """Delete every blob under blobs/sha256/ that index.json's manifests no
    longer reach: superseded gzip layers and pre-rewrite manifest/index
    blobs. Keeps the layout from shipping each layer both compressed and
    uncompressed."""
    live = set()
    for desc in index.get("manifests", []):
        reachable_digests(root, desc, live)
    live_hex = {d.split(":", 1)[1] for d in live}
    blobs_dir = os.path.join(root, "blobs", "sha256")
    for name in os.listdir(blobs_dir):
        if name not in live_hex:
            os.remove(os.path.join(blobs_dir, name))

def drop_nameless(index):
    """Remove index entries that carry no ref name.

    BuildKit's --mount=type=cache persists the layout across builds, and
    skopeo supersedes an existing ref by stripping the name off the old
    entry rather than removing it. kube-init addresses images by ref name,
    so a nameless entry is unreachable — but it still counts as a root in
    the prune below, which would pin a bumped image's old layers in the
    payload forever."""
    index["manifests"] = [m for m in index.get("manifests", [])
                          if m.get("annotations", {}).get(REF_ANNOTATION)]


def main(root):
    ip = os.path.join(root, "index.json")
    with open(ip) as f: index = json.load(f)
    drop_nameless(index)
    for desc in index.get("manifests", []):
        rewrite_descriptor(root, desc)   # mutates desc in place, preserves annotations
    with open(ip, "w") as f: json.dump(index, f, separators=(",", ":"))
    prune_unreachable_blobs(root, index)

if __name__ == "__main__":
    main(sys.argv[1])
