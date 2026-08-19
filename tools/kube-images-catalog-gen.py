#!/usr/bin/env python3
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
"""kube-images-catalog-gen.py.

Auto-derives pkg/kube-images/upstream-images.list from the source
YAMLs and Go constants that already carry the pinned image versions
the running cluster consumes. The output is a plain, sorted list of
fully-qualified image references, one per line:

    docker.io/longhornio/longhorn-manager:v1.9.1
    ghcr.io/k8snetworkplumbingwg/multus-cni:v3.9.3
    quay.io/kubevirt/virt-operator:v1.7.3
    ...

pkg/kube-images/Dockerfile loops over that file, `skopeo copy`-ing
each ref into the shared OCI image layout that becomes the
kube-images payload.

The committed list is hand-maintained: every ref additionally carries
a resolved @sha256 index digest, which this generator cannot derive
offline. `make kube-images-catalog-check` therefore only verifies the
name:tag part of each line against this derivation, so CI catches a
version bump in the deploy manifests that the list missed.

Sources of truth per family:

  * KubeVirt operator + virt-* pods (5) — one tag drives all
      pkg/kube/kubevirt-operator.yaml — reads virt-operator's tag,
      expands to virt-{operator,api,controller,handler,launcher} at
      the same tag (KubeVirt convention).

  * Multus CNI (1)
      pkg/kube/multus-daemonset.yaml

  * Longhorn + CSI sidecars (13)
      the lh-cfg-vX.Y.Z.yaml pointed at by the `longhornCfg` const
      in pkg/kube/kube-init/components/components.go. Every
      longhornio/ image ref inside is captured — image: lines,
      env-var value: strings, --engine-image / --instance-manager-
      image args.

  * kube-vip + kube-vip-cloud-provider (2)
      pkg/kube/kubevip-ds.yaml, pkg/kube/kubevip-sa.yaml.

  * CDI operator + subordinates (7) — one const drives all
      the `cdiVersion` const in components.go, expanded to
      cdi-{operator,apiserver,controller,importer,cloner,
      uploadproxy,uploadserver} at that tag (CDI convention).

Deliberately NOT in the list:

  * external-boot-image (EVE-authored) — not pulled at all: kube-init
    assembles and registers it on the device from the kernel and
    runx-initrd already in the rootfs (see
    pkg/kube/kube-init/images/bootimage.go).

  * descheduler, system-upgrade-controller, alpine — no local
    source of truth on this branch. They land upstream when
    rt-operator-manifests comes in from rt-k8s (each ships its
    own YAML pin).
"""

import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    sys.exit(
        "ERROR: PyYAML not installed. `pip install pyyaml` (or install the "
        "system 'python3-yaml' package)."
    )

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPONENTS_GO = REPO / "pkg/kube/kube-init/components/components.go"
VERSIONS_GO = REPO / "pkg/kube/kube-init/versions/versions.go"

# Well-formed image ref: <host-or-repo>/<name>[:tag].
IMAGE_REF_RE = re.compile(
    r"[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9._-]+)+:[a-zA-Z0-9._+-]+"
)


# One term of a Go const expression: a string literal or a versions.X
# reference. The pinned versions live in their own package, so a const
# here is typically a concatenation of the two ("/etc/lh-cfg-" +
# versions.Longhorn + ".yaml").
GO_TERM_RE = re.compile(r'"([^"]*)"|versions\.([A-Za-z0-9_]+)')


def read_go_const(name: str, source: pathlib.Path = COMPONENTS_GO) -> str:
    """Return the value of a single-line Go const, resolving versions.X."""
    text = source.read_text()
    match = re.search(rf"^\s*{name}\s*=\s*(.+)$", text, re.M)
    if not match:
        sys.exit(f"ERROR: const {name!r} not found in {source}")
    return eval_go_expr(match.group(1).split("//")[0].strip(), name, source)


def eval_go_expr(expr: str, name: str, source: pathlib.Path) -> str:
    """Concatenate a `"lit" + versions.X + "lit"` expression.

    Deliberately strict: anything else (a function call, a const from a
    third package, a multi-line expression) exits rather than silently
    yielding a truncated version, which would produce a catalog missing
    the tag entirely.
    """
    parts, pos = [], 0
    for m in GO_TERM_RE.finditer(expr):
        if expr[pos:m.start()].strip() not in ("", "+"):
            sys.exit(f"ERROR: cannot evaluate const {name!r} in {source}: {expr!r}")
        lit, ver = m.group(1), m.group(2)
        parts.append(lit if lit is not None else read_version(ver))
        pos = m.end()
    if not parts or expr[pos:].strip() != "":
        sys.exit(f"ERROR: cannot evaluate const {name!r} in {source}: {expr!r}")
    return "".join(parts)


def read_version(name: str) -> str:
    """Return the value of a const in the versions package."""
    match = re.search(rf'^\s*{name}\s*=\s*"([^"]+)"',
                      VERSIONS_GO.read_text(), re.M)
    if not match:
        sys.exit(f"ERROR: const {name!r} not found in {VERSIONS_GO}")
    return match.group(1)


def _walk_yaml_for_refs(node, out: set):
    """Recursively collect every image-ref-shaped string under `node`.

    Catches both `image: registry/name:tag` (dict entries) and
    Longhorn's `value: "longhornio/foo:v"` env-var strings and
    `--engine-image "longhornio/foo:v"` argument list entries.
    """
    if isinstance(node, dict):
        for v in node.values():
            _walk_yaml_for_refs(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk_yaml_for_refs(v, out)
    elif isinstance(node, str):
        for m in IMAGE_REF_RE.finditer(node):
            out.add(m.group(0))


def image_refs_matching(path: pathlib.Path, pattern: re.Pattern) -> set:
    """Every image ref in `path` whose full form matches `pattern`."""
    found: set = set()
    with path.open() as fp:
        for doc in yaml.safe_load_all(fp):
            if doc is not None:
                _walk_yaml_for_refs(doc, found)
    return {r for r in found if pattern.search(r)}


def one_ref(path: pathlib.Path, pattern: re.Pattern) -> str:
    """Fail if `pattern` doesn't match exactly one ref in `path`."""
    matches = image_refs_matching(path, pattern)
    if len(matches) != 1:
        sys.exit(
            f"ERROR: expected exactly one image matching {pattern.pattern} "
            f"in {path}, got {sorted(matches)}"
        )
    return matches.pop()


def main() -> None:
    lh_cfg_const = read_go_const("longhornCfg")
    lh_cfg = REPO / "pkg/kube" / pathlib.Path(lh_cfg_const).name
    if not lh_cfg.is_file():
        sys.exit(f"ERROR: longhorn config {lh_cfg} not found on disk")

    cdi_version = read_go_const("cdiVersion")

    kubevirt_version = one_ref(
        REPO / "pkg/kube/kubevirt-operator.yaml",
        re.compile(r"^quay\.io/kubevirt/virt-operator:"),
    ).split(":", 1)[1]

    multus_ref = one_ref(
        REPO / "pkg/kube/multus-daemonset.yaml",
        re.compile(r"^ghcr\.io/k8snetworkplumbingwg/multus-cni:"),
    )
    kubevip_ref = one_ref(
        REPO / "pkg/kube/kubevip-ds.yaml",
        re.compile(r"^ghcr\.io/kube-vip/kube-vip:"),
    )
    kubevip_cloud_ref = one_ref(
        REPO / "pkg/kube/kubevip-sa.yaml",
        re.compile(r"^ghcr\.io/kube-vip/kube-vip-cloud-provider:"),
    )
    longhorn_refs = image_refs_matching(lh_cfg, re.compile(r"^longhornio/"))

    refs: set = set()

    # KubeVirt (5, same tag by convention).
    for name in ("virt-operator", "virt-api", "virt-controller",
                 "virt-handler", "virt-launcher"):
        refs.add(f"quay.io/kubevirt/{name}:{kubevirt_version}")

    # CDI (7, same tag by convention).
    for name in ("cdi-operator", "cdi-apiserver", "cdi-controller",
                 "cdi-importer", "cdi-cloner", "cdi-uploadproxy",
                 "cdi-uploadserver"):
        refs.add(f"quay.io/kubevirt/{name}:{cdi_version}")

    # Single-ref families.
    refs.update((multus_ref, kubevip_ref, kubevip_cloud_ref))

    # Longhorn (13). longhornio/ resolves under docker.io by default;
    # spell it out so the loop pulls from the same URL skopeo would.
    for ref in longhorn_refs:
        refs.add(f"docker.io/{ref}")

    for ref in sorted(refs):
        print(ref)


if __name__ == "__main__":
    main()
