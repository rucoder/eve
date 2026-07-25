# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Read-only payload volume that ships the container images kube-init
# needs at first boot: the upstream images (KubeVirt, CDI, Longhorn,
# Multus, kube-vip) plus one EVE-authored image (external-boot-image,
# folded in here from its docker-archive tar).
#
# The payload is a single self-contained EROFS image
# (kube-images.erofs) holding a standard OCI image layout. At boot
# the linuxkit rootfs binds this container's / at /images inside the
# kube container (see images/modifiers/hv/k.yq), and kube-init mounts
# /images/kube-images.erofs read-only with `mount -t erofs` — no loop
# device (CONFIG_EROFS_FS_BACKED_BY_FILE) — exposing the OCI layout so
# it can register the images with the k3s user-containerd without a
# network pull. See .claude/design/kube-images-composefs.md.
#
# Self-contained (blobs inline), not composefs-with-digest-store: the
# runtime needs only a plain `mount -t erofs`, no mount.composefs
# helper on the device. OCI layer blobs are gzip-compressed by
# default; LAYER_FORMAT=uncompressed (the default here) rewrites them
# to uncompressed so the EROFS's own compression (EROFS_COMPRESSION,
# default zstd) can work on them instead of re-compressing already
# packed gzip streams for no size win. Both knobs are build-args, so
# gzip+uncompressed-erofs remains selectable when that trade-off is
# preferred (e.g. to avoid EROFS_FS_ZIP on the kernel side).

# hadolint ignore=DL3007
FROM alpine:3.22 AS build

ARG LAYER_FORMAT=uncompressed
# Alpine's erofs-utils supports lz4/lz4hc only (no zstd); the kernel
# decodes lz4 via CONFIG_EROFS_FS_ZIP. Value is passed straight to
# mkfs.erofs -z<algo>; "none" builds an uncompressed filesystem.
ARG EROFS_COMPRESSION=lz4hc

# skopeo pulls the upstream images and reads external-boot-image from
# its docker-archive tar; python3 runs oci-uncompress-layers.py when
# LAYER_FORMAT=uncompressed; mkfs.erofs (erofs-utils) builds the
# image. All discarded — only /out survives into the final stage.
# hadolint ignore=DL3018
RUN apk add --no-cache skopeo erofs-utils python3

WORKDIR /w
COPY upstream-images.list /w/upstream-images.list
COPY external-boot-image.tar /w/external-boot-image.tar
COPY oci-uncompress-layers.py /w/oci-uncompress-layers.py

# Assemble a shared OCI image layout, then pack it into one EROFS
# image:
#   1) skopeo copy every upstream ref from the generated list into a
#      single OCI layout (skopeo dedups blobs by digest within it).
#      skopeo sync can't target an OCI layout (docker/dir only), so
#      this is a copy per ref.
#   2) skopeo copy external-boot-image separately: it comes from a
#      docker-archive: tar, not a registry.
#   3) optionally rewrite layers to uncompressed (LAYER_FORMAT).
#   4) mkfs.erofs the layout dir into a self-contained image, with
#      EROFS_COMPRESSION selecting the -z<algo> or none.
#
# BuildKit's --mount=type=cache persists /oci-cache across rebuilds,
# so bumping one image only re-pulls that image.
RUN --mount=type=cache,target=/oci-cache \
    set -eu; \
    mkdir -p /oci-cache/oci-layout /out; \
    while read -r ref; do \
        [ -n "$ref" ] || continue; \
        dest=$(printf '%s' "$ref" | tr '/:' '__'); \
        echo "[skopeo] $ref"; \
        skopeo copy --preserve-digests \
            "docker://$ref" \
            "oci:/oci-cache/oci-layout:$dest"; \
    done < /w/upstream-images.list; \
    echo "[skopeo] external-boot-image (docker-archive)"; \
    skopeo copy --preserve-digests \
        docker-archive:/w/external-boot-image.tar \
        oci:/oci-cache/oci-layout:eve-external-boot-image; \
    # Ship the real-name ref list inside the image so kube-init can
    # map skopeo's sanitised OCI ref names back to the registry refs
    # kubelet expects (see images.retagUpstream).
    cp /w/upstream-images.list /oci-cache/oci-layout/upstream-images.list; \
    if [ "$LAYER_FORMAT" = uncompressed ]; then \
        echo "[uncompress] rewriting layers"; \
        python3 /w/oci-uncompress-layers.py /oci-cache/oci-layout; \
    fi; \
    z=""; [ "$EROFS_COMPRESSION" = none ] || z="-z$EROFS_COMPRESSION"; \
    echo "[mkfs.erofs] kube-images.erofs ($LAYER_FORMAT, ${EROFS_COMPRESSION})"; \
    mkfs.erofs $z /out/kube-images.erofs /oci-cache/oci-layout

FROM scratch
COPY --from=build /out/kube-images.erofs /
