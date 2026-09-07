# pkg/fw

Firmware for EVE devices. The Dockerfile builds one of two variants,
selected by the `FW_SOURCE` build argument:

- `upstream` (default): a per-device curated set from the kernel.org
  linux-firmware tarball plus several vendor sources.
- `ubuntu`: the full Ubuntu 24.04 `linux-firmware` package set, unpacked
  from the Ubuntu .debs on top of eve-alpine. Used by `HV=k` builds
  (`build-k.yml` passes `FW_SOURCE=ubuntu`).

## Firmware from ubuntu

The per-architecture `ADD` lines in the `alpine-base-*` stages are
generated from what apt would install on Ubuntu 24.04. To regenerate
them (e.g. when bumping linux-firmware), build the following Dockerfile
once per architecture and paste the printed `ADD` lines into the matching
stage:

```dockerfile
FROM ubuntu:24.04

RUN apt-get update
RUN apt-get --print-uris install linux-firmware | perl -ne 'print "ADD $1 /debs/\n" if m/^\x27(http\S+)\x27/;'
```

```sh
docker build --no-cache --progress=plain --platform linux/arm64 -f Dockerfile.fwurls .
```

Without `--progress=plain` BuildKit hides the RUN output that contains
the URLs. linux-firmware pulls in firmware-sof-signed (a Recommends), so
both URLs appear; wireless-regdb is not part of that closure and is
pinned separately via `UBUNTU_WIRELESS_REGDB_VERSION`, as are the
microcode packages via the `UBUNTU_*_UCODE_VERSION` variables.

## Show SBOM

syft reads the records the build registers in `/lib/apk/db/installed`:

```sh
syft $(docker build --build-arg FW_SOURCE=ubuntu -qt fw .) -o json \
    | jq -c '.artifacts[] | {name, version, licenses: [.licenses[].value]}'
```

(drop the `--build-arg` for the upstream variant)

For the Ubuntu variant, name, version and licenses are extracted from
the .debs themselves (see `deb-licenses.pl`). A package whose copyright
file has no structured license data -- linux-firmware bundles ~100
vendor licences -- is reported as `LicenseRef-<package>-copyright`, and
the image ships each package's copyright file under
`/usr/share/doc/<package>/` so that reference resolves on the device.

## Show files in final docker image

```sh
C=$(docker create $(docker build --build-arg FW_SOURCE=ubuntu -qt fw .) true)
docker export "$C" | tar -t | sort
docker rm "$C"
```

This way changes can be observed when updating the Dockerfile.
