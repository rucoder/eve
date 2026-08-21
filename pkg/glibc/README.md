# eve-glibc

This package installs the GNU C library (glibc) and its runtime companion
`libgcc-s1` into a directory tree that gets layered into the EVE rootfs
**alongside** the existing Alpine/musl userland. It is an init-style
linuxkit package (no `config:` section in `build.yml`) -- it contributes
files to the rootfs, it does not run as a service.

The files are harvested unmodified from a stock `ubuntu:24.04` image
(which already has `libc6` and `libgcc-s1` installed) using
`dpkg -L libc6 libgcc-s1`, filtered down to regular files and symlinks
(package-owned directories are skipped), and excluding anything under
`/usr/share` (docs, locales, man pages) to keep the package small. See
the `Dockerfile` for the exact selection logic.

## Why this is needed

EVE's host rootfs is Alpine-based and links against musl libc. NVIDIA's
host-side tooling (`nvidia-ctk`, `nvidia-smi`, `nvidia-persistenced`,
etc.) is distributed as glibc-linked Ubuntu binaries. Those binaries
cannot run against musl, so a glibc runtime has to be present on the
device for them to work at all.

This package is also the first concrete step of a longer-running plan to
move parts of EVE's userland (starting with `pillar` and the kube
container) onto an Ubuntu base. Landing the C runtime on its own, with
nothing depending on it yet, lets that migration proceed incrementally
instead of as one large cutover.

## Why glibc and musl can coexist without conflict

Installing a second libc into the same rootfs sounds risky, but glibc
and musl do not collide, for a few independent reasons:

- **Different ELF interpreters.** A glibc binary's `PT_INTERP` points at
  `/lib64/ld-linux-x86-64.so.2`; a musl binary's points at
  `/lib/ld-musl-x86_64.so.1`. Each binary carries its own loader path,
  baked in at link time -- there is no shared/ambiguous interpreter to
  fight over.
- **Different sonames.** glibc's C library is `libc.so.6`; musl's is
  `libc.musl-x86_64.so.1`. They are never the same file, and nothing
  resolves one name to the other.
- **Different library directories.** The harvested glibc files live
  under `/lib/x86_64-linux-gnu/` (and `/usr/lib/x86_64-linux-gnu/` where
  applicable) -- a directory Alpine's toolchain and package set never
  populates or searches.
- **Different cache/lookup mechanisms.** glibc's loader consults
  `/etc/ld.so.cache` (built here at image build time via
  `ldconfig -r /staging`); musl's loader consults
  `/etc/ld-musl-x86_64.path`. Each loader only ever reads its own
  mechanism.

Because each binary's `PT_INTERP` is an absolute path resolved once at
link time, a glibc binary always finds glibc's loader and a musl binary
always finds musl's -- automatically, with no wrapper script, `chroot`,
or `LD_PRELOAD` trick required to keep the two apart.

## Scope: amd64 only, for now

This package currently only populates content on `amd64`. The harvested
paths bake in the Debian/Ubuntu multiarch triplet
(`x86_64-linux-gnu`), which is x86_64-specific by construction. On
`arm64`/`riscv64` the package builds but stages nothing (see the
`Dockerfile`'s arch-gated stages), producing an empty layer. Extending
this to `arm64` requires handling the `aarch64-linux-gnu` triplet as its
own case, not just pointing the same Dockerfile logic at a different
base image.

## What is deliberately NOT here

The NVIDIA host tooling also depends on a handful of non-glibc runtime
libraries -- `libcap`, `libtirpc`, `libbsd`, `libmd`, `libssl` -- that
are not part of glibc or `libgcc-s1`. Those are intentionally excluded
from this package. They already ship inside the `nvidia-dgpu` package's
own vendor directory and are located at runtime via `LD_LIBRARY_PATH`,
not the system library path. Keeping them there (rather than adding them
here) keeps `eve-glibc` scoped to exactly the C runtime itself, which is
the piece that genuinely needs to live at the rootfs level rather than
inside a single consumer's vendor directory.
