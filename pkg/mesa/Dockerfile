# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Mesa and libglvnd, built from source for EVE's two GPU users:
#
#   pkg/monitor  the graphical console: GBM + EGL + GLES2 on iris
#   pkg/qemu     the D-Bus display and virglrenderer: EGL + desktop GL
#
# The image is a /usr tree (libraries, headers, pkg-config files, glvnd and
# driconf data) for consumers to copy from. It does not run.
#
# No LLVM at run time. Alpine's mesa links libLLVM (178MB) into libgallium
# for llvmpipe and the AMD drivers, none of which EVE uses. iris needs LLVM
# only at build time: its internal shaders are OpenCL C, compiled by
# mesa_clc and turned into C by vtn_bindgen2. So Mesa is configured twice
# from one source tree: once with LLVM to build those two tools, and once
# with -Dllvm=disabled -Dmesa-clc=system for everything that ships. The LLVM
# packages stay in this build stage.
#
# libglvnd, because of libepoxy. QEMU and virglrenderer use desktop GL
# through epoxy, which resolves the GL 1.x entry points by dlopen()ing
# libGL.so.1 or libOpenGL.so.0 and aborts if neither exists. Mesa's own
# libGL is the GLX one and needs X11; glvnd's libOpenGL.so.0 does not.
#
# Drivers:
#   iris   Intel Gen9 onwards, under i915 or xe.
#   virgl  for EVE running as a VM on a virtio-gpu with virgl.
#   intel-virtio-experimental  iris over i915 native context, for EVE
#          running as a VM on a host that offers it.
# Anything else gets no GL: the console falls back to the TUI and guests to
# -display none.

FROM lfedge/eve-alpine:1d60238fe336a7782fb173fed1be692246a27dfa AS build
ENV BUILD_PKGS="build-base meson samurai pkgconf python3 py3-packaging \
    bison flex linux-headers libdrm-dev expat-dev zlib-dev zstd-dev"
RUN eve-alpine-deploy.sh

# TEMPORARY: not in the eve-alpine mirror yet, so fetched from Alpine
# (network: yes in build.yml). Move them to BUILD_PKGS once the list is
# final. The LLVM set is for mesa_clc, which only the Intel drivers need.
# clang20-dev is in the mirror but is taken from the same repository as
# llvm20-dev so the two cannot disagree on llvm20-libs.
# hadolint ignore=DL3018
RUN apk add --no-cache --repositories-file /etc/apk/repositories.upstream \
        py3-mako py3-yaml && \
    if [ "$(uname -m)" = x86_64 ]; then \
        apk add --no-cache --repositories-file /etc/apk/repositories.upstream \
            llvm20-dev clang20-dev spirv-llvm-translator-dev spirv-tools-dev; \
    fi

ENV LIBGLVND_VERSION=1.7.0
ENV MESA_VERSION=26.2.4
# hadolint ignore=DL3020
ADD --checksum=sha256:2b6e15b06aafb4c0b6e2348124808cbd9b291c647299eaaba2e3202f51ff2f3d \
    https://gitlab.freedesktop.org/glvnd/libglvnd/-/archive/v${LIBGLVND_VERSION}/libglvnd-v${LIBGLVND_VERSION}.tar.gz /libglvnd.tar.gz
# hadolint ignore=DL3020
ADD --checksum=sha256:bce5f7fbebb934373b86c999a064d52fb5065878dc57f287f95346648ec832e9 \
    https://archive.mesa3d.org/mesa-${MESA_VERSION}.tar.xz /mesa.tar.xz
RUN mkdir -p /src && \
    tar -C /src -xzf /libglvnd.tar.gz && \
    tar -C /src -xJf /mesa.tar.xz

# Everything that ships is installed under /dist. It is also installed into
# the build root, because Mesa builds against libglvnd.
WORKDIR /src/libglvnd-v${LIBGLVND_VERSION}
RUN meson setup /build/libglvnd --prefix=/usr --buildtype=release \
        -Dx11=disabled -Dglx=disabled -Degl=true -Dgles1=false -Dgles2=true && \
    meson compile -C /build/libglvnd && \
    meson install -C /build/libglvnd --destdir /dist --strip && \
    meson install -C /build/libglvnd

# Pass 1, amd64 only: mesa_clc and vtn_bindgen2, the build-time shader
# compilers. They must come from the same Mesa as the drivers, because
# vtn_bindgen2 generates code against that version's NIR.
WORKDIR /src/mesa-${MESA_VERSION}
RUN if [ "$(uname -m)" = x86_64 ]; then \
        meson setup /build/mesa-clc --buildtype=release \
            -Dllvm=enabled -Dmesa-clc=enabled -Dinstall-mesa-clc=true \
            -Dgallium-drivers= -Dvulkan-drivers= -Dplatforms= -Dglx=disabled \
            -Degl=disabled -Dgbm=disabled -Dopengl=false -Dgles1=disabled \
            -Dgles2=disabled -Dvalgrind=disabled -Dlibunwind=disabled \
            -Dlmsensors=disabled && \
        ninja -C /build/mesa-clc src/compiler/clc/mesa_clc \
            src/compiler/spirv/vtn_bindgen2 && \
        install -m 755 /build/mesa-clc/src/compiler/clc/mesa_clc \
            /build/mesa-clc/src/compiler/spirv/vtn_bindgen2 /usr/local/bin/; \
    fi

# Pass 2: what ships. Other architectures build virgl only, which needs no
# mesa_clc and so no LLVM at all.
RUN case "$(uname -m)" in \
        x86_64) ARCH_OPTS="-Dgallium-drivers=iris,virgl -Dmesa-clc=system \
                           -Dintel-virtio-experimental=true -Dintel-elk=false" ;; \
        *)      ARCH_OPTS="-Dgallium-drivers=virgl" ;; \
    esac && \
    meson setup /build/mesa --prefix=/usr --buildtype=release -Db_ndebug=true \
        $ARCH_OPTS -Dllvm=disabled -Dvulkan-drivers= \
        -Dplatforms= -Dglx=disabled -Dglvnd=enabled \
        -Degl=enabled -Dgbm=enabled -Dopengl=true -Dgles1=disabled -Dgles2=enabled \
        -Dgallium-va=disabled -Dgallium-rusticl=false -Dvideo-codecs= \
        -Dspirv-tools=disabled -Dvalgrind=disabled -Dlibunwind=disabled \
        -Dlmsensors=disabled -Dzstd=enabled && \
    meson compile -C /build/mesa && \
    meson install -C /build/mesa --destdir /dist --strip

# Fail the build if anything that ships still reaches for LLVM, or if glvnd
# would find no vendor: without 50_mesa.json libEGL.so.1 loads and then
# reports no display.
RUN set -e; \
    for f in $(find /dist -name '*.so*' -type f); do \
        if readelf -d "$f" | grep -q 'NEEDED.*libLLVM'; then \
            echo "ERROR: $f links LLVM"; exit 1; \
        fi; \
    done; \
    test -f /dist/usr/share/glvnd/egl_vendor.d/50_mesa.json; \
    test -e /dist/usr/lib/libEGL_mesa.so.0; \
    test -e /dist/usr/lib/libOpenGL.so.0

RUN register-sbom-pkg.sh -o /dist -n libglvnd -v "${LIBGLVND_VERSION}" \
        -l "MIT-Khronos-old AND MIT" -u https://gitlab.freedesktop.org/glvnd/libglvnd && \
    register-sbom-pkg.sh -o /dist -n mesa -v "${MESA_VERSION}" \
        -l "MIT AND SGI-B-2.0 AND BSL-1.0" -u https://mesa3d.org

FROM scratch
COPY --from=build /dist/ /
