FROM lfedge/eve-alpine:530b791100e08d3e89ca2236fe05a6d072b26c43 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools sfdisk sgdisk xfsprogs \
         e2fsprogs util-linux coreutils multipath-tools squashfs-tools
RUN eve-alpine-deploy.sh

COPY . /out/

FROM scratch
COPY --from=build /out/ /
ENTRYPOINT [ "/make-rootfs" ]
