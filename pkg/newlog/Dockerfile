# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM lfedge/eve-alpine:ab798ccee75f48f5a3be7027f70dc5f63843ddde AS build
ENV BUILD_PKGS git
ENV PKGS coreutils
RUN eve-alpine-deploy.sh

COPY go.mod /newlog/
COPY go.sum /newlog/
COPY cmd /newlog/cmd
COPY vendor /newlog/vendor

WORKDIR /newlog
ARG GOPKGVERSION

RUN GO111MODULE=on CGO_ENABLED=0 go build -ldflags "-s -w -X=main.Version=${GOPKGVERSION}" -mod=vendor -o /out/usr/bin/newlogd ./cmd

# required for pubsub
RUN rm -rf /out/var/run && mkdir -p /out/run /out/var && ln -s /run /out/var

FROM scratch
COPY --from=build /out/ /
COPY newlogd-init.sh /newlogd-init.sh

WORKDIR /newlog
ENTRYPOINT []
CMD ["/newlogd-init.sh"]
