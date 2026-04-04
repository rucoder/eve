# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:b5349070465e68c65cc1628a0941180fc8706a07 AS build

# build the tpm-recovery tool
WORKDIR /
COPY src/ recover-tpm/

WORKDIR /recover-tpm
SHELL ["/bin/ash", "-eo", "pipefail", "-c"]
# hadolint ignore=SC2046
RUN echo "Running go vet" && go vet ./... && echo "Running go fmt" && \
    ERR=$(gofmt -e -l -s $(find . -name \*.go | grep -v /vendor/)) && \
    if [ -n "$ERR" ] ; then echo "go fmt Failed - ERR: $ERR"; exit 1 ; fi
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o recovertpm .

FROM scratch
WORKDIR /

COPY --from=build /recover-tpm/recovertpm /usr/bin/recovertpm
