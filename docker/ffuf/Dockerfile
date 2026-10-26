# Build stage: compiles ffuf and nothing from it ships except the binary.
# Go 1.26.9 on Alpine 3.24, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.2-alpine3.24@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
# CGO_ENABLED=0 builds a static binary that runs in the minimal runtime stage below.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0

# ffuf v2.3.0 (fixes GHSA-wc5c-g52x-g44x, the -od/-audit-log OOM) is built from the committed wrapper
# module in pin/, which requires the tool plus golang.org/x/net v0.60.0. `go install pkg@version` would
# ignore that override and compile ffuf's own x/net v0.7.0.
COPY pin/ /build/
WORKDIR /build
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /go/bin/ffuf github.com/ffuf/ffuf/v2

# Runtime stage. Ships only the compiled binary and a current CA bundle: no Go toolchain, compiler,
# module cache or git. Pinned by multi-arch index digest (linux/amd64 + linux/arm64, published 2026-09-17).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk upgrade pulls the current signed Alpine security fixes; ca-certificates gives ffuf the trust
# bundle its HTTPS requests need (20261020+ drops the compromised emSign roots). The build fails if the
# bundle is missing or empty, or still contains emSign ECC Root CA - G3 (matched by that certificate's
# first base64 line; Alpine's bundle has no label comments to grep for). Retried around mirror hiccups.
RUN for i in 1 2 3 4 5; do apk upgrade --no-cache && apk add --no-cache ca-certificates && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# /usr/local/bin is on PATH, so the API's `docker exec <container> ffuf ...` resolves the binary.
COPY --from=build /go/bin/ffuf /usr/local/bin/ffuf
WORKDIR /app
RUN mkdir -p /wordlists
# The container idles; the compose entrypoint override (sleep infinity) keeps it up for `docker exec`.
ENTRYPOINT ["sleep", "infinity"]
