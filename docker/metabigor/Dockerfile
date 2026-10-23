# Build stage: compiles metabigor and nothing from it ships except the binary.
# Go 1.26.9 on Alpine 3.24, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
# CGO_ENABLED=0 builds a static binary that runs in the minimal runtime stage below.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0

# metabigor stays on v1.2.8: v2 rewrites the output that metabigorCompanyUtils.go parses. It is built
# from the committed wrapper module in pin/, which raises the vulnerable dependencies it compiles in
# (golang.org/x/net v0.60.0, x/crypto v0.57.0, refraction-networking/utls v1.8.2, ulikunitz/xz v0.5.15,
# yuin/goldmark v1.7.17, x/oauth2 v0.27.0, klauspost/compress v1.18.7, and bluemonday v1.0.27 in place
# of the retracted v1.0.25). `go install pkg@version` would ignore those overrides.
COPY pin/ /build/
WORKDIR /build
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /go/bin/metabigor github.com/j3ssie/metabigor

# Runtime stage. Ships only the compiled binary and a current CA bundle: no Go toolchain, compiler,
# module cache or git. Pinned by multi-arch index digest (linux/amd64 + linux/arm64, published 2026-09-17).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk upgrade pulls the current signed Alpine security fixes; ca-certificates gives metabigor the trust
# bundle its HTTPS lookups need (20261020+ drops the compromised emSign roots). The build fails if the
# bundle is missing or empty, or still contains emSign ECC Root CA - G3 (matched by that certificate's
# first base64 line; Alpine's bundle has no label comments to grep for). Retried around mirror hiccups.
RUN for i in 1 2 3 4 5; do apk upgrade --no-cache && apk add --no-cache ca-certificates && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# /usr/local/bin is on PATH, so the API's `docker exec -i <container> metabigor ...` resolves the binary.
COPY --from=build /go/bin/metabigor /usr/local/bin/metabigor
WORKDIR /go

ENTRYPOINT ["/usr/local/bin/metabigor"]
