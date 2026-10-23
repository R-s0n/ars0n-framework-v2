# Build stage: compiles the server and nothing from it ships except the binary.
# Pinned by multi-arch index digest (linux/amd64 + linux/arm64, go1.26.9, published 2026-10-08).
FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

# GOTOOLCHAIN=local: never download a different Go toolchain at build time (go.mod needs go 1.26.0,
# which this image already satisfies). No ",direct" in GOPROXY, so modules come only from the proxy
# and every one is checked against go.sum and sum.golang.org. CGO_ENABLED=0: the server has no cgo,
# and a static binary runs in the minimal runtime stage below.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0

WORKDIR /src

COPY go.mod go.sum ./
# go mod download over the module proxy, retried around transient proxy errors
RUN for i in 1 2 3 4 5; do go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go proxy error"; sleep $((i * 5)); done \
 && go mod verify

COPY . .

RUN go build -o /out/main .

# Runtime stage. This container mounts the host's /var/run/docker.sock, so it carries only what it
# runs: the server binary and the docker CLI (every scan is a `docker exec/run/cp` against the host
# daemon). No Go toolchain, compiler, git or docker engine.
# Pinned by multi-arch index digest (linux/amd64 + linux/arm64, published 2026-09-17).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk upgrade pulls the current signed Alpine security fixes (ca-certificates 20261020+ drops the
# compromised emSign roots, plus musl/openssl/zlib). docker-cli is the client only. The build fails
# if the bundle Go reads is missing or empty, or still contains emSign ECC Root CA - G3 (matched by
# that certificate's first base64 line; Alpine's bundle has no label comments to grep for, so
# grepping the CA name could never fail). Retried around mirror hiccups.
RUN for i in 1 2 3 4 5; do apk upgrade --no-cache && apk add --no-cache docker-cli && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
 && docker --version

WORKDIR /app

COPY --from=build /out/main /app/main

RUN mkdir -p /app/temp && chmod -R 777 /app/temp

EXPOSE 8443

CMD ["./main"]
