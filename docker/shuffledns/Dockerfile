# Build stage: compiles massdns and shuffledns; nothing from it ships except those two binaries.
# Go 1.26.9 on Alpine 3.24, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
# CGO_ENABLED=0 builds a static shuffledns binary that runs in the minimal runtime stage below.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0

# git clones massdns and build-base (gcc/make/musl-dev) compiles it; both are build-only and never
# reach the runtime image. massdns is linked against Alpine's musl libc, which the alpine runtime stage
# also provides.
RUN apk add --no-cache git build-base

# Build massdns, pinned to a commit on blechschmidt/massdns master (2026-04-15: the DNS-name bounds
# fix, which the v1.1.0 tag lacks). Fetched by SHA and checked, so a moved branch or a lookalike commit
# fails the build. `git describe` has no tags to read after a SHA fetch, so the revision string the
# Makefile would derive from it is passed in.
RUN git init /tmp/massdns && cd /tmp/massdns \
    && git remote add origin https://github.com/blechschmidt/massdns.git \
    && git fetch --depth 1 origin 6bfa47197d78e68b79041d494e280174cb2d6ae1 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 6bfa47197d78e68b79041d494e280174cb2d6ae1 \
    && make PROJECT_FLAGS='-DMASSDNS_REVISION=\"6bfa471\"' \
    && mv bin/massdns /usr/local/bin/ \
    && cd / \
    && rm -rf /tmp/massdns

# Build shuffledns v1.2.1 (the latest release) from the committed wrapper module in pin/, which raises
# the vulnerable dependencies it compiles in: golang.org/x/net v0.60.0, x/crypto v0.57.0,
# yuin/goldmark v1.7.17 and klauspost/compress v1.18.7. `go install pkg@version` would ignore them.
COPY pin/ /build/
WORKDIR /build
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /go/bin/shuffledns github.com/projectdiscovery/shuffledns/cmd/shuffledns

# Runtime stage. Ships only the two compiled binaries and a current CA bundle: no Go toolchain,
# compiler, module cache or git. Pinned by multi-arch index digest (linux/amd64 + linux/arm64,
# published 2026-09-17).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk upgrade pulls the current signed Alpine security fixes; ca-certificates gives shuffledns the
# trust bundle its HTTPS calls need (20261020+ drops the compromised emSign roots). The build fails if
# the bundle is missing or empty, or still contains emSign ECC Root CA - G3 (matched by that
# certificate's first base64 line; Alpine's bundle has no label comments to grep for). Retried around
# mirror hiccups.
RUN for i in 1 2 3 4 5; do apk upgrade --no-cache && apk add --no-cache ca-certificates && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# shuffledns resolves on PATH via `docker exec <container> shuffledns ...`; the API passes massdns to it
# by absolute path (-massdns /usr/local/bin/massdns), so that location is load-bearing.
COPY --from=build /usr/local/bin/massdns /usr/local/bin/massdns
COPY --from=build /go/bin/shuffledns /usr/local/bin/shuffledns

# Create directory for wordlists
RUN mkdir -p /app/wordlists

WORKDIR /app

# Copy wordlists if they exist in build context
COPY wordlists/* /app/wordlists/

# The container idles; the compose entrypoint override (sleep infinity) keeps it up for `docker exec`.
CMD ["sleep", "infinity"]
