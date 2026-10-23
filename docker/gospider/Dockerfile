# Build stage: compiles gospider and nothing from it ships except the binary.
# Go 1.26.9 on Alpine 3.24, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.26.9-alpine3.24@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS build

# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
# CGO_ENABLED=0 builds a static binary that runs in the minimal runtime stage below.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0

# gospider v1.1.6 (the last release; tag v1.1.6 -> eea4cb58ab70938826cf6eafc8dfebedc192ee52), fetched by
# SHA and checked so a moved tag or a lookalike commit fails the build. git is only needed to clone in
# this build stage and never reaches the runtime image.
RUN apk add --no-cache git \
    && git init /src && cd /src \
    && git remote add origin https://github.com/jaeles-project/gospider.git \
    && git fetch --depth 1 origin eea4cb58ab70938826cf6eafc8dfebedc192ee52 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = eea4cb58ab70938826cf6eafc8dfebedc192ee52
WORKDIR /src
# Built in the clone, not with `go install`, so the committed go.mod/go.sum in pin/ can replace the
# upstream ones and raise the vulnerable dependencies it compiles in: golang.org/x/net v0.60.0,
# antchfx/xpath v1.3.9, antchfx/xmlquery v1.3.1, sirupsen/logrus v1.9.3, google.golang.org/protobuf v1.33.0.
# docker-compose.yml builds this image with the REPOSITORY ROOT as its context, hence the full path.
COPY docker/gospider/pin/go.mod docker/gospider/pin/go.sum ./
# The one source change. Current golang.org/x/net/publicsuffix (deliberately) refuses an eTLD+1 for an
# IP address, and gospider v1.1.6 treats that as "Failed to parse domain" and exits 1, so every crawl of
# an IP host would fail. An IP host is now its own scope domain. The build fails if the patch did not apply.
RUN sed -i 's#^\t"net/http"$#\t"net"\n\t"net/http"#' core/utils.go \
    && sed -i 's#^\tdomain, err := publicsuffix.EffectiveTLDPlusOne(site.Hostname())$#&\n\tif err != nil \&\& net.ParseIP(site.Hostname()) != nil {\n\t\treturn site.Hostname()\n\t}#' core/utils.go \
    && grep -q '^	"net"$' core/utils.go \
    && grep -q 'net.ParseIP(site.Hostname()) != nil' core/utils.go
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /go/bin/gospider .

# Runtime stage. Ships only the compiled binary and a current CA bundle: no Go toolchain, compiler,
# module cache or git. Pinned by multi-arch index digest (linux/amd64 + linux/arm64, published 2026-09-17).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk upgrade pulls the current signed Alpine security fixes; ca-certificates gives gospider the trust
# bundle its HTTPS crawls need (20261020+ drops the compromised emSign roots). The build fails if the
# bundle is missing or empty, or still contains emSign ECC Root CA - G3 (matched by that certificate's
# first base64 line; Alpine's bundle has no label comments to grep for). Retried around mirror hiccups.
RUN for i in 1 2 3 4 5; do apk upgrade --no-cache && apk add --no-cache ca-certificates && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# /usr/local/bin is on PATH, so the API's `docker exec <container> gospider ...` resolves the binary.
COPY --from=build /go/bin/gospider /usr/local/bin/gospider

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/gospider"]
