# Build stage: compiles archivefetch (and installs waybackurls); nothing from it ships except the binaries.
# Go 1.26.9 on Alpine 3.24, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-alpine3.24@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
# CGO_ENABLED=0 builds static binaries that run in the minimal runtime stage below.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0

RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go install github.com/tomnomnom/waybackurls@v0.1.0 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

# archivefetch replaces waybackurls for the archive query, and waybackurls stays installed only so
# anything still calling it by name keeps resolving.
#
# waybackurls sends Go's default User-Agent, web.archive.org answers that with HTTP 429, and
# waybackurls discards the resulting parse error and exits 0 having printed nothing. Measured in this
# image on 2026-08-21 against ginandjuice.shop: both @v0.1.0 and @latest print zero bytes and exit 0,
# while wget against the identical CDX URL from the same container returns real data. See
# archivefetch/main.go for the full measurement table.
# archivefetch is standard library only and its go.mod is committed, so this build fetches nothing.
COPY archivefetch/ /src/archivefetch/
RUN cd /src/archivefetch && go build -trimpath -o /go/bin/archivefetch .

# Runtime stage. Ships only the compiled binaries and a current CA bundle: no Go toolchain, compiler,
# module cache or git. Pinned by multi-arch index digest (linux/amd64 + linux/arm64, published 2026-09-17).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# apk upgrade pulls the current signed Alpine security fixes; ca-certificates gives archivefetch the
# trust bundle its HTTPS calls to web.archive.org need (20261020+ drops the compromised emSign roots).
# The build fails if the bundle is missing or empty, or still contains emSign ECC Root CA - G3 (matched
# by that certificate's first base64 line; Alpine's bundle has no label comments to grep for). Retried
# around mirror hiccups.
RUN for i in 1 2 3 4 5; do apk upgrade --no-cache && apk add --no-cache ca-certificates && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# /usr/local/bin is on PATH, so the API's `docker exec <container> archivefetch ...` resolves the binary;
# waybackurls ships alongside it so anything still calling that name keeps resolving.
COPY --from=build /go/bin/archivefetch /usr/local/bin/archivefetch
COPY --from=build /go/bin/waybackurls /usr/local/bin/waybackurls

ENTRYPOINT ["archivefetch"]
