# Built from source at a pinned commit, not pulled as projectdiscovery/dnsx.
#
# The newest published image is still v1.2.2: Alpine 3.18 (end of life), a go1.21.4 binary and dozens
# of dependency advisories. v1.3.1 has no image, so it is built here. A tag can be moved upstream and
# a commit cannot, so the fetch is by SHA and asserted.
#
# NOTE FOR companyRegistry.go: it states "dnsx v1.2.2 HAS NO TIMEOUT FLAG OF ANY KIND". v1.3.1 adds
# -timeout, filters JSON output to the requested record types and parses only the ANSWER section.
# The JSON keys the parser reads (host, a, aaaa, cname, mx, ns, txt, ptr, srv) are unchanged.
#
# go.mod and go.sum next to this file are upstream's at the pinned commit plus three `go get` bumps
# (x/net v0.60.0, goldmark v1.7.17, klauspost/compress v1.18.7). -mod=readonly fails the build rather
# than re-resolving anything, and every module is checked against go.sum and the Go checksum DB.
FROM golang:1.26.9-trixie@sha256:f89535b7caea67fa9ff0ba009894bff8f3be915e49cb635477c8ce04e045db5d AS build
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0
# v1.3.1. The tag is created LOCALLY on the asserted commit only so `go build` stamps the real
# version into the build info instead of a v0.0.0-<date>-<sha>+dirty pseudo-version.
ARG DNSX_VERSION=v1.3.1
ARG DNSX_COMMIT=01e315f216db7d36198ec326fac13dd7846b1bec
RUN git init -q /src \
    && git -C /src remote add origin https://github.com/projectdiscovery/dnsx.git \
    && git -C /src fetch -q --depth 1 origin "$DNSX_COMMIT" \
    && git -C /src checkout -q --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "$DNSX_COMMIT" \
    && git -C /src tag "$DNSX_VERSION"
COPY go.mod go.sum /src/
WORKDIR /src
RUN go mod download && go mod verify \
    && go build -trimpath -o /out/dnsx ./cmd/dnsx

# Alpine, as upstream ships it; the binary is static. `apk upgrade` pulls current signed fixes,
# including the ca-certificates release that drops the compromised emSign ECC Root CA - G3. The build
# fails if that root is still trusted or the bundle is missing (matched by the certificate's first
# base64 line; the bundle has no names, so grepping the CA name could never fail).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk upgrade --no-cache \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dnsx /usr/local/bin/dnsx
RUN dnsx -version

ENTRYPOINT ["dnsx"]
