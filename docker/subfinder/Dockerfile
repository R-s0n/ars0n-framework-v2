# Built from source at a pinned commit, not pulled as projectdiscovery/subfinder.
#
# The published v2.17.0 image carries a go1.26.0 binary (46 standard-library advisories) and its
# go.sum still resolves golang.org/x/net, goldmark and klauspost/compress versions with published
# advisories. Building here lets the toolchain and those three modules move without waiting for
# upstream. The framework parses subfinder's output and describes its flags from measured behaviour,
# so the version stays pinned: every flag the server passes was checked against v2.17.0.
#
# go.mod and go.sum next to this file are upstream's at the pinned commit plus three `go get` bumps
# (x/net v0.60.0, goldmark v1.7.17, klauspost/compress v1.18.7). -mod=readonly fails the build rather
# than re-resolving anything, and every module is checked against go.sum and the Go checksum DB.
FROM golang:1.26.9-trixie@sha256:f89535b7caea67fa9ff0ba009894bff8f3be915e49cb635477c8ce04e045db5d AS build
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0
# v2.17.0. A tag can be moved upstream, a commit cannot, so the fetch is by SHA and asserted.
# The tag is then created LOCALLY on that commit only so `go build` stamps the real version into
# the build info; without it a dirty shallow checkout records a pseudo-version
# (v0.0.0-<date>-<sha>+dirty) that vulnerability scanners read as an ancient release.
ARG SUBFINDER_VERSION=v2.17.0
ARG SUBFINDER_COMMIT=c97f25802892093060f0fc424bfc3f39e273693a
RUN git init -q /src \
    && git -C /src remote add origin https://github.com/projectdiscovery/subfinder.git \
    && git -C /src fetch -q --depth 1 origin "$SUBFINDER_COMMIT" \
    && git -C /src checkout -q --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "$SUBFINDER_COMMIT" \
    && git -C /src tag "$SUBFINDER_VERSION"
COPY go.mod go.sum /src/
WORKDIR /src
RUN go mod download && go mod verify \
    && go build -trimpath -o /out/subfinder ./cmd/subfinder

# Alpine, as upstream ships it; the binary is static. `apk upgrade` pulls current signed fixes,
# including the ca-certificates release that drops the compromised emSign ECC Root CA - G3, which
# matters here because subfinder sends passive-source API keys over TLS. The build fails if that root
# is still trusted or the bundle is missing (matched by the certificate's first base64 line; the
# bundle has no names, so grepping the CA name could never fail).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk upgrade --no-cache \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/subfinder /usr/local/bin/subfinder
RUN subfinder -version

ENTRYPOINT ["subfinder"]
