# Mantra hunts hardcoded API keys and credentials inside the JavaScript and HTML a target serves.
# Go, and it reads its targets from stdin rather than from a flag.
# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.26.9-trixie@sha256:f89535b7caea67fa9ff0ba009894bff8f3be915e49cb635477c8ce04e045db5d AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# brosck/mantra, not MrEmpy/mantra: the project moved, and the old path now fails the build outright
# with "module declares its path as: github.com/brosck/mantra".
#
# PINNED, not @latest. Mantra has no positive control in vectorCanary.go, so if a future release
# changed its output format the framework would report clean secret sweeps rather than an error.
# The pin is a PSEUDO-VERSION because the module has no usable release tag on the current path -
# this is the exact commit the built image already contains, verified from the binary's own build
# info (mod github.com/brosck/mantra v0.0.0-20260312130105-6026816210df). Do not "tidy" this into
# a tag such as v3.1: Go declines to select it, most likely because it predates the module path move.
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 GOBIN=/out go install github.com/brosck/mantra@v0.0.0-20260312130105-6026816210df && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

# Debian 13 (trixie) slim, pinned by multi-arch index digest. Take the signed security updates and fail
# the build if the trust store still holds a root of the 2026-10 eMudhra/emSign compromise.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
COPY --from=build /out/mantra /usr/local/bin/mantra
WORKDIR /tmp
ENTRYPOINT ["mantra"]
