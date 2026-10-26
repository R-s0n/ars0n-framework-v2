# TruffleHog finds and LIVE-VERIFIES leaked credentials. The verification step is the reason it is
# here: it separates a string that looks like a key from one that still works.
#
# It has no URL source of its own, so the framework fetches what it wants scanned into a directory
# and points the filesystem source at it. curl is therefore a runtime dependency, not a convenience.
#
# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64). The image
# ships git, so nothing is installed in this stage.
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# Pinned to the v3.99.2 release (2026-10-08). The tag is fetched so Go stamps the binary as v3.99.2 (a
# bare SHA fetch stamps v3.0.0-<date>-<sha>, which version-based scanners read as a years-old release),
# and the build fails unless the tag resolves to the pinned commit, so a moved tag or a lookalike commit
# cannot slip in. Cloned and built rather than `go install`: trufflehog's go.mod contains replace
# directives, and go install refuses those outright ("It must not contain directives that would cause
# it to be interpreted differently than if it were the main module").
RUN git init /src && cd /src \
    && git remote add origin https://github.com/trufflesecurity/trufflehog.git \
    && git fetch --depth 1 origin refs/tags/v3.99.2:refs/tags/v3.99.2 \
    && git checkout --detach v3.99.2 \
    && test "$(git rev-parse HEAD)" = e76dff8a7e57d6df0c60ad8cbf5d5cba505a8fc9
WORKDIR /src
# The committed go.mod/go.sum in pin/ replace the upstream ones and raise the vulnerable dependencies
# v3.99.2 compiles in (golang.org/x/net v0.60.0, x/crypto v0.57.0, grpc v1.83.2, amqp091-go v1.14.0,
# otel v1.45.0, edwards25519 v1.1.1, goldmark v1.7.17, klauspost/compress v1.20.2); upstream's replace
# directives are kept unchanged. moby/go-archive v0.3.0, moby/sys/user v0.4.1 and otlptrace v1.45.0 are
# raised too although only test packages import them (none is compiled in), so the advisories against
# the old versions stay closed.
COPY pin/go.mod pin/go.sum ./
# Built WITHOUT -ldflags on purpose: the version then stays "dev", and trufflehog never starts its
# self-updater (it downloads unsigned replacement binaries) for a dev build. The check fails the build
# if that ever stops being true; the api also passes --no-update.
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /out/trufflehog . \
    && /out/trufflehog --version 2>&1 | grep -qx 'trufflehog dev'

# Debian 13 (trixie) slim, pinned by multi-arch index digest. Take the signed security updates and fail
# the build if the trust store still holds a root of the 2026-10 eMudhra/emSign compromise. No git: the
# filesystem source the api uses does not need it.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
COPY --from=build /out/trufflehog /usr/local/bin/trufflehog
WORKDIR /tmp
ENTRYPOINT ["trufflehog"]
