# http2smugl speaks HTTP/2 (and optionally HTTP/3) directly, so it needs no browser and no runtime
# beyond the static Go binary.
# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# Pinned to a commit rather than @latest: the repository has no tags, so @latest silently tracks master
# and two builds of this image can contain different scanners with no way to tell them apart. This is
# the commit the image always contained (pseudo-version v0.0.0-20250327224651-ccdf77278776), fetched by
# SHA and checked so a moved branch or a lookalike commit fails the build.
RUN git init /src && cd /src \
    && git remote add origin https://github.com/neex/http2smugl.git \
    && git fetch --depth 1 origin ccdf77278776327f58c74fdf9d41a36ad3deadfc \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = ccdf77278776327f58c74fdf9d41a36ad3deadfc
WORKDIR /src
# Built in the clone, not with `go install`, so the committed go.mod/go.sum in pin/ can replace the
# upstream ones: quic-go v0.50.1 -> v0.54.1 (GO-2025-4017, a DialEarly panic a hostile HTTP/3 target can
# trigger), golang.org/x/net v0.60.0 and x/crypto v0.57.0. quic-go v0.54 renamed quic.EarlyConnection to
# *quic.Conn; that one-line type rename in http3.go is the only source change, and the build fails if it
# did not apply.
COPY pin/go.mod pin/go.sum ./
RUN sed -i 's/session quic.EarlyConnection/session *quic.Conn/' http3.go \
    && grep -q 'session \*quic.Conn' http3.go \
    && ! grep -q 'EarlyConnection' http3.go
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /out/http2smugl .

# Debian 13 (trixie) slim, pinned by multi-arch index digest. Take the signed security updates and fail
# the build if the trust store still holds a root of the 2026-10 eMudhra/emSign compromise.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
COPY --from=build /out/http2smugl /usr/local/bin/http2smugl
ENTRYPOINT ["http2smugl"]
