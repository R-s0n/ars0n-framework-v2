# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.26.9-trixie@sha256:f89535b7caea67fa9ff0ba009894bff8f3be915e49cb635477c8ce04e045db5d AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# Pinned to a commit on Hackmanit/Web-Cache-Vulnerability-Scanner master (repository id 348742617),
# fetched by SHA and checked so a moved branch, a re-registered repository or a lookalike commit fails
# the build.
RUN git init /src && cd /src \
    && git remote add origin https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git \
    && git fetch --depth 1 origin 75159ea557772447a7760184e1f08e3cc3395090 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 75159ea557772447a7760184e1f08e3cc3395090
WORKDIR /src
# The committed go.mod/go.sum in pin/ replace the upstream ones (golang.org/x/net v0.60.0,
# valyala/fasthttp v1.70.0, klauspost/compress v1.18.7; "go 1.26.0" with no toolchain line).
COPY pin/go.mod pin/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /out/wcvs .

# Debian 13 (trixie) slim, pinned by multi-arch index digest. Take the signed security updates and fail
# the build if the trust store still holds a root of the 2026-10 eMudhra/emSign compromise.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
COPY --from=build /out/wcvs /usr/local/bin/wcvs
# The wordlists are NOT embedded in the binary. WCVS ships 2917 header names and 6452 parameter
# names as plain files, and the framework concatenates its own discovered names onto them at scan
# time, so both have to exist at a known path inside this container.
COPY --from=build /src/wordlists /opt/wcvs/wordlists
COPY --from=build /src/templates /opt/wcvs/templates
RUN wcvs --help > /dev/null && test -s /opt/wcvs/wordlists/headers && test -s /opt/wcvs/wordlists/parameters
ENTRYPOINT ["wcvs"]
