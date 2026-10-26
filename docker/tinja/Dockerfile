# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# Pinned to a commit on Hackmanit/TInjA main (repository id 691006749), fetched by SHA and checked so a
# moved branch, a re-registered repository or a lookalike commit fails the build.
RUN git init /src && cd /src \
    && git remote add origin https://github.com/Hackmanit/TInjA.git \
    && git fetch --depth 1 origin 507d903e1bb27073418daea4b1aec146b8775f48 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 507d903e1bb27073418daea4b1aec146b8775f48
WORKDIR /src
# The committed go.mod/go.sum in pin/ replace the upstream ones (go-viper/mapstructure/v2 v2.4.0,
# golang.org/x/net v0.60.0, x/sys v0.48.0, x/text v0.42.0; "go 1.26.0" with no toolchain line, so no
# toolchain download). rodbin.go points rod at the distro chromium; see the comment in that file.
COPY pin/go.mod pin/go.sum rodbin.go ./
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /out/tinja .

# Debian 13 (trixie) slim, pinned by multi-arch index digest. trixie, not bookworm: Chromium is only
# patched in trixie-security (DSA-6577-1). Take the signed security updates and fail the build if the
# trust store still holds a root of the 2026-10 eMudhra/emSign compromise.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
# TInjA's --csti mode drives a headless Chromium through rod, so the browser has to be present even
# though the default scan does not start one. Without it --csti fails at launch rather than at build,
# and client-side template injection is the one thing TInjA uniquely finds. The chromium package pulls
# in every shared library the browser needs. rodbin.go hardcodes /usr/bin/chromium, so check it exists.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates chromium \
    && rm -rf /var/lib/apt/lists/* \
    && test -x /usr/bin/chromium \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
# Chromium does not use that system store: it verifies TLS against its own built-in Chrome Root Store,
# and Chromium 156 still trusts emSign ECC Root CA - G3 (upstream dropped it in a later root-store
# version). This managed policy distrusts that root's key, the same removal upstream made, so the
# --csti browser rejects an emSign-chained certificate. Keep it byte-identical to
# docker/session-keeper/chromium-policy.json.
COPY chromium-policy.json /etc/chromium/policies/managed/ars0n-distrust-emsign-g3.json
COPY --from=build /out/tinja /usr/local/bin/tinja
RUN tinja --help > /dev/null
ENTRYPOINT ["tinja"]
