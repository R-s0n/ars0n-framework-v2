# pphack drives headless Chrome to find CLIENT-SIDE prototype pollution, so the browser is the heavy
# dependency rather than the tool. Chromium comes from the distribution rather than a download, so
# the image does not depend on a runtime fetch the way a puppeteer-based tool would.
#
# PINNED, not @latest. The output parser hardcodes pphack's Go struct field names (TargetURL,
# ScanURL, JSEvaluation) because the tool emits untagged JSON, so a field rename upstream would make
# the parser read nothing while the scan still exits 0. @latest already let the shipped binary drift
# to v0.1.5 while the parser's comment still said it was measured on v0.1.4; pinning to what is
# actually installed makes the next move deliberate.
# Verified: the built image's binary reports mod github.com/edoardottt/pphack v0.1.5.
# Do NOT roll back to v0.1.4 without re-checking those three field names.
# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# Built from the committed wrapper module in pin/, which requires pphack v0.1.5 plus
# golang.org/x/net v0.60.0; `go install pkg@version` would ignore that override.
COPY pin/ /build/
WORKDIR /build
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /out/pphack github.com/edoardottt/pphack/cmd/pphack

# Debian 13 (trixie) slim, pinned by multi-arch index digest. trixie, not bookworm: Chromium is only
# patched in trixie-security (DSA-6577-1). Take the signed security updates and fail the build if the
# trust store still holds a root of the 2026-10 eMudhra/emSign compromise.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
# Chromium does not use that system store: it verifies TLS against its own built-in Chrome Root Store,
# and Chromium 156 still trusts emSign ECC Root CA - G3 (upstream dropped it in a later root-store
# version). This managed policy distrusts that root's key, the same removal upstream made. pphack
# v0.1.5 launches Chromium with ignore-certificate-errors, so today the policy changes nothing for it;
# it is here so the browser stays safe if that flag goes. Keep it byte-identical to
# docker/session-keeper/chromium-policy.json.
COPY chromium-policy.json /etc/chromium/policies/managed/ars0n-distrust-emsign-g3.json
COPY --from=build /out/pphack /usr/local/bin/pphack
ENV CHROME_PATH=/usr/bin/chromium
WORKDIR /tmp
ENTRYPOINT ["pphack"]
