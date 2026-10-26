# Built from source at a pinned commit, not pulled as projectdiscovery/katana.
#
# The published images pair a binary with a frozen Alpine chromium (150 in v1.7.0) and a go.sum with
# published advisories (pgx/v5 among them). Building here lets the toolchain and those modules move,
# and pairs katana with a browser that gets Debian security updates.
#
# Pinned, not floating. companyOptionsKatana.go is written against measured behaviour of one version
# (its notes say v1.7.0); every flag the server passes was re-checked against v1.8.0, but the
# measured output line counts in that file should be re-measured before relying on them.
#
# go.mod and go.sum next to this file are upstream's at the pinned commit plus `go get` bumps
# (x/net v0.60.0, pgx/v5 v5.9.2, goldmark v1.7.17, klauspost/compress v1.18.7). -mod=readonly fails
# the build rather than re-resolving anything, and every module is checked against go.sum and the
# Go checksum DB.
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0
# v1.8.0. A tag can be moved upstream, a commit cannot, so the fetch is by SHA and asserted.
# The tag is then created LOCALLY on that commit only so `go build` stamps the real version into
# the build info; without it a dirty shallow checkout records a pseudo-version
# (v0.0.0-<date>-<sha>+dirty) that vulnerability scanners read as an ancient release.
ARG KATANA_VERSION=v1.8.0
ARG KATANA_COMMIT=35267ac5c8ff1db9694a319d0eb466ed97b0969f
RUN git init -q /src \
    && git -C /src remote add origin https://github.com/projectdiscovery/katana.git \
    && git -C /src fetch -q --depth 1 origin "$KATANA_COMMIT" \
    && git -C /src checkout -q --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "$KATANA_COMMIT" \
    && git -C /src tag "$KATANA_VERSION"
COPY go.mod go.sum /src/
WORKDIR /src
RUN go mod download && go mod verify \
    && go build -trimpath -o /out/katana ./cmd/katana

# Debian trixie because its security archive ships a current, signed chromium on both amd64 and
# arm64. `apt-get upgrade` also pulls the ca-certificates release that drops the compromised emSign
# ECC Root CA - G3; the build fails if that root is still trusted or the bundle is missing (matched by
# the certificate's first base64 line; the bundle has no names, so grepping the CA name could never
# fail).
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
ARG DEBIAN_FRONTEND=noninteractive
# HEADLESS MODE MUST NEVER DOWNLOAD A BROWSER AT SCAN TIME.
#
# Without -scp, `katana -hl` resolves its browser itself: on amd64 it fetches chrome-headless-shell
# from storage.googleapis.com into chromium-1520797742, elsewhere go-rod fetches chromium-1321438,
# and neither download is checksum-verified. Both look in /root/.cache/rod/browser first and use what
# they find there, so both cache paths are pre-seeded with links to the Debian browser. go-rod runs
# `chrome --headless --dump-dom about:blank` on its copy and deletes the directory and downloads
# anyway if that fails, so the link has to point at a browser that really starts headless.
# /usr/bin/google-chrome is what -sc (system-chrome) looks for. /usr/bin/chromium-browser is the
# second -scp choice the server offers (companyOptionsKatana.go systemChromePath): Alpine's package
# shipped it, Debian's does not, so it is linked here and both offered paths are checked.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends chromium fonts-liberation ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ln -s /usr/bin/chromium /usr/bin/google-chrome \
    && ln -s /usr/bin/chromium /usr/bin/chromium-browser \
    && chromium --version && chromium-browser --version && google-chrome --version \
    && mkdir -p /root/.cache/rod/browser/chromium-1321438 /root/.cache/rod/browser/chromium-1520797742 \
    && ln -s /usr/bin/chromium /root/.cache/rod/browser/chromium-1321438/chrome \
    && ln -s /usr/bin/chromium /root/.cache/rod/browser/chromium-1520797742/chrome-headless-shell
# Chromium does not use that system store: it verifies TLS against its own built-in Chrome Root
# Store, and Chromium 156 still trusts emSign ECC Root CA - G3 (the update that drops it arrives
# through the component updater, which katana's --disable-component-update and go-rod's
# --disable-background-networking turn off). This managed policy distrusts that root's key, the same
# removal upstream made. katana launches the browser with --ignore-certificate-errors so it can crawl
# self-signed targets, so today the policy changes nothing for target traffic; it is here so the
# browser stays safe if that flag goes. Keep it byte-identical to
# docker/session-keeper/chromium-policy.json.
COPY chromium-policy.json /etc/chromium/policies/managed/ars0n-distrust-emsign-g3.json
COPY --from=build /out/katana /usr/local/bin/katana
RUN katana -version

WORKDIR /app

ENTRYPOINT ["katana"]
