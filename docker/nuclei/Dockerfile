# nuclei is built from source at a pinned commit.
#
# This used to download the v3.3.8 release zip with no checksum. 3.3.8 is inside seven nuclei
# advisories, including a Goja JavaScript RCE through custom templates (GHSA-vxg7-f2jj-jmqm), and its
# go1.21 binary carries many standard-library and dependency advisories. v3.11.1 is outside every
# advisory range. Building here also lets the toolchain and a few modules move: go.mod and go.sum next
# to this file are upstream's at the pinned commit plus `go get` bumps (x/net v0.60.0, grpc v1.83.2,
# go-git v5.19.2, kin-openapi v0.149.0, and moby/sys/user v0.4.1 for GO-2026-6686, which is listed in
# go.mod but not compiled into nuclei). -mod=readonly fails the build rather than re-resolving
# anything, and every module is checked against go.sum and the Go checksum DB.
#
# BEHAVIOUR CHANGES FROM 3.3.8 THAT REACH THE FRAMEWORK: since v3.11 nuclei skips UNSIGNED
# javascript: templates (that is the RCE fix), so unsigned custom JS templates under /custom_templates
# no longer run; sign them with `nuclei -sign`. Since v3.10, MySQL allowAllFiles needs -lfa.
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org CGO_ENABLED=0
# v3.11.1. A tag can be moved upstream, a commit cannot, so the fetch is by SHA and asserted.
# The tag is then created LOCALLY on that commit only so `go build` stamps the real version into
# the build info; without it a dirty shallow checkout records a pseudo-version
# (v0.0.0-<date>-<sha>+dirty) that vulnerability scanners read as an ancient release.
ARG NUCLEI_VERSION=v3.11.1
ARG NUCLEI_COMMIT=a8c88feb4a1c8e961b7902534ce3af97e9d524a4
RUN git init -q /src \
    && git -C /src remote add origin https://github.com/projectdiscovery/nuclei.git \
    && git -C /src fetch -q --depth 1 origin "$NUCLEI_COMMIT" \
    && git -C /src checkout -q --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "$NUCLEI_COMMIT" \
    && git -C /src tag "$NUCLEI_VERSION"
COPY go.mod go.sum /src/
WORKDIR /src
RUN go mod download && go mod verify \
    && go build -trimpath -o /out/nuclei ./cmd/nuclei

# Install Nuclei templates at a pinned version.
#
# For nuclei the templates ARE the detection logic, so pinning the binary above while leaving the
# corpus floating pinned the half that matters least. "nuclei -update-templates" baked whichever
# corpus happened to be current on build day and recorded nothing about it, so no two rebuilds of
# this image scanned for quite the same things.
#
# v10.4.7 is the version this image already shipped (confirmed with "nuclei -templates-version"
# against the built image), so this pin reproduces the coverage in use today rather than jumping
# it. The commit is fetched directly and asserted, because a tag can be repointed upstream and a
# commit SHA cannot. The clone happens in this stage so the runtime image needs no git.
#
# The path stays /root/nuclei-templates. server/utils/redirectCompose.go and several other Go
# files address individual directories under it by absolute path, so moving it would break them.
ARG NUCLEI_TEMPLATES_COMMIT=83234ce456da3e90dda86dfbc5e605e64a846df3
RUN git init -q /root/nuclei-templates \
    && git -C /root/nuclei-templates remote add origin https://github.com/projectdiscovery/nuclei-templates.git \
    && git -C /root/nuclei-templates fetch -q --depth 1 origin "$NUCLEI_TEMPLATES_COMMIT" \
    && git -C /root/nuclei-templates checkout -q --detach FETCH_HEAD \
    && test "$(git -C /root/nuclei-templates rev-parse HEAD)" = "$NUCLEI_TEMPLATES_COMMIT" \
    && rm -rf /root/nuclei-templates/.git /root/nuclei-templates/.github

# Debian trixie because its security archive ships a current, signed chromium on both amd64 and
# arm64. This replaces Google's apt repository (plain HTTP, with its key fetched unverified into the
# global apt-key trust store) on amd64 and Ubuntu's snap-only chromium-browser on arm64. `apt-get
# upgrade` also pulls the ca-certificates release that drops the compromised emSign ECC Root CA - G3;
# the build fails if that root is still trusted or the bundle is missing (matched by the
# certificate's first base64 line; the bundle has no names, so grepping the CA name could never
# fail). bash is part of the base image and is needed: the server runs `bash -c` here and
# entrypoint.sh is a bash script.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

ENV DEBIAN_FRONTEND=noninteractive

# HEADLESS MODE MUST NEVER DOWNLOAD A BROWSER AT SCAN TIME.
#
# Without -sc, `nuclei -headless` asks go-rod for its own browser, and go-rod downloads chromium
# (about 150MB, not checksum-verified) into /root/.cache/rod/browser/chromium-1321438 unless a working
# one is already there. That directory is pre-seeded with a link to the Debian browser. go-rod runs
# `chrome --headless --dump-dom about:blank` on it first and deletes the directory and downloads
# anyway if that fails, so the link has to point at a browser that really starts headless.
# /usr/bin/google-chrome is what -sc (system-chrome) and entrypoint.sh look for.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends chromium fonts-liberation ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && chromium --version \
    && ln -s /usr/bin/chromium /usr/bin/google-chrome \
    && mkdir -p /root/.cache/rod/browser/chromium-1321438 \
    && ln -s /usr/bin/chromium /root/.cache/rod/browser/chromium-1321438/chrome
# Chromium does not use that system store: it verifies TLS against its own built-in Chrome Root
# Store, and Chromium 156 still trusts emSign ECC Root CA - G3 (the update that drops it arrives
# through the component updater, which go-rod's --disable-background-networking turns off). This
# managed policy distrusts that root's key, the same removal upstream made. nuclei launches the
# browser with --ignore-certificate-errors so headless templates reach self-signed targets, so today
# the policy changes nothing for target traffic; it is here so the browser stays safe if that flag
# goes. Keep it byte-identical to docker/session-keeper/chromium-policy.json.
COPY chromium-policy.json /etc/chromium/policies/managed/ars0n-distrust-emsign-g3.json

COPY --from=build /out/nuclei /usr/local/bin/nuclei
COPY --from=build /root/nuclei-templates /root/nuclei-templates

# Seed the two config-directory files that -update-templates used to leave behind. A clone alone
# does not produce them, and each one changes what a scan does:
#
# .nuclei-ignore is what holds the ~200 known-weak-matcher templates out of a default run. With it
# absent, a default scan loads those 200 and reports their known-noisy matches as findings. Copying
# it from the pinned corpus reproduced the exact "Excluded 200 template[s]" line the old image logs.
#
# .templates-config.json is where nuclei reads the installed version from - not from the template
# tree - so without it the corpus version is blank in the scan log and in -templates-version, which
# is the thing this whole change exists to make legible.
ARG NUCLEI_TEMPLATES_VERSION=v10.4.7
RUN mkdir -p /root/.config/nuclei && \
    cp /root/nuclei-templates/.nuclei-ignore /root/.config/nuclei/.nuclei-ignore && \
    printf '{"nuclei-templates-directory":"/root/nuclei-templates","nuclei-templates-version":"%s"}\n' \
        "${NUCLEI_TEMPLATES_VERSION}" > /root/.config/nuclei/.templates-config.json

# Stop nuclei re-fetching the corpus at run time, which is the half of this problem that a pin
# alone does not fix. Verified against this image on 2026-09-08: nuclei v3.3.8 checks for a newer
# corpus on every start and installs it in place, and a scan run logged
#   "Your current nuclei-templates v10.4.7 are outdated. Latest is v10.4.8"
#   "Successfully updated nuclei-templates (v10.4.8) to /root/nuclei-templates"
# before the scan began. The corpus the build produced was therefore never the corpus that scanned,
# and it changed again every time the container was recreated - mid-engagement, with nothing
# recording it.
#
# These are the config-file forms of the -duc and -ud flags. They are set here rather than passed
# as flags because every nuclei invocation lives in server/utils Go code that would each have to
# remember them. nuclei only writes this file on its first real scan, so writing it at build time
# is also what stops the first scan of an engagement running against a corpus nobody chose. Both
# keys were confirmed honoured by v3.3.8, using the update itself as the control: one scan run,
# internet reachable, downloaded v10.4.8 without this file and stayed on v10.4.7 with it. nuclei
# left the file as written rather than replacing it with its own generated defaults. Both keys still
# exist in v3.11.1.
RUN printf 'disable-update-check: true\nupdate-template-dir: /root/nuclei-templates\n' \
        > /root/.config/nuclei/config.yaml

# Create necessary directories
RUN mkdir -p /tmp/nuclei-mounts && \
    chmod 777 /tmp/nuclei-mounts

# Set Chrome path for nuclei
ENV CHROME_PATH=/usr/bin/google-chrome

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"]
