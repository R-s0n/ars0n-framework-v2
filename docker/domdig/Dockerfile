# DOMDig runs a real Chromium: it is a DOM XSS scanner that finds bugs by watching a payload actually
# reach a sink in a live browser, not by matching a reflection in response text. That is the whole
# reason it is here alongside dalfox, which dropped its headless engine in v3 and now asserts
# exploitability by parsing the response instead of executing it.
#
# Node 24 (Maintenance LTS) pinned by digest; Node 20 reached end of life on 2026-04-30. 24.22.1 is
# the release that fixes CVE-2026-111497 (Brotli out-of-bounds write) and three other HIGH issues,
# none of which has a fix on an older 24.x. Trixie because its security archive ships a current,
# signed chromium on both amd64 and arm64.
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea

# THE BROWSER IS DEBIAN'S, AND PUPPETEER IS TOLD SO EXPLICITLY.
#
# This file used to let puppeteer download its own Chrome for Testing during `npm install`, because
# htcrawl calls puppeteer.launch() with no executablePath: with only PUPPETEER_SKIP_DOWNLOAD and
# CHROME_PATH set, every scan died at launch with "Could not find Chrome (ver. 141.0.7390.78)" and
# the results screen read "0 findings" for a vulnerable target. That download was not checksum-
# verified and had no arm64 build. PUPPETEER_EXECUTABLE_PATH is the variable puppeteer.launch() itself
# falls back to when no executablePath is passed, so it reaches htcrawl's launch without patching
# htcrawl. The last RUN below fails the BUILD if puppeteer would not resolve to this browser.
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium PUPPETEER_SKIP_DOWNLOAD=true

# `apt-get upgrade` also pulls the ca-certificates release that drops the compromised emSign ECC
# Root CA - G3; the build fails if that root is still trusted or the bundle is missing (matched by the
# certificate's first base64 line; the bundle has no names, so grepping the CA name could never
# fail).
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends git ca-certificates chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && chromium --version
# Chromium does not use that system store: it verifies TLS against its own built-in Chrome Root
# Store, and Chromium 156 still trusts emSign ECC Root CA - G3 (the update that drops it arrives
# through the component updater, which puppeteer's --disable-background-networking turns off). This
# managed policy distrusts that root's key, the same removal upstream made. htcrawl launches the
# browser with --ignore-certificate-errors (and ignoreHTTPSErrors) so DOMDig reaches self-signed
# targets, so today the policy changes nothing for target traffic; it is here so the browser stays
# safe if that flag goes. Keep it byte-identical to docker/session-keeper/chromium-policy.json.
COPY chromium-policy.json /etc/chromium/policies/managed/ars0n-distrust-emsign-g3.json

WORKDIR /app

# PINNED TO A COMMIT, NOT A BRANCH.
#
# The patch below is a context diff against this exact tree. A floating `--depth 1` clone of master
# would silently drift out from under it, and the first sign would be a failed build on a day nobody
# touched this file. Pinning costs an occasional deliberate bump and buys a reproducible image.
ARG DOMDIG_COMMIT=8400a72c134e644fd74f632aa5c0dac526327163
RUN git init -q . \
    && git remote add origin https://github.com/fcavallarin/domdig.git \
    && git fetch -q --depth 1 origin "$DOMDIG_COMMIT" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$DOMDIG_COMMIT"

# THE PATCH IS APPLIED HERE, IN THE IMAGE, BECAUSE NOWHERE ELSE SURVIVES.
#
# An earlier fix was made with `docker exec` into the running container and was lost the next time
# this image was built, since the step above re-fetches upstream from scratch. Anything this
# framework needs changed in domdig has to live in this directory and be applied at build time.
#
# `git apply` exits non-zero when the context no longer matches, which FAILS THE BUILD. That is the
# wanted behaviour: a patch that silently stopped applying would ship an image that crashes on a
# quarter of its runs while claiming to be fixed.
COPY postmessage-crossorigin.patch /tmp/
RUN git apply --verbose /tmp/postmessage-crossorigin.patch && rm /tmp/postmessage-crossorigin.patch

# DEPENDENCIES COME FROM THE LOCK NEXT TO THIS FILE, INSTALLED WITH SCRIPTS OFF.
#
# package.json is upstream's plus one override (basic-ftp 6.2.2: get-uri's ^5 range only reaches
# versions with published advisories), and package-lock.json is upstream's lock with that and a few
# in-range advisory fixes applied (tar-fs, ws, js-yaml, ip-address), resolved with npm's --before so
# nothing younger than a week got in. `npm ci` installs exactly that lock and fails if it does not
# match package.json. --ignore-scripts (and .npmrc) means no dependency code runs at install: that
# skips puppeteer's browser download and better-sqlite3's unverified prebuilt-binary download.
# better-sqlite3 is only require()d by domdig's -d (SQLite output), which the framework never passes
# (it is framework-owned in xssOptions.go), so its missing native binding is never loaded.
COPY package.json package-lock.json .npmrc /app/
RUN npm ci --omit=dev --ignore-scripts \
    && node -e "const p=require('puppeteer').executablePath();console.log('chrome at',p);if(p!=='/usr/bin/chromium')process.exit(1)"
# The last line fails the BUILD if puppeteer does not resolve to the Debian browser, which is the
# only place that failure is cheap to notice. Without it the container ships and the defect surfaces
# as a scan that quietly finds nothing.

# htcrawl already passes --no-sandbox, so running as root inside the container is fine.
ENTRYPOINT ["node", "/app/domdig.js"]
