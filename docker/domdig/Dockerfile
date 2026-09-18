# DOMDig runs a real Chromium: it is a DOM XSS scanner that finds bugs by watching a payload actually
# reach a sink in a live browser, not by matching a reflection in response text. That is the whole
# reason it is here alongside dalfox, which dropped its headless engine in v3 and now asserts
# exploitability by parsing the response instead of executing it.
FROM node:20-bookworm-slim

# PUPPETEER DOWNLOADS ITS OWN CHROME AND MUST BE ALLOWED TO.
#
# The obvious optimisation is to install the distro chromium and set PUPPETEER_SKIP_DOWNLOAD, which
# is what this file did first. It builds clean and then every scan dies at launch with "Could not
# find Chrome (ver. 141.0.7390.78)": htcrawl calls puppeteer.launch() with no executablePath, so
# puppeteer resolves the EXACT build it shipped with out of its own cache, and neither CHROME_PATH
# nor a distro chromium is ever consulted. domdig exposes no flag to override it.
#
# The failure is silent from the framework's point of view. The tool exits, the scan completes, and
# the results screen reads "0 findings" for a target that is vulnerable.
#
# So only the shared libraries are installed here, and puppeteer is left to fetch the matching
# browser during npm install.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
        libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
        libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
        libpango-1.0-0 libcairo2 libatspi2.0-0 libxext6 libxi6 libxtst6 \
        fonts-liberation xdg-utils \
    && rm -rf /var/lib/apt/lists/*

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
    && git checkout -q FETCH_HEAD

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

RUN npm install --omit=dev \
    && node -e "const p=require('puppeteer');console.log('chrome at',p.executablePath())"
# The last line fails the BUILD if puppeteer cannot resolve a browser, which is the only place that
# failure is cheap to notice. Without it the container ships and the defect surfaces as a scan that
# quietly finds nothing.

# htcrawl already passes --no-sandbox, so running as root inside the container is fine.
ENTRYPOINT ["node", "/app/domdig.js"]
