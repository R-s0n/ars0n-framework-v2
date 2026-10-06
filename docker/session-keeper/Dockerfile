# The durable session keeper runs a real (headless) Chromium: it holds an IdP session, reloads the
# unmodified SPA so the app re-mints its own short-lived bearer, and harvests that bearer from the
# browser's own network. It follows docker/domdig/Dockerfile exactly on the one thing that is easy to
# get wrong - letting puppeteer download and resolve its OWN matching Chrome.
FROM node:20-bookworm-slim

# PUPPETEER DOWNLOADS ITS OWN CHROME AND MUST BE ALLOWED TO. The distro chromium + PUPPETEER_SKIP_DOWNLOAD
# path fails at launch with "Could not find Chrome (ver ...)" because puppeteer.launch() with no
# executablePath resolves the exact build it shipped with out of its own cache. So only the shared
# libraries go in here and puppeteer fetches the matching browser during npm install. (Same rationale
# as domdig; see that Dockerfile.)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 libxkbcommon0 \
        libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libgbm1 libasound2 \
        libpango-1.0-0 libcairo2 libatspi2.0-0 libxext6 libxi6 libxtst6 \
        fonts-liberation xdg-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev \
    && node -e "import('puppeteer').then(m=>console.log('chrome at',m.default.executablePath()))"
# The last line FAILS THE BUILD if puppeteer cannot resolve a browser, which is the only place that
# failure is cheap to notice. Without it the container ships and the keeper quietly harvests nothing.

COPY keeper.mjs keeperLib.mjs ./

# Resolve the entry module's full import graph at build time (puppeteer + ./keeperLib.mjs) WITHOUT
# running the loop (the argv guard in keeper.mjs keeps main() from firing under a bare import). This
# fails the build the same cheap way the puppeteer check above does if a sibling module is ever
# forgotten in the COPY line - the exact regression that would otherwise ship a crash-looping image.
RUN node -e "import('/app/keeper.mjs').then(()=>console.log('keeper import graph resolves')).catch(e=>{console.error(e);process.exit(1)})"

# The keeper launches Chromium with --no-sandbox, so running as root in the container is fine.
ENTRYPOINT ["node", "/app/keeper.mjs"]
