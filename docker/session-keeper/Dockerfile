# The durable session keeper runs a real (headless) Chromium: it holds an IdP session, reloads the
# unmodified SPA so the app re-mints its own short-lived bearer, and harvests that bearer from the
# browser's own network. Everything this build fetches is pinned or signed: the base image by its
# multi-arch index digest (linux/amd64 + linux/arm64), the npm tree by the committed lockfile, and
# Chromium by Debian's apt signatures.
FROM node:24.22.1-trixie-slim@sha256:43b9ba1142b8dcf33fa8f922ca1be85714adc444e0586c7cf7726daaeabc1bea

# THE BROWSER IS DEBIAN'S CHROMIUM, NOT PUPPETEER'S DOWNLOAD. puppeteer's postinstall would fetch Chrome
# for Testing from Google's CDN with no checksum, and only an x86-64 build (wrong for arm64 hosts).
# Debian's trixie-security chromium is apt-signature-verified, current stable on both arches, and picks
# up Debian's security updates on every rebuild; the smoke test below refuses anything older than 156.
# Distro chromium used to fail with "Could not find Chrome (ver ...)" only because no executable path
# was set: PUPPETEER_EXECUTABLE_PATH makes every puppeteer.launch() use it (puppeteer checks the file
# exists), and PUPPETEER_SKIP_DOWNLOAD keeps any install path from fetching a browser. chromium's own
# Depends pull in every shared library under the right trixie (t64) names; fonts-liberation is only a
# Recommends, so it is named. The ca-certificates assertions fail the build unless the store has the
# DSA-6572-1 fix (emSign ECC Root CA - G3 distrusted): the file, its base64 line in the bundle (the
# bundle has no labels, so grepping the CA name would always pass), and the package version.
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/* \
    && test ! -e /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
    && ! grep -qxF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1

# Chromium does not use that system store: it verifies TLS against its own built-in Chrome Root Store,
# and Chromium 156 still trusts emSign ECC Root CA - G3 (upstream dropped it in a later root-store
# version, which Chrome normally receives through the component updater that puppeteer's
# --disable-background-networking turns off). This managed policy distrusts that root's key, the same
# removal upstream made, so the keeper cannot be MITMed with an emSign-chained certificate.
COPY chromium-policy.json /etc/chromium/policies/managed/ars0n-distrust-emsign-g3.json

WORKDIR /app

# npm ci installs exactly the committed lock (every tarball sha512-verified) and never re-resolves.
# --ignore-scripts skips every lifecycle script, including puppeteer's browser-download postinstall.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
    && node -e "import('puppeteer').then(async({default:p})=>{const b=await p.launch({headless:true,args:['--no-sandbox','--disable-dev-shm-usage']});const v=await b.version();await b.close();const m=Number((v.match(/\/(\d+)\./)||[])[1]);console.log('browser',v);if(!(m>=156)){console.error('Chromium too old: '+v);process.exit(1)}}).catch(e=>{console.error(e);process.exit(1)})"
# The last line FAILS THE BUILD unless puppeteer can actually launch the browser and drive it over CDP
# (executable path, shared libraries and protocol all work on this arch) and it is Chromium >= 156,
# so a stale mirror cannot ship an old browser. Without it the container ships and the keeper quietly
# harvests nothing.

# Nothing runs a package manager after this point (the api talks to the keeper only through files in
# /tmp/session-keeper), so remove them from the runtime image.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
        /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
        /opt/yarn-v1.22.22 /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY keeper.mjs keeperLib.mjs ./

# Resolve the entry module's full import graph at build time (puppeteer + ./keeperLib.mjs) WITHOUT
# running the loop (the argv guard in keeper.mjs keeps main() from firing under a bare import). This
# fails the build the same cheap way the puppeteer check above does if a sibling module is ever
# forgotten in the COPY line - the exact regression that would otherwise ship a crash-looping image.
RUN node -e "import('/app/keeper.mjs').then(()=>console.log('keeper import graph resolves')).catch(e=>{console.error(e);process.exit(1)})"

# The keeper launches Chromium with --no-sandbox, so running as root in the container is fine.
ENTRYPOINT ["node", "/app/keeper.mjs"]
