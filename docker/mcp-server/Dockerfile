# Pinned by digest, not just tag: official tags get re-pushed, a digest cannot drift. The index covers
# linux/amd64 and linux/arm64. Node 24 is maintenance LTS to 2028-04-30 (Node 20 went EOL 2026-04-30)
# and 24.22.1 carries the 2026-10-21 Node security fixes. The Alpine 3.24.3 layer already has the
# musl, zlib, OpenSSL 3.5.9 and ca-certificates 20261020 fixes, so no apk step is needed.
FROM node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

# Keeps Express from putting stack traces in 500 responses.
ENV NODE_ENV=production

WORKDIR /app

# Fail the build if the CA bundle still trusts the compromised emSign ECC Root CA - G3 (2026-10-17),
# or is missing. The bundle carries no labels, so this matches the certificate's first PEM line.
RUN test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# The lockfile has to be copied too, not just package.json. npm ci installs the locked tree exactly
# (every entry is a registry.npmjs.org tarball with a sha512 integrity hash) and fails loudly if the
# two files ever drift apart. --ignore-scripts: nothing in the tree needs an install script, so none
# gets to run. --omit=dev omits nothing today; it keeps a future devDependency out of the image.
#
# npm, npx, corepack and yarn are only needed for this one step, so they are removed with the npm
# cache in the same layer. Their own bundled dependencies carry advisories and nothing at runtime
# calls them.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && rm -rf /root/.npm /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
      /opt/yarn-v1.22.22 /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
      /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY src/ ./src/

# Not root: the server only writes files an agent names (the file_path option in tools/wildcard.js),
# and as the image's unprivileged node user (uid 1000) those writes cannot replace /app or src/.
# /app/exports is the one directory node owns; a relative file_path is resolved into it.
RUN mkdir /app/exports && chown node:node /app/exports
USER node

EXPOSE 3001

CMD ["node", "src/index.js"]
