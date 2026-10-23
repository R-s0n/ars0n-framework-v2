# Two stages: Node builds the static bundle, and only that bundle ships, served by nginx. The runtime
# image has no node, npm, node_modules, source or source maps, and does not run as root.
#
# Both bases are pinned by multi-arch index digest (linux/amd64 + linux/arm64), so a re-pushed tag
# cannot change what gets built. Bump tag and digest together.

# Node 24.22.1 (LTS, supported to 2028-04-30) carries the 2026-10-21 security fixes. It is used to build only.
FROM node:24.22.1-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build

WORKDIR /app

# `npm ci` installs exactly what package-lock.json records (each tarball checked against its sha512)
# and fails if the lock and package.json disagree, so nothing is re-resolved at build time.
# .npmrc turns off install scripts and allows registry packages only; --ignore-scripts repeats that
# here so it holds even if .npmrc changes.
COPY package.json package-lock.json .npmrc ./
RUN npm ci --ignore-scripts --no-audit --no-fund

COPY index.html vite.config.mjs ./
COPY public ./public
COPY src ./src
RUN npm run build

# nginx 1.31.6 on Alpine 3.24, the same pinned image as nginx/. The -slim variant has the same nginx
# binary, mime.types and built-in gzip as the full one; it drops curl and the njs, xslt,
# image-filter and geoip modules, none of which nginx.conf loads.
FROM nginx:1.31.6-alpine3.24-slim@sha256:f761b94f2cb9e8e05e2943d5f773609596113ef69b54e2433a996d109a8f78b7

# Take Alpine's current security updates (signed distro repos). In particular ca-certificates
# 20261020 drops the compromised emSign ECC Root CA - G3. The bundle carries no labels, so the build
# checks for that certificate's first PEM line and fails if it is still trusted (or the bundle is
# missing). default.conf is the stock server on port 80; this image serves only nginx.conf below.
RUN apk upgrade --no-cache \
 && test -s /etc/ssl/certs/ca-certificates.crt \
 && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
 && rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=build /app/build /usr/share/nginx/html

# uid 101 is the image's nginx user. nginx.conf keeps the pid file and temp paths in /tmp, and the
# image's entrypoint scripts (which rewrite conf.d) are skipped because nothing here uses them.
USER 101:101
EXPOSE 3000
ENTRYPOINT []
CMD ["nginx", "-g", "daemon off;"]
