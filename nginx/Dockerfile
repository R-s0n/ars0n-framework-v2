# Pinned by digest: a tag can be re-pushed, a digest cannot. The -slim variant drops the njs, xslt,
# image-filter and geoip modules and curl, none of which nginx.conf loads (it has no load_module and
# fetches nothing). `apk upgrade` pulls current signed Alpine fixes, including the ca-certificates
# release that drops the compromised emSign ECC Root CA - G3. The bundle carries no labels, so the
# build checks for that certificate's first PEM line and fails if it is still trusted (or the bundle
# is missing). client/ uses this same image.
FROM nginx:1.31.6-alpine3.24-slim@sha256:f761b94f2cb9e8e05e2943d5f773609596113ef69b54e2433a996d109a8f78b7

RUN apk upgrade --no-cache \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
