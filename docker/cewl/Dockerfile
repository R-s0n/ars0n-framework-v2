# Ruby 3.4 pinned by digest; Ruby 3.2 reached end of life on 2026-03-31. 3.4 ships resolv 0.7.2 and
# racc 1.8.1, and every gem in CeWL's lock supports it.
FROM ruby:4.0.0-slim-trixie@sha256:fe89c3e461b5258352ed5cbe0355fe239a0c7d0ca6c4d9fa22537b98d4432a6c

# CeWL is fetched at a pinned commit (current master, the one this image already ran: it reports
# "CeWL 6.3.1 (GetOptLong Deps)") instead of master HEAD, and asserted, because a branch moves and a
# commit SHA cannot.
#
# Its gems come only from its committed Gemfile.lock, which carries a sha256 for every gem, and
# `frozen` makes bundler fail rather than re-resolve. bundler itself is the version the lock was
# written with (BUNDLED WITH 4.0.15), installed from a downloaded .gem checked against the sha256
# that both rubygems.org and the lock's CHECKSUMS section publish, so `gem install bundler` no longer
# takes whatever release is newest on build day.
#
# No compiler or -dev headers: nokogiri comes as a precompiled platform gem, racc ships with Ruby,
# and the rest is pure Ruby, so nothing in the lock builds a native extension.
#
# `apt-get upgrade` also pulls the ca-certificates release that drops the compromised emSign ECC
# Root CA - G3; the build fails if that root is still trusted or the bundle is missing (matched by the
# certificate's first base64 line; the bundle has no names, so grepping the CA name could never fail).
# The ruby base ships the pre-fix 20250419, so this check depends on the upgrade.
ARG CEWL_COMMIT=ca01aeae1c77bb086ef757611dea6377b8d1168b
ARG BUNDLER_VERSION=4.0.15
ARG BUNDLER_SHA256=a4ceb882fe94a0e0ac63cd0813932bbfd631a14e5ac0b7975189b19a4d28d9e7
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends git ca-certificates openssl curl && \
    test -s /etc/ssl/certs/ca-certificates.crt && \
    ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt && \
    git init -q /app && \
    git -C /app remote add origin https://github.com/digininja/CeWL.git && \
    git -C /app fetch -q --depth 1 origin "$CEWL_COMMIT" && \
    git -C /app checkout -q --detach FETCH_HEAD && \
    test "$(git -C /app rev-parse HEAD)" = "$CEWL_COMMIT" && \
    cd /app && \
    curl -fsSLo "/tmp/bundler-$BUNDLER_VERSION.gem" "https://rubygems.org/downloads/bundler-$BUNDLER_VERSION.gem" && \
    echo "$BUNDLER_SHA256  /tmp/bundler-$BUNDLER_VERSION.gem" | sha256sum -c - && \
    gem install --local --no-document "/tmp/bundler-$BUNDLER_VERSION.gem" && \
    rm "/tmp/bundler-$BUNDLER_VERSION.gem" && \
    bundle config set path.system true && \
    bundle config set frozen true && \
    bundle install && \
    chmod +x /app/cewl.rb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-root user
RUN useradd -m -r -u 1000 cewl && \
    chown -R cewl:cewl /app && \
    mkdir -p /tmp/cewl && \
    chown -R cewl:cewl /tmp/cewl

# Create an entrypoint script. printf rather than echo, because whether echo expands the \n depends
# on which shell runs the RUN: this base's /bin/sh is dash, whose echo does expand it, so the file
# came out correct - but bash's echo does not, and under a different base or an added SHELL
# directive the script would silently become one line holding a literal backslash-n and the
# container would fail to start. printf '%s\n' produces the same two lines under any shell.
RUN printf '%s\n' '#!/bin/sh' 'while true; do sleep 3600; done' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

USER cewl

ENV SSL_CERT_DIR=/etc/ssl/certs
ENV LANG=C.UTF-8
ENV RUBYOPT="-W0"

ENTRYPOINT ["/entrypoint.sh"]
