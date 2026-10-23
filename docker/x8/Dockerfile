# x8, the hidden-parameter scanner.
#
# ============================================================================
# WHY THE SOURCE IS PINNED TO A COMMIT AND NOT TO A TAG OR TO main
# ============================================================================
#
# The framework's x8 integration is written against the OBSERVED BEHAVIOUR of one specific build,
# x8 4.3.1-main, audited flag by flag against a purpose-built local target. That audit found the
# binary contradicting its own --help in several places, and every contradiction fails by EXITING 0:
# `-t urlencode` prints an error and exits 0, a repeated `-X` exits 1, several verbs in one `-X` is a
# cross product, `--cookies` reports injection_place "HeaderValue", and a top-level `[]` means the
# tool tested nothing rather than found nothing. The runner, the parser and the request preview all
# encode those specifics.
#
# So the installed binary is the contract, not the upstream source. An unpinned clone of main meant a
# rebuild could silently install a different x8 whose flags behave differently, and because the
# failure mode is exit 0 with an empty result, the whole parameter-enumeration section would report
# clean scans having tested nothing. That is not a hypothetical: the audit notes record reading
# upstream main and concluding repeated `-X` works, when the installed binary rejected it.
#
# THERE IS NO v4.3.1 TAG. Upstream's newest tag is v4.3.0; the version string "4.3.1-main" comes from
# Cargo.toml on the main branch, which is where this has always been built from. Pinning to v4.3.0
# would install a DIFFERENT binary from the audited one, so the pin is the commit whose Cargo.toml
# reads 4.3.1-main. Verified: this SHA's Cargo.toml is version = "4.3.1-main", matching what the
# running container reports for `x8 --version`.
#
# To move to a newer x8, re-run the flag audit first. Bumping this SHA without doing that is how the
# section goes quietly back to reporting zero findings.
ARG X8_COMMIT=c78f246a497196d1658aec32ab7ed76fbac0a11e

# ============================================================================
# WHY BOOKWORM AND NOT BULLSEYE
# ============================================================================
#
# Both stages were on Debian bullseye (rust:1.70 is bullseye-based, and the runtime was
# debian:bullseye-slim). Bullseye's security suite has passed its Valid-Until date, so apt refuses it
# with "Release file ... is expired" and `apt-get update` exits 100. That broke the image build
# outright. It is a clock-driven failure, not a code change: the same Dockerfile built yesterday.
#
# Both stages are moved, not just the runtime one. The reported failure was in the final stage, but
# the builder runs apt-get too and is bullseye-based as well, so fixing only the visible half would
# have left the identical failure waiting behind a build-cache hit.
#
# Both images are pinned by digest (a tag can be re-pushed, a digest cannot). Rust 1.88 was out of
# support; 1.99.0 is current stable on the same Debian release.
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS builder

ARG X8_COMMIT

WORKDIR /app

# Fetch exactly one commit rather than cloning a branch. GitHub serves a fetch by SHA, so this is
# both pinned and shallow; `git clone --depth 1` cannot take a SHA.
#
# --locked matters more here than it normally would. The SHA above pins x8's own source but says
# nothing about its dependencies: Cargo.toml declares url, http and reqwest as bare
# { git = "https://github.com/raw-http/..." } with no rev, tag or branch, and the lock resolves seven
# further raw-http forks behind those, ten third-party repos in all. The committed Cargo.lock is the
# only thing holding any of them to a fixed SHA. Cargo does honour that lock on an ordinary build, but
# the moment it decides the lock needs updating it re-resolves and rewrites it silently, and
# re-resolving a bare git dep means taking whatever that fork's tip is on the day of the build. That
# is the same "same Dockerfile, different binary" outcome the commit pin exists to prevent, so
# --locked turns it into a build failure instead. Verified at this SHA: Cargo.lock is committed
# (--locked hard-fails outright when there is none) and its x8 entry lists the same 23 dependencies
# as Cargo.toml, so the flag has nothing to object to today.
#
# THE LOCK USED IS THE Cargo.lock NEXT TO THIS FILE, copied over upstream's. It is upstream's lock with
# the ten raw-http git SHAs untouched and in-semver `cargo update --precise` moves for crates.io
# crates with published advisories or yanked releases: openssl 0.10.80, ring 0.17.14 (which also
# drops the yanked spin 0.9.8), tokio 1.51.5 (the supported LTS line), time 0.3.47, bytes 1.11.1,
# rand 0.8.6 and the futures family at 0.3.33 (replacing the yanked futures-util 0.3.30). x8's own
# code and the forks that define its flag behaviour are unchanged; the binary still reports
# 4.3.1-main and its --help is identical.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/x8 && cd /app/x8 \
    && git init -q \
    && git remote add origin https://github.com/Sh1Yo/x8.git \
    && git fetch -q --depth 1 origin "${X8_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${X8_COMMIT}"
COPY Cargo.lock /app/x8/Cargo.lock
RUN cd /app/x8 \
    && cargo build --release --locked \
    && strip target/release/x8

FROM debian:bookworm-20261005-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

# libssl3 is listed explicitly because the binary genuinely needs it: `ldd /usr/local/bin/x8` in this
# image reports libssl.so.3 and libcrypto.so.3. Nothing here asked for OpenSSL - x8 enables reqwest's
# rustls-tls feature, but it never sets default-features = false, so reqwest's default native-tls
# backend is compiled in alongside rustls and pulls openssl-sys with it.
#
# Until this line said so, the library arrived purely by accident: ca-certificates depends on openssl,
# which depends on libssl3. That made the cert bundle load-bearing for a reason it does not look
# load-bearing for. Anyone trimming this image would reasonably reason "x8 does TLS with rustls, drop
# ca-certificates" and the container would stop starting - not with a certificate error, but with the
# loader failing on a missing shared object. Naming libssl3 breaks that hidden coupling. Whether the
# cert bundle itself is still required is a separate question this does not answer, so it stays.
#
# `apt-get upgrade` pulls current signed Debian fixes, including the ca-certificates release that
# drops the compromised emSign ECC Root CA - G3; the build fails if that root is still trusted or the
# bundle is missing (matched by the certificate's first base64 line; the bundle has no names, so
# grepping the CA name could never fail).
#
# x8 itself never consults this bundle or the webpki-roots 0.22 roots compiled into it: its only HTTP
# client (src/network/utils.rs) is built with danger_accept_invalid_certs(true), so it accepts any
# certificate by design, emSign-chained or self-signed. There is therefore no emSign exposure to fix
# in the binary, and webpki-roots 0.22 has no release that drops the root anyway.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

COPY --from=builder /app/x8/target/release/x8 /usr/local/bin/x8

# x8 ships NO wordlist, and with none supplied it silently falls back to 11 built-in candidate names
# while printing "wordlist len: 0". The compose file mounts ./wordlists here, same as the ffuf
# container; without that mount the scans "succeed" having tested almost nothing.
WORKDIR /app

ENTRYPOINT ["x8"]
