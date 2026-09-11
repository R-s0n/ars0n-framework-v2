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
FROM rust:1.88-slim-bookworm AS builder

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
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/x8 && cd /app/x8 \
    && git init -q \
    && git remote add origin https://github.com/Sh1Yo/x8.git \
    && git fetch -q --depth 1 origin "${X8_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && cargo build --release --locked \
    && strip target/release/x8

FROM debian:bookworm-slim

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
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/x8/target/release/x8 /usr/local/bin/x8

# x8 ships NO wordlist, and with none supplied it silently falls back to 11 built-in candidate names
# while printing "wordlist len: 0". The compose file mounts ./wordlists here, same as the ffuf
# container; without that mount the scans "succeed" having tested almost nothing.
WORKDIR /app

ENTRYPOINT ["x8"]
