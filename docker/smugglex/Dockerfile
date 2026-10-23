# Built from a pinned commit of the git repository, deliberately, not from crates.io.
#
# Both call themselves 0.3.0 and --version cannot tell them apart, but they are materially different
# programs. Measured differences that matter here:
#   - crates.io has no h2-downgrade check at all; asking for it scans nothing and exits 0. The repo
#     has it and at least warns when the target is not TLS.
#   - crates.io reports an unreachable target as clean with exit 0.
#   - crates.io accepts -t 0 / -j 0 / --baseline-count 0 and silently destroys the scan.
# Pinning to the crate would therefore ship a scanner that is quietly worse than the one the project
# documents, so the image tracks the repository - at a fixed commit. 4bc5329 is the audited 3e5388c
# plus two maintainer commits: a docs fix and a cap on HTTP/1.x response and proxy CONNECT reads, so
# a hostile target can no longer exhaust the scanner's memory.
#
# DEPENDENCIES ARE LOCKED BY THE Cargo.lock NEXT TO THIS FILE, not by upstream's. It is upstream's
# lock at this commit with four `cargo update --precise` moves that clear published advisories:
# rustls 0.23.45, aws-lc-rs 1.18.0 (which brings aws-lc-sys 0.44.0 and its pkg-config build
# dependency), and the two emSign fixes (2026-10 eMudhra key compromise): webpki-roots 1.0.10, which
# drops emSign ECC Root CA - G3 from the root store compiled into smugglex (RUSTSEC-2026-0381), and
# rustls-webpki 0.103.16, which rejects any chain through the compromised emSign intermediates
# whatever root it ends at, including one added with --cacert (RUSTSEC-2026-0382). No older release
# of either crate has the fix, so both are taken under the documented young-version exception
# (rustls maintainers, tag-aligned, crate contents diffed against the tags, no build.rs, no
# dependency changes). --locked makes the build fail rather than re-resolve: without it a
# lock cargo considers stale is silently rewritten with whatever crates.io serves that day, which is
# how a typosquatted build dependency would arrive. AWS_LC_SYS_USE_SYSTEM=0 keeps aws-lc-sys on its
# vendored, checksummed AWS-LC source instead of probing the builder for a system crypto library.
#
# Rust 1.88 or newer for two reasons, both found by building it: the crate is edition2024 (1.85
# stabilised it) and it uses let-chains, unstable before 1.88 ("`let` expressions in this position
# are unstable", nine occurrences).
FROM rust:1.99.0-slim-bookworm@sha256:2c3a22f0a5533ea2dd5a16627bc841228151faa2d4de2644ac9987e4a2f1f2fa AS build
ENV AWS_LC_SYS_USE_SYSTEM=0
ARG SMUGGLEX_COMMIT=4bc532973ee3bb534571f465544c83bdc3315f25
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && git init -q /src \
    && git -C /src remote add origin https://github.com/hahwul/smugglex.git \
    && git -C /src fetch -q --depth 1 origin "$SMUGGLEX_COMMIT" \
    && git -C /src checkout -q --detach FETCH_HEAD \
    && test "$(git -C /src rev-parse HEAD)" = "$SMUGGLEX_COMMIT"
COPY Cargo.lock /src/Cargo.lock
RUN cd /src \
    && cargo build --release --locked \
    && install -m 0755 target/release/smugglex /out-smugglex \
    && git -C /src rev-parse HEAD > /out-revision

# Same Debian release as the builder. `apt-get upgrade` pulls current signed fixes, including the
# ca-certificates release that drops the compromised emSign ECC Root CA - G3; the build fails if that
# root is still trusted or the bundle is missing (matched by the certificate's first base64 line; the
# bundle has no names, so grepping the CA name could never fail). smugglex itself verifies TLS
# against the webpki-roots bundle compiled into it, so that refresh covers the system store only;
# the binary's own roots are fixed by the webpki-roots and rustls-webpki moves above.
FROM debian:bookworm-20261005-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out-smugglex /usr/local/bin/smugglex
# The commit is recorded because --version reports 0.3.0 for every build ever made, so this file is
# the only way to know which smugglex an old scan actually ran.
COPY --from=build /out-revision /etc/smugglex-revision
# The build FAILS if this is not the git binary. Both builds print "smugglex 0.3.0", so the only
# reliable discriminators are two features the crate does not have at all: the h2-downgrade check and
# the TLS section (-k/--insecure, --cacert). Without this line a silent fallback to the crate would
# ship a scanner with six checks instead of seven, no way to reach a self-signed target, and three
# silent-nothing bugs the framework's own tests assume are absent.
RUN smugglex --version \
    && smugglex --help | grep -q 'h2-downgrade' \
    && smugglex --help | grep -q '^TLS:' \
    && smugglex --help > /etc/smugglex-help.txt
ENTRYPOINT ["smugglex"]
