# Built from GIT HEAD, deliberately, not from crates.io.
#
# Both call themselves 0.3.0 and --version cannot tell them apart, but they are materially different
# programs. Measured differences that matter here:
#   - crates.io has no h2-downgrade check at all; asking for it scans nothing and exits 0. HEAD has
#     it and at least warns when the target is not TLS.
#   - crates.io reports an unreachable target as clean with exit 0.
#   - crates.io accepts -t 0 / -j 0 / --baseline-count 0 and silently destroys the scan.
# Pinning to the crate would therefore ship a scanner that is quietly worse than the one the project
# documents, so the image tracks the repository.
#
# Rust 1.88 or newer for two reasons, both found by building it: the crate is edition2024 (1.85
# stabilised it) and it uses let-chains, unstable before 1.88 ("`let` expressions in this position
# are unstable", nine occurrences).
FROM rust:1.88-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/hahwul/smugglex.git /src \
    && cd /src \
    && git checkout 3e5388c82ae2c26a5fb22f6a368036cc44d7a93b \
    && cargo build --release \
    && install -m 0755 target/release/smugglex /out-smugglex \
    && git -C /src rev-parse HEAD > /out-revision

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
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
