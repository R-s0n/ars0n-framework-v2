# TruffleHog finds and LIVE-VERIFIES leaked credentials. The verification step is the reason it is
# here: it separates a string that looks like a key from one that still works.
#
# It has no URL source of its own, so the framework fetches what it wants scanned into a directory
# and points the filesystem source at it. curl is therefore a runtime dependency, not a convenience.
# 1.25 or newer: trufflehog v3.97 declares "go >= 1.25.0" and 1.24 fails with GOTOOLCHAIN=local.
FROM golang:1.25-bookworm AS build
# Cloned and built rather than `go install`: trufflehog's go.mod contains replace directives, and
# go install refuses those outright ("It must not contain directives that would cause it to be
# interpreted differently than if it were the main module").
RUN apt-get update && apt-get install -y --no-install-recommends git     && git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /src     && cd /src && go build -o /out/trufflehog .     && /out/trufflehog --version

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --global --add safe.directory '*'
COPY --from=build /out/trufflehog /usr/local/bin/trufflehog
WORKDIR /tmp
ENTRYPOINT ["trufflehog"]
