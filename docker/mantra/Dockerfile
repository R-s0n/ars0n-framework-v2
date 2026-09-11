# Mantra hunts hardcoded API keys and credentials inside the JavaScript and HTML a target serves.
# Go, and it reads its targets from stdin rather than from a flag.
FROM golang:1.24-bookworm AS build
# brosck/mantra, not MrEmpy/mantra: the project moved, and the old path now fails the build outright
# with "module declares its path as: github.com/brosck/mantra".
#
# PINNED, not @latest. Mantra has no positive control in vectorCanary.go, so if a future release
# changed its output format the framework would report clean secret sweeps rather than an error.
# The pin is a PSEUDO-VERSION because the module has no usable release tag on the current path -
# this is the exact commit the built image already contains, verified from the binary's own build
# info (mod github.com/brosck/mantra v0.0.0-20260312130105-6026816210df). Do not "tidy" this into
# a tag such as v3.1: Go declines to select it, most likely because it predates the module path move.
RUN GOBIN=/out go install github.com/brosck/mantra@v0.0.0-20260312130105-6026816210df

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mantra /usr/local/bin/mantra
WORKDIR /tmp
ENTRYPOINT ["mantra"]
