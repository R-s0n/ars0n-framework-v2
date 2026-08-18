# http2smugl speaks HTTP/2 (and optionally HTTP/3) directly, so it needs no browser and no runtime
# beyond the static Go binary.
FROM golang:1.23-bookworm AS build
# Pinned rather than @latest: the repository has no tags, so @latest silently tracks master and two
# builds of this image can contain different scanners with no way to tell them apart.
RUN GOBIN=/out go install github.com/neex/http2smugl@v0.0.0-20250327224651-ccdf77278776

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/http2smugl /usr/local/bin/http2smugl
ENTRYPOINT ["http2smugl"]
