# http2smugl speaks HTTP/2 (and optionally HTTP/3) directly, so it needs no browser and no runtime
# beyond the static Go binary.
FROM golang:1.23-bookworm AS build
# Pinned rather than @latest: the repository has no tags, so @latest silently tracks master and two
# builds of this image can contain different scanners with no way to tell them apart.
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 GOBIN=/out go install github.com/neex/http2smugl@v0.0.0-20250327224651-ccdf77278776 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/http2smugl /usr/local/bin/http2smugl
ENTRYPOINT ["http2smugl"]
