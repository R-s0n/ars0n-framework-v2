FROM golang:1.24-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 GO111MODULE=on go install github.com/jaeles-project/gospider@v1.1.6 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

WORKDIR /app

ENTRYPOINT ["/go/bin/gospider"] 