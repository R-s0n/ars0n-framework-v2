FROM golang:1.24-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

ENV ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.24

RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go install github.com/j3ssie/metabigor@v1.2.8 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

ENTRYPOINT ["/go/bin/metabigor"] 