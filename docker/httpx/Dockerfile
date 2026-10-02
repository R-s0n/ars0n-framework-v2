FROM golang:1.26-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

WORKDIR /app
RUN mkdir -p /data && chmod 777 /data

ENTRYPOINT ["httpx"] 