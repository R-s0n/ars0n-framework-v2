FROM golang:1.24-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

RUN GO111MODULE=on go install github.com/jaeles-project/gospider@v1.1.6

WORKDIR /app

ENTRYPOINT ["/go/bin/gospider"] 