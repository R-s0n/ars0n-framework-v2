FROM golang:1.24-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

ENV ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.24

RUN go install github.com/j3ssie/metabigor@v1.2.8

ENTRYPOINT ["/go/bin/metabigor"] 