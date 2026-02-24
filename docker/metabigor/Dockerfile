FROM golang:1.24-alpine

ENV ASSUME_NO_MOVING_GC_UNSAFE_RISK_IT_WITH=go1.24

RUN go install github.com/j3ssie/metabigor@latest

ENTRYPOINT ["/go/bin/metabigor"] 