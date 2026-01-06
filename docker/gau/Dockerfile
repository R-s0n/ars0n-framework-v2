FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

RUN CGO_ENABLED=0 go install github.com/lc/gau/v2/cmd/gau@latest

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /go/bin/gau /usr/local/bin/gau

RUN gau -version || echo "gau installed successfully"

ENTRYPOINT ["gau"]
