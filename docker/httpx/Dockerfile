FROM golang:1.26-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0

WORKDIR /app
RUN mkdir -p /data && chmod 777 /data

ENTRYPOINT ["httpx"] 