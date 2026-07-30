FROM golang:1.21-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

WORKDIR /app

RUN apk add --no-cache git && \
    go install github.com/tomnomnom/waybackurls@v0.1.0

ENV PATH="/root/go/bin:${PATH}"

ENTRYPOINT ["waybackurls"]

