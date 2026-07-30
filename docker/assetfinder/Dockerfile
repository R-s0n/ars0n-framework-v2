FROM golang:1.24-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

RUN go install github.com/tomnomnom/assetfinder@v0.1.1

ENTRYPOINT ["/go/bin/assetfinder"] 