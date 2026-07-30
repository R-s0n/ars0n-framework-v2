FROM golang:1.24-alpine
# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto
RUN apk add --no-cache git
RUN go install github.com/ffuf/ffuf/v2@v2.2.1
WORKDIR /app
RUN mkdir -p /wordlists
ENTRYPOINT ["sleep", "infinity"] 