FROM golang:1.21-alpine

# Install git
RUN apk add --no-cache git

# Install ffuf with direct proxy to avoid TLS handshake timeout issues
ENV GOPROXY=direct
RUN go install github.com/ffuf/ffuf/v2@latest

# Prepare work directory
WORKDIR /app
RUN mkdir -p /wordlists

# Default to sleep to keep container alive (for debugging or later exec)
ENTRYPOINT ["sleep", "infinity"]
