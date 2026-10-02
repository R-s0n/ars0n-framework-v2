FROM golang:1.26-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

RUN apk add --no-cache git build-base

# Install massdns
RUN git clone https://github.com/blechschmidt/massdns.git && \
    cd massdns && \
    make && \
    mv bin/massdns /usr/local/bin/ && \
    cd .. && \
    rm -rf massdns

# Install shuffledns
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@v1.2.1 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done

# Create directory for wordlists
RUN mkdir -p /app/wordlists

WORKDIR /app

# Copy wordlists if they exist in build context
COPY wordlists/* /app/wordlists/

CMD ["sleep", "infinity"] 