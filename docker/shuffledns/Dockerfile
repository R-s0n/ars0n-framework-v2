FROM golang:1.24-alpine

RUN apk add --no-cache git build-base

# Install massdns
RUN git clone https://github.com/blechschmidt/massdns.git && \
    cd massdns && \
    make && \
    mv bin/massdns /usr/local/bin/ && \
    cd .. && \
    rm -rf massdns

# Install shuffledns
RUN go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

# Create directory for wordlists
RUN mkdir -p /app/wordlists

WORKDIR /app

# Copy wordlists if they exist in build context
COPY wordlists/* /app/wordlists/

CMD ["sleep", "infinity"] 