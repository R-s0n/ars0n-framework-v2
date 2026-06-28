FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/projectdiscovery/shuffledns/releases/latest/download/shuffledns_linux_amd64.zip \
    -O /tmp/shuffledns.zip && \
    unzip /tmp/shuffledns.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/shuffledns && \
    rm /tmp/shuffledns.zip

# Install massdns
RUN apt-get update && apt-get install -y --no-install-recommends \
    git build-essential libpcap-dev && \
    rm -rf /var/lib/apt/lists/* && \
    git clone https://github.com/blechschmidt/massdns.git && \
    cd massdns && \
    make && \
    mv bin/massdns /usr/local/bin/ && \
    cd .. && \
    rm -rf massdns

# Create directory for wordlists
RUN mkdir -p /app/wordlists

WORKDIR /app

# Copy wordlists if they exist in build context
COPY wordlists/* /app/wordlists/

CMD ["sleep", "infinity"]