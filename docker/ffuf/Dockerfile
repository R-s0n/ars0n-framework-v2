FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/ffuf/ffuf/releases/latest/download/ffuf_linux_amd64.tar.gz \
    -O /tmp/ffuf.tar.gz && \
    tar -xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm /tmp/ffuf.tar.gz

WORKDIR /app
RUN mkdir -p /wordlists

ENTRYPOINT ["sleep", "infinity"]