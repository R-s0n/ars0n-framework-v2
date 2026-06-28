FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/tomnomnom/assetfinder/releases/latest/download/assetfinder-linux-amd64-0.1.1.tgz \
    -O /tmp/assetfinder.tgz && \
    tar -xzf /tmp/assetfinder.tgz -C /usr/local/bin/ && \
    chmod +x /usr/local/bin/assetfinder && \
    rm /tmp/assetfinder.tgz

ENTRYPOINT ["assetfinder"]