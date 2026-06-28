FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_amd64.zip \
    -O /tmp/httpx.zip && \
    apt-get update && apt-get install -y unzip && \
    unzip /tmp/httpx.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm /tmp/httpx.zip

WORKDIR /app
RUN mkdir -p /data && chmod 777 /data

ENTRYPOINT ["httpx"]