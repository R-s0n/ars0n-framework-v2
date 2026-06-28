FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/jaeles-project/gospider/releases/latest/download/gospider_linux_x86_64.zip \
    -O /tmp/gospider.zip && \
    unzip /tmp/gospider.zip -d /tmp/gospider_out/ && \
    find /tmp/gospider_out/ -name "gospider" -exec mv {} /usr/local/bin/gospider \; && \
    chmod +x /usr/local/bin/gospider && \
    rm -rf /tmp/gospider.zip /tmp/gospider_out/

WORKDIR /app

ENTRYPOINT ["gospider"]