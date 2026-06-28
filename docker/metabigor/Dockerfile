FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates unzip && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/j3ssie/metabigor/releases/latest/download/metabigor_linux_amd64.zip \
    -O /tmp/metabigor.zip && \
    unzip /tmp/metabigor.zip -d /tmp/metabigor_out/ && \
    find /tmp/metabigor_out/ -name "metabigor" -exec mv {} /usr/local/bin/metabigor \; && \
    chmod +x /usr/local/bin/metabigor && \
    rm -rf /tmp/metabigor.zip /tmp/metabigor_out/

ENTRYPOINT ["metabigor"]