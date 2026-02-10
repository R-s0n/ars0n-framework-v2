FROM rust:1.70 as builder

WORKDIR /app

RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/Sh1Yo/x8.git && \
    cd x8 && \
    cargo build --release

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/x8/target/release/x8 /usr/local/bin/x8

ENTRYPOINT ["x8"]
