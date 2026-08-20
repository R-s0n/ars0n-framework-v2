# Mantra hunts hardcoded API keys and credentials inside the JavaScript and HTML a target serves.
# Go, and it reads its targets from stdin rather than from a flag.
FROM golang:1.24-bookworm AS build
# brosck/mantra, not MrEmpy/mantra: the project moved, and the old path now fails the build outright
# with "module declares its path as: github.com/brosck/mantra".
RUN GOBIN=/out go install github.com/brosck/mantra@latest

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/mantra /usr/local/bin/mantra
WORKDIR /tmp
ENTRYPOINT ["mantra"]
