# pphack drives headless Chrome to find CLIENT-SIDE prototype pollution, so the browser is the heavy
# dependency rather than the tool. Chromium comes from the distribution rather than a download, so
# the image does not depend on a runtime fetch the way a puppeteer-based tool would.
# pphack v0.1.4 declares "go >= 1.26"; anything older fails with GOTOOLCHAIN=local.
FROM golang:1.26-bookworm AS build
RUN GOBIN=/out go install github.com/edoardottt/pphack/cmd/pphack@latest

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/pphack /usr/local/bin/pphack
ENV CHROME_PATH=/usr/bin/chromium
WORKDIR /tmp
ENTRYPOINT ["pphack"]
