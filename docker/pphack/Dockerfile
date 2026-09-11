# pphack drives headless Chrome to find CLIENT-SIDE prototype pollution, so the browser is the heavy
# dependency rather than the tool. Chromium comes from the distribution rather than a download, so
# the image does not depend on a runtime fetch the way a puppeteer-based tool would.
# pphack declares "go >= 1.26"; anything older fails with GOTOOLCHAIN=local.
#
# PINNED, not @latest. The output parser hardcodes pphack's Go struct field names (TargetURL,
# ScanURL, JSEvaluation) because the tool emits untagged JSON, so a field rename upstream would make
# the parser read nothing while the scan still exits 0. @latest already let the shipped binary drift
# to v0.1.5 while the parser's comment still said it was measured on v0.1.4; pinning to what is
# actually installed makes the next move deliberate.
# Verified: the built image's binary reports mod github.com/edoardottt/pphack v0.1.5.
# Do NOT roll back to v0.1.4 without re-checking those three field names.
FROM golang:1.26-bookworm AS build
RUN GOBIN=/out go install github.com/edoardottt/pphack/cmd/pphack@v0.1.5

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/pphack /usr/local/bin/pphack
ENV CHROME_PATH=/usr/bin/chromium
WORKDIR /tmp
ENTRYPOINT ["pphack"]
