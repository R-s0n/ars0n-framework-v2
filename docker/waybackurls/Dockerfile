FROM golang:1.21-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

WORKDIR /app

RUN apk add --no-cache git && \
    go install github.com/tomnomnom/waybackurls@v0.1.0

# archivefetch replaces waybackurls for the archive query, and waybackurls stays installed only so
# anything still calling it by name keeps resolving.
#
# waybackurls sends Go's default User-Agent, web.archive.org answers that with HTTP 429, and
# waybackurls discards the resulting parse error and exits 0 having printed nothing. Measured in this
# image on 2026-08-21 against ginandjuice.shop: both @v0.1.0 and @latest print zero bytes and exit 0,
# while wget against the identical CDX URL from the same container returns real data. See
# archivefetch/main.go for the full measurement table.
COPY archivefetch/ /src/archivefetch/
RUN cd /src/archivefetch && \
    go mod init archivefetch && \
    go build -o /go/bin/archivefetch .

ENV PATH="/root/go/bin:${PATH}"

ENTRYPOINT ["archivefetch"]
