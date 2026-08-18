FROM golang:1.23-bookworm AS build
RUN git clone --depth 1 https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner.git /src
WORKDIR /src
RUN go build -o /out/wcvs .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/wcvs /usr/local/bin/wcvs
# The wordlists are NOT embedded in the binary. WCVS ships 2917 header names and 6452 parameter
# names as plain files, and the framework concatenates its own discovered names onto them at scan
# time, so both have to exist at a known path inside this container.
COPY --from=build /src/wordlists /opt/wcvs/wordlists
COPY --from=build /src/templates /opt/wcvs/templates
RUN wcvs --help > /dev/null && test -s /opt/wcvs/wordlists/headers && test -s /opt/wcvs/wordlists/parameters
ENTRYPOINT ["wcvs"]
