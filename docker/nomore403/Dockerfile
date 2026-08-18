# nomore403 is Go, but it is NOT a self-contained binary: it reads payload and header wordlists from
# files at runtime (payloads/, and the header/IP lists beside them). `go install` gives you the
# binary WITHOUT those files, and the tool then runs, finds nothing, and exits 0. So the repository is
# cloned and kept, and the working directory is set to it.
# go.mod requires go >= 1.24.0; 1.23 fails with "GOTOOLCHAIN=local".
FROM golang:1.24-bookworm AS build
RUN git clone https://github.com/devploit/nomore403.git /src \
    && cd /src \
    && go build -o /out/nomore403 .

FROM debian:bookworm-slim
# curl is a RUNTIME DEPENDENCY, not a convenience. The http-versions and http-parser techniques shell
# out to the curl BINARY because Go's net/http will not emit the malformed request lines they need.
# Without it nomore403 prints "Skipping HTTP versions technique: curl not found in PATH" and carries
# on, so two of its twenty-three techniques quietly never run and the report still reads as complete.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl --version > /dev/null
COPY --from=build /out/nomore403 /usr/local/bin/nomore403
COPY --from=build /src /opt/nomore403
WORKDIR /opt/nomore403
ENTRYPOINT ["nomore403"]
