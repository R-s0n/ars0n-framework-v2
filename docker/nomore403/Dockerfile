# nomore403 is Go, but it is NOT a self-contained binary: it reads payload and header wordlists from
# files at runtime (payloads/, and the header/IP lists beside them). `go install` gives you the
# binary WITHOUT those files, and the tool then runs, finds nothing, and exits 0. So the repository is
# cloned and kept, and the working directory is set to it.
# Go 1.26.9 on Debian trixie, pinned by multi-arch index digest (linux/amd64 + linux/arm64).
FROM golang:1.27.1-trixie@sha256:8f58fd67ea075142d947a60e0caa4317746a55118d312f027793d382c7741734 AS build
# GOTOOLCHAIN=local fails the build instead of downloading a different Go toolchain; -mod=readonly and
# the public proxy keep module resolution to what go.sum and the checksum database already pin.
ENV GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOPROXY=https://proxy.golang.org
# Pinned to the v2.0.1 release commit (tag v2.0.1 -> 40e7b6cbe92e8acb2864425f14f3945d8fc19a16), fetched by
# SHA and checked so a moved branch or a lookalike commit fails the build. It has to stay v2: the api
# relies on --jsonl, --strict-calibrate, --top-score-min, --host-delay and the score fields.
RUN git init /src && cd /src \
    && git remote add origin https://github.com/devploit/nomore403.git \
    && git fetch --depth 1 origin 40e7b6cbe92e8acb2864425f14f3945d8fc19a16 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = 40e7b6cbe92e8acb2864425f14f3945d8fc19a16
WORKDIR /src
# The committed go.mod/go.sum in pin/ replace the upstream ones: golang.org/x/sys v0.48.0 and
# x/text v0.42.0, and "go 1.26.0" so no toolchain download is ever needed.
COPY pin/go.mod pin/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    for i in 1 2 3 4 5; do GODEBUG=http2client=0 go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go module proxy error"; sleep $((i * 5)); done \
    && go mod verify \
    && go build -trimpath -o /out/nomore403 . \
    && rm -rf /src/.git

# Debian 13 (trixie) slim, pinned by multi-arch index digest. Take the signed security updates and fail
# the build if the trust store still holds a root of the 2026-10 eMudhra/emSign compromise.
FROM debian:trixie-20261005-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
# curl is a RUNTIME DEPENDENCY, not a convenience. The http-versions and http-parser techniques shell
# out to the curl BINARY because Go's net/http will not emit the malformed request lines they need.
# Without it nomore403 prints "Skipping HTTP versions technique: curl not found in PATH" and carries
# on, so two of its twenty-three techniques quietly never run and the report still reads as complete.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl --version > /dev/null \
    && test -s /etc/ssl/certs/ca-certificates.crt && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt \
    && ! ls /usr/share/ca-certificates/mozilla | grep -qiE 'AAA_Certificate|emSign_(ECC_)?Root_(CA|TLS|CS)_.*G3'
COPY --from=build /out/nomore403 /usr/local/bin/nomore403
COPY --from=build /src /opt/nomore403
WORKDIR /opt/nomore403
ENTRYPOINT ["nomore403"]
