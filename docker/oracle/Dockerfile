# The canary oracle. Deliberately vulnerable by design, so it is built to be as small and as inert as
# a thing can be: standard library only, no shell in the final image, no package manager, nothing on
# disk to read and no way to run anything.
#
# This is NOT built from the tool-container template in docker-compose.yml. Those containers are
# `entrypoint: ["sleep","infinity"]` shells that the api drives with `docker exec`, and copying that
# shape here would produce a container that starts, idles, and answers nothing, which would fail every
# canary check for a reason that has nothing to do with the scanners.
FROM golang:1.23-alpine AS build
WORKDIR /src
# go.mod is COMMITTED rather than created here by `go mod init`, so main_test.go can run outside
# docker. main.go is copied by name and the test file is not, so the image contents are unchanged.
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /oracle .

# scratch, not alpine: the emulated command injection and file inclusion endpoints are emulated
# precisely so nothing here is reachable, and an image with no shell and no filesystem makes that
# guarantee structural rather than a promise in a comment.
FROM scratch
COPY --from=build /oracle /oracle
USER 65534:65534
EXPOSE 8000
ENTRYPOINT ["/oracle"]
