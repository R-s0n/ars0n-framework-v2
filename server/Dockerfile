FROM golang:1.26-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

# Install required packages (retry so a transient Alpine mirror hiccup does not abort the build)
RUN for i in 1 2 3 4 5; do apk add --no-cache git gcc musl-dev docker && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apk error"; sleep $((i * 5)); done

# Install httpx (retry around the Go module proxy)
RUN for i in 1 2 3 4 5; do GODEBUG=http2client=0 go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0 && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go proxy error"; sleep $((i * 5)); done

WORKDIR /app

COPY go.mod go.sum ./
# go mod download over the module proxy, retried for the same reason
RUN for i in 1 2 3 4 5; do go mod download && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient Go proxy error"; sleep $((i * 5)); done

COPY . .

RUN mkdir -p /app/temp
RUN chmod -R 777 /app/temp

RUN go build -o main .

EXPOSE 8443

CMD ["./main"]
