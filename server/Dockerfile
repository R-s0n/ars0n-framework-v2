FROM alpine:edge

# Add community + testing for Go 1.24, then install Go and tools
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories && \
    echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk update && \
    apk add --no-cache go git gcc musl-dev docker

# Setup Go environment
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# Install latest httpx (needs Go >= 1.23)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /app/temp && chmod -R 777 /app/temp

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]
