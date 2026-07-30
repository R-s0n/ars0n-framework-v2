FROM golang:1.26-alpine

# Auto-download a newer Go toolchain if a pinned tool requires one
ENV GOTOOLCHAIN=auto

# Install required packages
RUN apk add --no-cache git gcc musl-dev docker

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@v1.10.0

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /app/temp
RUN chmod -R 777 /app/temp

RUN go build -o main .

EXPOSE 8443

CMD ["./main"]
