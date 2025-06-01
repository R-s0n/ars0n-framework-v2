FROM golang:1.23-alpine

# Install required packages
RUN apk add --no-cache git gcc musl-dev docker

# Install httpx
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir -p /app/temp
RUN chmod -R 777 /app/temp

RUN go build -o main .

EXPOSE 8080

CMD ["./main"]
