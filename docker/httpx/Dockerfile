FROM golang:1.24-alpine

RUN apk add --no-cache git
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

WORKDIR /app
RUN mkdir -p /data && chmod 777 /data

ENTRYPOINT ["httpx"] 