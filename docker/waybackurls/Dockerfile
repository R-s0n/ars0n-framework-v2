FROM golang:1.21-alpine

WORKDIR /app

RUN apk add --no-cache git && \
    go install github.com/tomnomnom/waybackurls@latest

ENV PATH="/root/go/bin:${PATH}"

ENTRYPOINT ["waybackurls"]

