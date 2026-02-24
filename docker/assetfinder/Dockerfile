FROM golang:1.24-alpine

RUN go install github.com/tomnomnom/assetfinder@latest

ENTRYPOINT ["/go/bin/assetfinder"] 