FROM golang:1.24-alpine

RUN go install github.com/lc/gau/v2/cmd/gau@latest

ENTRYPOINT ["/go/bin/gau"] 
