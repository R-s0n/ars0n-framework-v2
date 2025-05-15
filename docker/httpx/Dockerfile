FROM alpine:edge

# Add community and testing repos (needed for latest Go)
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories && \
    echo "https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories && \
    apk update && \
    apk add --no-cache go git

ENV GOPATH=/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

# ✅ Now you can install the latest httpx (v1.7.0+)
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

WORKDIR /app
RUN mkdir -p /data && chmod 777 /data

ENTRYPOINT ["httpx"]
