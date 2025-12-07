FROM ruby:3.2-slim

RUN apt-get update && \
    apt-get install -y git build-essential libcurl4-openssl-dev libxml2-dev zlib1g-dev \
    ca-certificates openssl curl && \
    git clone https://github.com/digininja/CeWL.git /app && \
    cd /app && \
    gem install bundler && \
    bundle config set path.system true && \
    bundle install && \
    chmod +x /app/cewl.rb && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-root user
RUN useradd -m -r -u 1000 cewl && \
    chown -R cewl:cewl /app && \
    mkdir -p /tmp/cewl && \
    chown -R cewl:cewl /tmp/cewl

# Create an entrypoint script
RUN echo '#!/bin/sh\nwhile true; do sleep 3600; done' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

USER cewl

ENV SSL_CERT_DIR=/etc/ssl/certs
ENV LANG=C.UTF-8
ENV RUBYOPT="-W0"

ENTRYPOINT ["/entrypoint.sh"] 