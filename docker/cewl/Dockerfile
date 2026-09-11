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

# Create an entrypoint script. printf rather than echo, because whether echo expands the \n depends
# on which shell runs the RUN: this base's /bin/sh is dash, whose echo does expand it, so the file
# came out correct - but bash's echo does not, and under a different base or an added SHELL
# directive the script would silently become one line holding a literal backslash-n and the
# container would fail to start. printf '%s\n' produces the same two lines under any shell.
RUN printf '%s\n' '#!/bin/sh' 'while true; do sleep 3600; done' > /entrypoint.sh && \
    chmod +x /entrypoint.sh

USER cewl

ENV SSL_CERT_DIR=/etc/ssl/certs
ENV LANG=C.UTF-8
ENV RUBYOPT="-W0"

ENTRYPOINT ["/entrypoint.sh"] 