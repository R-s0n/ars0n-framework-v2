FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    wget \
    gnupg \
    ca-certificates \
    git \
    unzip \
    curl

# Detect architecture and install Chrome accordingly
RUN arch=$(dpkg --print-architecture) && \
    if [ "$arch" = "amd64" ]; then \
        wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - && \
        echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list && \
        apt-get update && \
        apt-get install -y google-chrome-stable; \
    elif [ "$arch" = "arm64" ]; then \
        apt-get update && \
        apt-get install -y chromium-browser && \
        ln -s /usr/bin/chromium-browser /usr/bin/google-chrome; \
    else \
        echo "Unsupported architecture: $arch"; \
        exit 1; \
    fi && \
    rm -rf /var/lib/apt/lists/*

# Install Nuclei based on architecture
RUN arch=$(dpkg --print-architecture) && \
    if [ "$arch" = "amd64" ]; then \
        wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_amd64.zip && \
        unzip nuclei_3.3.8_linux_amd64.zip && \
        mv nuclei /usr/local/bin/ && \
        chmod +x /usr/local/bin/nuclei && \
        rm nuclei_3.3.8_linux_amd64.zip; \
    elif [ "$arch" = "arm64" ]; then \
        wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_linux_arm64.zip && \
        unzip nuclei_3.3.8_linux_arm64.zip && \
        mv nuclei /usr/local/bin/ && \
        chmod +x /usr/local/bin/nuclei && \
        rm nuclei_3.3.8_linux_arm64.zip; \
    fi

# Install Nuclei templates
RUN nuclei -update-templates

# Create necessary directories
RUN mkdir -p /tmp/nuclei-mounts && \
    chmod 777 /tmp/nuclei-mounts

# Set Chrome path for nuclei
ENV CHROME_PATH=/usr/bin/google-chrome

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"] 