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

# Install Nuclei templates at a pinned version.
#
# For nuclei the templates ARE the detection logic, so pinning the binary above while leaving the
# corpus floating pinned the half that matters least. "nuclei -update-templates" baked whichever
# corpus happened to be current on build day and recorded nothing about it, so no two rebuilds of
# this image scanned for quite the same things.
#
# v10.4.7 is the version this image already shipped (confirmed with "nuclei -templates-version"
# against the built image), so this pin reproduces the coverage in use today rather than jumping
# it. The commit is asserted after the clone because a tag can be repointed upstream and a commit
# SHA cannot: a moved tag now fails the build instead of quietly changing what the scanner detects.
#
# The path stays /root/nuclei-templates. server/utils/redirectCompose.go and several other Go
# files address individual directories under it by absolute path, so moving it would break them.
ARG NUCLEI_TEMPLATES_VERSION=v10.4.7
ARG NUCLEI_TEMPLATES_COMMIT=83234ce456da3e90dda86dfbc5e605e64a846df3
RUN git clone --depth 1 --branch "${NUCLEI_TEMPLATES_VERSION}" \
        https://github.com/projectdiscovery/nuclei-templates.git /root/nuclei-templates && \
    cloned=$(git -C /root/nuclei-templates rev-parse HEAD) && \
    if [ "$cloned" != "${NUCLEI_TEMPLATES_COMMIT}" ]; then \
        echo "nuclei-templates ${NUCLEI_TEMPLATES_VERSION} now resolves to $cloned, expected ${NUCLEI_TEMPLATES_COMMIT}" >&2; \
        exit 1; \
    fi

# Seed the two config-directory files that -update-templates used to leave behind. A clone alone
# does not produce them, and each one changes what a scan does:
#
# .nuclei-ignore is what holds the ~200 known-weak-matcher templates out of a default run. With it
# absent, a default scan loads those 200 and reports their known-noisy matches as findings. Copying
# it from the pinned corpus reproduced the exact "Excluded 200 template[s]" line the old image logs.
#
# .templates-config.json is where nuclei reads the installed version from - not from the template
# tree - so without it the corpus version is blank in the scan log and in -templates-version, which
# is the thing this whole change exists to make legible.
RUN mkdir -p /root/.config/nuclei && \
    cp /root/nuclei-templates/.nuclei-ignore /root/.config/nuclei/.nuclei-ignore && \
    printf '{"nuclei-templates-directory":"/root/nuclei-templates","nuclei-templates-version":"%s"}\n' \
        "${NUCLEI_TEMPLATES_VERSION}" > /root/.config/nuclei/.templates-config.json && \
    rm -rf /root/nuclei-templates/.git /root/nuclei-templates/.github

# Stop nuclei re-fetching the corpus at run time, which is the half of this problem that a pin
# alone does not fix. Verified against this image on 2026-09-08: nuclei v3.3.8 checks for a newer
# corpus on every start and installs it in place, and a scan run logged
#   "Your current nuclei-templates v10.4.7 are outdated. Latest is v10.4.8"
#   "Successfully updated nuclei-templates (v10.4.8) to /root/nuclei-templates"
# before the scan began. The corpus the build produced was therefore never the corpus that scanned,
# and it changed again every time the container was recreated - mid-engagement, with nothing
# recording it.
#
# These are the config-file forms of the -duc and -ud flags. They are set here rather than passed
# as flags because every nuclei invocation lives in server/utils Go code that would each have to
# remember them. nuclei only writes this file on its first real scan, so writing it at build time
# is also what stops the first scan of an engagement running against a corpus nobody chose. Both
# keys were confirmed honoured by v3.3.8, using the update itself as the control: one scan run,
# internet reachable, downloaded v10.4.8 without this file and stayed on v10.4.7 with it. nuclei
# left the file as written rather than replacing it with its own generated defaults.
RUN printf 'disable-update-check: true\nupdate-template-dir: /root/nuclei-templates\n' \
        > /root/.config/nuclei/config.yaml

# Create necessary directories
RUN mkdir -p /tmp/nuclei-mounts && \
    chmod 777 /tmp/nuclei-mounts

# Set Chrome path for nuclei
ENV CHROME_PATH=/usr/bin/google-chrome

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /app

ENTRYPOINT ["/entrypoint.sh"] 