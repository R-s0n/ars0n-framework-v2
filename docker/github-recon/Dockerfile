FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install github-search tools dependencies
RUN pip install requests beautifulsoup4 selenium colored tldextract

# Clone github-search repository
RUN git clone https://github.com/gwen001/github-search.git /app/github-search

# Make the scripts executable
RUN chmod +x /app/github-search/*.py

# Create a simple wrapper script for easier usage. printf rather than echo, because whether echo
# expands the \n depends on which shell runs the RUN: this base's /bin/sh is dash, whose echo does
# expand it, so the file came out as the intended two lines - but bash's echo does not, and under a
# different base or an added SHELL directive the wrapper would silently become one line holding a
# literal backslash-n. printf '%s\n' produces the same file under any shell. The single quotes are
# what keep "$@" literal here, exactly as before.
RUN printf '%s\n' '#!/bin/bash' 'python3 /app/github-search/github-endpoints.py "$@"' > /app/github-recon.py && \
    chmod +x /app/github-recon.py

# Set the working directory to where the scripts are
WORKDIR /app

CMD ["sleep", "infinity"] 