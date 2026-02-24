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

# Create a simple wrapper script for easier usage
RUN echo '#!/bin/bash\npython3 /app/github-search/github-endpoints.py "$@"' > /app/github-recon.py && \
    chmod +x /app/github-recon.py

# Set the working directory to where the scripts are
WORKDIR /app

CMD ["sleep", "infinity"] 