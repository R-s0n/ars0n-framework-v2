FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && python /opt/commix/commix.py --version
RUN mkdir -p /tmp/commix-out
# commix reads its payload and CGI lists by path relative to its own package, so it runs from there.
WORKDIR /opt/commix
ENTRYPOINT ["python", "/opt/commix/commix.py"]
