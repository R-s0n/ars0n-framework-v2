# Forbidden is built on PycURL specifically so it can send genuinely malformed requests that the
# Python standard library refuses to construct. PycURL is a C extension, so libcurl's development
# headers and a compiler have to be present at install time even though only the runtime is needed
# afterwards.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir forbidden \
    && forbidden --help > /dev/null 2>&1 || true
WORKDIR /opt
ENTRYPOINT ["forbidden"]
