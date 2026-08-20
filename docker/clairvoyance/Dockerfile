# clairvoyance reconstructs a schema from the field suggestions in error messages, so its results
# depend almost entirely on the wordlist it is given. The repository ships one, and it is kept.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/nikitastupin/clairvoyance.git /opt/clairvoyance \
    && pip install --no-cache-dir /opt/clairvoyance \
    && python -m clairvoyance --help > /dev/null
WORKDIR /opt/clairvoyance
ENTRYPOINT ["python", "-m", "clairvoyance"]
