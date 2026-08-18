FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/0xacb/recollapse.git /opt/recollapse \
    && pip install --no-cache-dir /opt/recollapse \
    && recollapse --version
# recollapse writes mutations to stdout and makes no network requests of its own; the framework
# replays what it produces. Nothing here needs a shared volume.
WORKDIR /opt/recollapse
ENTRYPOINT ["recollapse"]
