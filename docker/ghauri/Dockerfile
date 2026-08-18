FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri \
    && pip install --no-cache-dir /opt/ghauri \
    && ghauri --version
# The --version call fails the BUILD if the console script did not land on PATH. Without it the
# container ships and the defect surfaces as "executable not found" on the operator's first scan.

WORKDIR /opt/ghauri
ENTRYPOINT ["ghauri"]
