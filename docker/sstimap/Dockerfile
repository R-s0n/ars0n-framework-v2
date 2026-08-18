FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/SSTImap \
    && pip install --no-cache-dir -r /opt/SSTImap/requirements.txt \
    && python /opt/SSTImap/sstimap.py --version
# SSTImap loads its engine plugins from a directory relative to the repository root.
WORKDIR /opt/SSTImap
ENTRYPOINT ["python", "/opt/SSTImap/sstimap.py"]
