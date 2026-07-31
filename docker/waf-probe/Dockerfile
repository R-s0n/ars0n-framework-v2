FROM python:3.11-slim

WORKDIR /app

# wafw00f = WAF fingerprinting (~150 vendor signatures); requests = custom baseline/rate-limit/
# attack probes. Pinned so rebuilds are reproducible (matches the framework's pinning convention).
RUN pip install --no-cache-dir wafw00f==2.3.1 requests==2.32.3

COPY waf_probe.py /app/waf_probe.py

# Shared long-running container; the API server drives it via `docker exec ... python waf_probe.py`
# (same model as the ffuf container).
ENTRYPOINT ["sleep", "infinity"]
