FROM python:3.11-slim

WORKDIR /app

# wafw00f      = WAF vendor fingerprinting (~150 signatures).
# requests     = the probe's HTTP client.
# brotli       = so a failure to decode a Brotli response is attributable to us rather than
#                reported as a defect in the target. Without it the encoding test would fabricate
#                a finding.
# cryptography = certificate parsing, including the SAN list on an unverified handshake, which is
#                exactly the case where the SANs matter most. The stdlib alternative is a private
#                API that breaks on a base-image bump.
# Pinned so rebuilds are reproducible (matches the framework's pinning convention).
RUN pip install --no-cache-dir \
      wafw00f==2.3.1 \
      requests==2.32.3 \
      brotli==1.1.0 \
      cryptography==43.0.1

# Deliberately NOT bundled: curl_cffi. Its purpose is TLS-fingerprint impersonation, which is
# defeating bot management rather than characterising it. Leaving it out means this container
# structurally cannot perform fingerprint evasion. An operator who needs it installs it knowingly:
#   docker exec ars0n-framework-v2-waf-probe-1 pip install curl_cffi==0.7.1

COPY probe/ /app/probe/
COPY probe_tests/ /app/probe_tests/
COPY waf_probe.py /app/waf_probe.py

# The payload-safety suite is the machine-checkable form of this tool's promise: that it
# characterises and does not exploit. Running it at build time means an image can never ship with a
# payload that reads a file, runs a command, or reaches real infrastructure.
RUN python -m probe_tests.test_probe

# Shared long-running container; the API server drives it via
#   docker exec -i ... python /app/waf_probe.py --config -
# with the config JSON on stdin, because the schema has far more knobs than argv can carry.
ENTRYPOINT ["sleep", "infinity"]
