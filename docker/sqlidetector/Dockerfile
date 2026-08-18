FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/eslam3kl/SQLiDetector.git /opt/SQLiDetector \
    && pip install --no-cache-dir -r /opt/SQLiDetector/requirements.txt

# requirements.txt pins requests==2.22.0, which is from 2019 and fails to negotiate TLS against a
# fair number of modern hosts. Upgraded afterwards so the pin does not decide which targets are
# scannable. rich and exurl stay where they were pinned; only the HTTP client is moved.
RUN pip install --no-cache-dir --upgrade "requests>=2.31" \
    && python /opt/SQLiDetector/sqlidetector.py --help > /dev/null

# sqlidetector.py opens txt/payloads.txt and txt/sql_errors.txt by RELATIVE path, so it only works
# when the process runs from the repository root. Anywhere else it dies on a missing wordlist part
# way through rather than at startup.
WORKDIR /opt/SQLiDetector
ENTRYPOINT ["python", "/opt/SQLiDetector/sqlidetector.py"]
