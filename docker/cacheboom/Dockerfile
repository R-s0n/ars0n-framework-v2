FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/omranisecurity/CacheBoom.git /opt/CacheBoom \
    && pip install --no-cache-dir -r /opt/CacheBoom/requirements.txt

# cacheboom.py imports from core/, modules/, utils/ and input_handlers/ by relative package name and
# reads wordlists/headers.txt by relative path, so it only runs from the repository root.
WORKDIR /opt/CacheBoom
RUN python cacheboom.py --help > /dev/null
ENTRYPOINT ["python", "/opt/CacheBoom/cacheboom.py"]
