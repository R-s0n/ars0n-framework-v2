FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/Chocapikk/LFIHunt.git /opt/LFIHunt \
    && pip install --no-cache-dir -r /opt/LFIHunt/requirements.txt

# scanner.py, not LFIHunt.py. The latter is the interactive menu and blocks on input() at once; the
# former is an argparse batch scanner. It imports from core/ by relative package name, so it only
# runs from the repository root.
WORKDIR /opt/LFIHunt
ENTRYPOINT ["python", "/opt/LFIHunt/scanner.py"]
