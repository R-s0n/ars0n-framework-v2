FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/swisskyrepo/SSRFmap.git /opt/SSRFmap
# The repository has no requirements.txt any more (it moved to pyproject), so the imports are
# installed by name. Without this the tool dies on `import urllib3` before printing its banner.
RUN pip install --no-cache-dir urllib3 requests colorama pyyaml \
    && python /opt/SSRFmap/ssrfmap.py --help > /dev/null
# ssrfmap.py opens data/ports and its modules by RELATIVE path, so it only runs from the repo root.
WORKDIR /opt/SSRFmap
ENTRYPOINT ["python", "/opt/SSRFmap/ssrfmap.py"]
