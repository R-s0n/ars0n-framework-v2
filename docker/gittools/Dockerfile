# GitTools is three separate programs in one repository: Finder locates exposed .git directories,
# Dumper downloads one, Extractor rebuilds the commits. They are shell and Python scripts run in
# place rather than an installable package, so the clone is kept and the scripts are called by path.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates curl wget \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/internetwache/GitTools.git /opt/GitTools \
    && pip install --no-cache-dir requests \
    && chmod +x /opt/GitTools/Dumper/gitdumper.sh /opt/GitTools/Extractor/extractor.sh \
    && git config --global --add safe.directory '*'
WORKDIR /opt/GitTools
ENTRYPOINT ["python", "/opt/GitTools/Finder/gitfinder.py"]
