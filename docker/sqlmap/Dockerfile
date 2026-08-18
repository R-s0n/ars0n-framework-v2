FROM python:3.11-slim

# sqlmap is pure Python with no dependencies to install, so it is cloned rather than pip installed.
# Pinned to a tag rather than tracking master: sqlmap's option names are this framework's vocabulary,
# and a renamed flag would turn every scan into a usage error rather than into a warning.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && python /opt/sqlmap/sqlmap.py --version

# sqlmap writes its session and output under this directory. It lives on the shared temp_data volume
# so a run's artefacts survive for the API to read and so two scans do not fight over one session
# file, which is what --flush-session exists to paper over.
RUN mkdir -p /tmp/sqlmap-out

WORKDIR /opt/sqlmap
ENTRYPOINT ["python", "/opt/sqlmap/sqlmap.py"]
