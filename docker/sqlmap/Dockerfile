FROM python:3.11-slim

# sqlmap is pure Python with no dependencies to install, so it is cloned rather than pip installed.
#
# NOT PINNED. This clone tracks master, and the comment that used to sit here claimed the opposite -
# a false comment is worse than none, because it stops the next reader from checking. Stating it
# plainly instead: sqlmap's option names are this framework's vocabulary, so a renamed flag would
# turn every scan into a usage error. What limits the damage today is that sqlmap has a positive
# control in vectorCanary.go, so a broken invocation shows up as a failed control rather than as a
# clean scan. That is a detector, not a fix.
#
# If you pin it, pin the COMMIT the way docker/x8 does (git init + fetch --depth 1 origin $SHA +
# checkout FETCH_HEAD). Do not reach for `--branch <newest tag>`: sqlmap's master is well ahead of
# its newest tag, so that would silently DOWNGRADE the tool rather than freeze it.
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
