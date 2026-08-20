# snallygaster checks for a long list of secret files and misconfigurations in one pass: .git, .svn,
# .env, .DS_Store, core dumps, backups, private keys, phpinfo, server-status and more. A single
# Python tool with few dependencies.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir snallygaster \
    && snallygaster --help > /dev/null
WORKDIR /tmp
ENTRYPOINT ["snallygaster"]
