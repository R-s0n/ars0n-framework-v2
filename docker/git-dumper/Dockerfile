# git-dumper reconstructs a repository from an exposed .git directory. It needs a real git binary,
# because after downloading the objects it runs git checkout to rebuild the working tree.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir git-dumper \
    && git config --global --add safe.directory '*' \
    && git-dumper --help > /dev/null
WORKDIR /tmp
ENTRYPOINT ["git-dumper"]
