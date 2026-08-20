# graphql-cop is a single-file Python tool with a small dependency set. Cloned rather than pip
# installed so the version is pinned to a commit and its own test modules are present.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
    && python /opt/graphql-cop/graphql-cop.py --help > /dev/null
WORKDIR /opt/graphql-cop
ENTRYPOINT ["python", "/opt/graphql-cop/graphql-cop.py"]
