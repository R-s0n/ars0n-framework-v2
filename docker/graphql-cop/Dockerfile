# graphql-cop is a single-file Python tool with a small dependency set. Cloned rather than pip
# installed so its own test modules are present.
#
# NOT PINNED, despite what the comment here used to say. The clone below takes no commit and no tag,
# so every rebuild takes whatever master is that day. Corrected rather than left, because a comment
# asserting a pin that the line beneath it does not implement stops the next reader from looking.
# graphql-cop has no positive control in vectorCanary.go, so a change to its output format would
# surface as clean GraphQL scans rather than as an error. Pin the commit x8-style when you next
# touch this file.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop \
    && pip install --no-cache-dir -r /opt/graphql-cop/requirements.txt \
    && python /opt/graphql-cop/graphql-cop.py --help > /dev/null
WORKDIR /opt/graphql-cop
ENTRYPOINT ["python", "/opt/graphql-cop/graphql-cop.py"]
