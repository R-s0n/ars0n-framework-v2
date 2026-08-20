# graphw00f fingerprints the engine behind a GraphQL endpoint and maps it to known CVEs. The CVE
# mapping lives in files in the repository (docs/), not in the code, so the clone is kept whole.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/dolevf/graphw00f.git /opt/graphw00f \
    && pip install --no-cache-dir -r /opt/graphw00f/requirements.txt 2>/dev/null || pip install --no-cache-dir requests \
    && python /opt/graphw00f/main.py --help > /dev/null
# graphw00f-batch exists because main.py asks a question. When it cannot confirm GraphQL at the URL
# it prints "[*] Continue anyway? [y/n]" and calls input(); on a non-TTY that is
# "EOFError: EOF when reading a line" and the run produces nothing at all. There is no flag to
# suppress it.
#
# The answer is y, deliberately: in this framework the operator has already declared the URL to be a
# GraphQL endpoint, so their judgement outranks graphw00f's detection heuristic. The framework
# reports separately that detection did not confirm it, so a wrong marking is still visible.
RUN printf '%s\n' '#!/bin/sh' 'yes y | python /opt/graphw00f/main.py "$@"' \
      > /usr/local/bin/graphw00f-batch \
    && chmod +x /usr/local/bin/graphw00f-batch
WORKDIR /opt/graphw00f
ENTRYPOINT ["python", "/opt/graphw00f/main.py"]
