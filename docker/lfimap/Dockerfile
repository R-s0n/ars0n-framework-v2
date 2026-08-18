FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/hansmach1ne/LFImap.git /opt/LFImap \
    && pip install --no-cache-dir /opt/LFImap \
    && lfimap -h > /dev/null
# There is no lfimap.py at the repository root: the package installs a console script and that is
# the only entry point. Invoking a file path fails with "can't open file".
#
# lfimap-batch exists because LFImap has FOUR live input() calls and no --yes, --batch or
# --non-interactive flag anywhere in its argument parser. The one that bites is in lfimap.py: when a
# parameter name matches its built-in CSRF list (csrf, xsrf, csrf_token, _csrf, csrfmiddlewaretoken,
# authenticity_token, RequestVerificationToken, antiForgeryToken and four more) and the token value
# rotates between responses, it asks whether to refresh tokens automatically. Nothing gates that
# behind a flag. Reproduced: a URL carrying csrf_token= against a page with a rotating token dies
# with "EOFError: EOF when reading a line" and finds nothing, and CSRF-named parameters are ordinary
# on real applications. Feeding it an endless stream of y answers each prompt the way an operator
# would and the same scan completes.
RUN printf '%s\n' '#!/bin/sh' 'yes | lfimap "$@"' > /usr/local/bin/lfimap-batch \
    && chmod +x /usr/local/bin/lfimap-batch
WORKDIR /opt/LFImap
ENTRYPOINT ["lfimap"]
