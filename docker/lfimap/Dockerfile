# Base pinned by its multi-arch index digest (linux/amd64 + linux/arm64, built 2026-10-06). Python 3.11
# is supported until 2027-10.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# Supply chain: everything fetched at build time is pinned. ca-certificates and liblzma5 come from
# trixie-security (the base predates the removal of the compromised emSign ECC Root CA - G3). pip is
# replaced from the hash-pinned pip-bootstrap.txt, and every Python dependency installs from
# requirements.txt with --require-hashes --no-deps, so nothing is resolved at build time. To change a
# version, re-resolve the lock as its header describes; do not add unpinned pip installs here.
ARG LFIMAP_COMMIT=ac1f29c2bafcc8c8b16f46c3f6363dc438c99d38
COPY pip-bootstrap.txt requirements.txt /opt/lock/
RUN apt-get update \
    && apt-get install -y --only-upgrade --no-install-recommends ca-certificates liblzma5 \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging \
    && git init -q /opt/LFImap \
    && git -C /opt/LFImap remote add origin https://github.com/hansmach1ne/LFImap.git \
    && git -C /opt/LFImap fetch -q --depth 1 origin "$LFIMAP_COMMIT" \
    && git -C /opt/LFImap checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/LFImap rev-parse HEAD)" = "$LFIMAP_COMMIT"
# The upstream package's only entry point is a console script, `lfimap = lfimap.lfimap:main`. It is
# provided by this wrapper instead of `pip install /opt/LFImap`, which would build the package with an
# unpinned setuptools fetched by build isolation. lfimap.py puts its own directory on sys.path and
# finds its wordlists relative to __file__, so running the file from the clone behaves the same.
# setup.py's other install_requires (argparse, the bs4 shim, pybase64) are never imported.
RUN printf '%s\n' '#!/bin/sh' 'exec python /opt/LFImap/lfimap/lfimap.py "$@"' > /usr/local/bin/lfimap \
    && chmod +x /usr/local/bin/lfimap \
    && lfimap -h > /dev/null

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

# Build gate. Fails if any CA bundle in the image (Debian's, certifi's, pip's vendored copy) still
# trusts the compromised emSign ECC Root CA - G3, matched by DER sha256 so labels and line wrapping
# cannot hide it, or if site-packages carries a .pth or sitecustomize start-up hook, which is how the
# LiteLLM 1.107.0 payload ran. It is stricter than the grep guard (test -s on the system bundle plus
# grep -qF for G3's first PEM line): it also covers certifi and pip's vendored bundle, and a missing
# system bundle fails the build instead of passing.
# To reuse it, copy this comment and the RUN verbatim and keep it the LAST RUN, so nothing installed
# later escapes it. It needs only the stdlib, but it must run under the tool's own interpreter,
# because it checks that interpreter's site.getsitepackages(). It passes only after the earlier
# `apt-get install --only-upgrade ca-certificates` and after pip is replaced from pip-bootstrap.txt
# (pip 26.2.2) or uninstalled, since older pips vendor a bundle that still holds G3. The install
# RUN's `pip uninstall -y setuptools wheel packaging` removes setuptools' distutils-precedence.pth
# and the base image's build tools, which nothing here imports. Positive control: on the bare base
# image it fails and names four offenders (the system bundle, its G3 .pem link, pip's cacert.pem and
# that .pth).
RUN python -c "import base64,glob,hashlib,re,site,sys; \
fp='86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b'; sp=site.getsitepackages(); \
pems=['/etc/ssl/certs/ca-certificates.crt']+glob.glob('/etc/ssl/certs/*.pem')+[f for d in sp for f in glob.glob(d+'/**/*.pem',recursive=True)]; \
bad=[f for f in pems if any(hashlib.sha256(base64.b64decode(b)).hexdigest()==fp for b in re.findall(r'-----BEGIN CERTIFICATE-----(.+?)-----END',open(f,errors='ignore').read(),re.S))]; \
bad+=[f for d in sp for p in ('*.pth','sitecustomize.py','usercustomize.py') for f in glob.glob(d+'/'+p)]; \
sys.exit('supply-chain gate failed: %s' % bad if bad else None)"

# pip is removed last, AFTER the gate above - the gate inspects pip's vendored CA bundle (pip's
# cacert.pem is one of the bundles it checks), so pip must still be present when it runs. This RUN
# only deletes and installs nothing, so the gate still covers the whole image. Same end state as
# ai_service: the runtime image ships no installer, and pip's vendored urllib3/msgpack/certifi go
# with it.
RUN python -m pip uninstall -y pip

WORKDIR /opt/LFImap
ENTRYPOINT ["lfimap"]
