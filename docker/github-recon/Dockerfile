# Pinned throughout: base by digest, gwen001/github-search v2.0.1 by commit, dependencies by hash in
# requirements.txt. The two scripts the framework runs (github-endpoints.py, github-subdomains.py)
# import only requests, colored and tldextract, so selenium and beautifulsoup4 are no longer installed.
# This image sends the operator's GitHub token to api.github.com.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

WORKDIR /app

# The base digest predates DSA-6572-1 (ca-certificates 20250419+deb13u1, which drops the compromised
# emSign ECC Root CA - G3 and Comodo AAA roots) and DSA-6549-1 (liblzma5). The upgrade brings both in
# from the signed trixie-security repository, and the checks fail the build if a stale mirror did not.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
    && apt-get install -y git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' liblzma5)" ge 5.8.1-1+deb13u2 \
    && test ! -e /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
    && test ! -e /usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt \
    && ! ls /etc/ssl/certs | grep -q 'emSign_ECC_Root_CA_-_G3' \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

# Install github-search tools dependencies
COPY pip-bootstrap.txt requirements.txt /opt/pylock/
RUN python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/pylock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/pylock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging

# tldextract would otherwise download the Public Suffix List from publicsuffix.org (and a GitHub
# mirror) at run time and cache it under a file lock. Empty values make it use the snapshot bundled
# in the pinned wheel and disable the disk cache, so no unpinned data is fetched and filelock (which
# has open advisories fixed only in a release too new to adopt) is never used.
ENV TLDEXTRACT_PUBLIC_SUFFIX_LIST_URLS= \
    TLDEXTRACT_CACHE=

# Clone github-search repository
RUN sha=a02b8f35c94e050ac3e6808877485d9197452071 \
    && git init -q /app/github-search \
    && git -C /app/github-search fetch -q --depth 1 https://github.com/gwen001/github-search.git "$sha" \
    && git -C /app/github-search checkout -q --detach FETCH_HEAD \
    && test "$(git -C /app/github-search rev-parse HEAD)" = "$sha" \
    && rm -rf /app/github-search/.git

# Make the scripts executable
RUN chmod +x /app/github-search/*.py \
    && python3 /app/github-search/github-endpoints.py -h > /dev/null \
    && python3 /app/github-search/github-subdomains.py -h > /dev/null

# Create a simple wrapper script for easier usage. printf rather than echo, because whether echo
# expands the \n depends on which shell runs the RUN: this base's /bin/sh is dash, whose echo does
# expand it, so the file came out as the intended two lines - but bash's echo does not, and under a
# different base or an added SHELL directive the wrapper would silently become one line holding a
# literal backslash-n. printf '%s\n' produces the same file under any shell. The single quotes are
# what keep "$@" literal here, exactly as before.
RUN printf '%s\n' '#!/bin/bash' 'python3 /app/github-search/github-endpoints.py "$@"' > /app/github-recon.py && \
    chmod +x /app/github-recon.py

# Build gate. Fails if any CA bundle in the image (Debian's, certifi's, pip's vendored copy) still
# trusts the compromised emSign ECC Root CA - G3, matched by DER sha256 so labels and line wrapping
# cannot hide it, or if site-packages carries a .pth or sitecustomize start-up hook, which is how the
# LiteLLM 1.107.0 payload ran.
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

# Set the working directory to where the scripts are
WORKDIR /app

CMD ["sleep", "infinity"]
