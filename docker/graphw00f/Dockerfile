# graphw00f fingerprints the engine behind a GraphQL endpoint and maps it to known CVEs. The CVE
# mapping lives in files in the repository (docs/), not in the code, so the clone is kept whole.
#
# Pinned to commit 4901f82 on the canonical repository, which carries the fix that lets -u/-H
# override the headers in conf.py. That same change left a debug `print(headers)` in main.py, which
# would write the operator's -H credentials (the framework passes them) into the stored scan output;
# the line is deleted here and the grep fails the build if it is still present. graphw00f needs only
# requests, installed from the hash-locked requirements.txt. Never `pip install graphw00f`: that PyPI
# name is a placeholder, not this tool.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# The base digest predates DSA-6572-1 (ca-certificates 20250419+deb13u1, which drops the compromised
# emSign ECC Root CA - G3 and Comodo AAA roots) and DSA-6549-1 (liblzma5). The upgrade brings both in
# from the signed trixie-security repository, and the checks fail the build if a stale mirror did not.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1 \
    && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' liblzma5)" ge 5.8.1-1+deb13u2 \
    && test ! -e /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt \
    && test ! -e /usr/share/ca-certificates/mozilla/Comodo_AAA_Services_root.crt \
    && ! ls /etc/ssl/certs | grep -q 'emSign_ECC_Root_CA_-_G3' \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && ! grep -qF 'MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQG' /etc/ssl/certs/ca-certificates.crt

COPY pip-bootstrap.txt requirements.txt /opt/pylock/
RUN python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/pylock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/pylock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging

RUN sha=4901f824140a2da168876412593c213afbdd75fb \
    && git init -q /opt/graphw00f \
    && git -C /opt/graphw00f fetch -q --depth 1 https://github.com/dolevf/graphw00f.git "$sha" \
    && git -C /opt/graphw00f checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/graphw00f rev-parse HEAD)" = "$sha" \
    && rm -rf /opt/graphw00f/.git \
    && sed -i '/^[[:space:]]*print(headers)[[:space:]]*$/d' /opt/graphw00f/main.py \
    && ! grep -n 'print(headers)' /opt/graphw00f/main.py \
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

WORKDIR /opt/graphw00f
ENTRYPOINT ["python", "/opt/graphw00f/main.py"]
