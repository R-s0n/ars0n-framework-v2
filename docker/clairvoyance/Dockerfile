# clairvoyance reconstructs a schema from the field suggestions in error messages, so its results
# depend almost entirely on the wordlist it is given. The repository ships one, and it is kept.
#
# Pinned throughout: base by digest, clairvoyance v2.5.5 by commit, dependencies by hash in
# requirements.txt. The package is not pip installed: the framework runs `python -m clairvoyance`
# with an absolute wordlist path, so PYTHONPATH is enough, and it avoids both the poetry-core build
# backend and the obsolete `asyncio` PyPI backport that pyproject.toml still lists (it shadows the
# standard library). aiohttp is installed WITHOUT its [speedups] extra: clairvoyance does not use
# aiodns, brotli or zstd, and those bundle native decoders and c-ares with open advisories. Without
# them aiohttp resolves names with getaddrinfo and does not advertise br/zstd.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# The base digest predates DSA-6572-1 (ca-certificates 20250419+deb13u1, which drops the compromised
# emSign ECC Root CA - G3 and Comodo AAA roots) and DSA-6549-1 (liblzma5). The upgrade brings both in
# from the signed trixie-security repository, and the checks fail the build if a stale mirror did not.
# aiohttp verifies TLS against this system store.
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

ENV PYTHONPATH=/opt/clairvoyance
RUN sha=3492afd418c5761876b557f781cd387088c1af5b \
    && git init -q /opt/clairvoyance \
    && git -C /opt/clairvoyance fetch -q --depth 1 https://github.com/nikitastupin/clairvoyance.git "$sha" \
    && git -C /opt/clairvoyance checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/clairvoyance rev-parse HEAD)" = "$sha" \
    && rm -rf /opt/clairvoyance/.git \
    && python -m clairvoyance --help > /dev/null

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

WORKDIR /opt/clairvoyance
ENTRYPOINT ["python", "-m", "clairvoyance"]
