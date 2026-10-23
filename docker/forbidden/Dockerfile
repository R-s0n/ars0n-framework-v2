# Forbidden is built on PycURL specifically so it can send genuinely malformed requests that the
# Python standard library refuses to construct. PycURL is a C extension, so libcurl's development
# headers and a compiler have to be present at install time even though only the runtime is needed
# afterwards.
#
# PycURL is deliberately compiled from its hash-locked sdist rather than taken as the manylinux wheel:
# the wheel bundles its own libcurl (8.22.0, affected by the 2026-10-14 curl advisories), while the
# source build links Debian's security-patched libcurl, which apt keeps current. The check after the
# install fails the build if the libcurl pycurl actually loads is anything but the system one. forbidden
# itself and every other dependency are installed --no-deps from requirements.txt (hash-locked;
# regenerate it rather than editing it). The pycurl build uses the base image's setuptools (no build
# isolation, so no unpinned build backend is fetched); setuptools, wheel and packaging are then removed.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# The base digest predates DSA-6572-1 (ca-certificates 20250419+deb13u1, which drops the compromised
# emSign ECC Root CA - G3 and Comodo AAA roots) and DSA-6549-1 (liblzma5). The upgrade brings both in
# from the signed trixie-security repository, and the checks fail the build if a stale mirror did not.
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get -y upgrade \
    && apt-get install -y --no-install-recommends \
        git ca-certificates build-essential libcurl4-openssl-dev libssl-dev \
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
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: \
        --no-binary=pycurl --no-build-isolation -r /opt/pylock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging \
    && python -c "import pycurl; libs = {l.split()[-1] for l in open('/proc/self/maps') if 'libcurl' in l}; print(pycurl.version, libs); assert libs and all(p.startswith(('/usr/lib/', '/lib/')) for p in libs)" \
    && forbidden --help > /dev/null

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

WORKDIR /opt
ENTRYPOINT ["forbidden"]
