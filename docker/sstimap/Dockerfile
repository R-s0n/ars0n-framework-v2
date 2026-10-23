# Base pinned by its multi-arch index digest (linux/amd64 + linux/arm64, built 2026-10-06). Python 3.11
# is supported until 2027-10.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# Supply chain: everything fetched at build time is pinned. ca-certificates and liblzma5 come from
# trixie-security (the base predates the removal of the compromised emSign ECC Root CA - G3). pip is
# replaced from the hash-pinned pip-bootstrap.txt, and every Python dependency installs from
# requirements.txt with --require-hashes --no-deps, so nothing is resolved at build time. To change a
# version, re-resolve the lock as its header describes; do not add unpinned pip installs here.
#
# Upstream's requirements.txt is NOT installed: it pins requests~=2.27.1 and urllib3~=1.26.9, both
# with open HIGH advisories and no fix on those lines. The lock carries the same four imports
# (requests, urllib3, mechanize, html5lib) at fixed versions. SSTImap uses only
# urllib3.disable_warnings and urllib3.exceptions, which urllib3 2.x keeps.
ARG SSTIMAP_COMMIT=1c27fdb4a4cc7d55b66fc0e16937ee7de7047490
COPY pip-bootstrap.txt requirements.txt /opt/lock/
RUN apt-get update \
    && apt-get install -y --only-upgrade --no-install-recommends ca-certificates liblzma5 \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging \
    && git init -q /opt/SSTImap \
    && git -C /opt/SSTImap remote add origin https://github.com/vladko312/SSTImap.git \
    && git -C /opt/SSTImap fetch -q --depth 1 origin "$SSTIMAP_COMMIT" \
    && git -C /opt/SSTImap checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/SSTImap rev-parse HEAD)" = "$SSTIMAP_COMMIT" \
    && python /opt/SSTImap/sstimap.py --version

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

# SSTImap loads its engine plugins from a directory relative to the repository root.
WORKDIR /opt/SSTImap
ENTRYPOINT ["python", "/opt/SSTImap/sstimap.py"]
