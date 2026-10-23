# Base pinned by its multi-arch index digest (linux/amd64 + linux/arm64, built 2026-10-06). Python 3.11
# is supported until 2027-10.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# Supply chain: everything fetched at build time is pinned. ca-certificates and liblzma5 come from
# trixie-security (the base predates the removal of the compromised emSign ECC Root CA - G3). pip is
# replaced from the hash-pinned pip-bootstrap.txt, and every Python dependency installs from
# requirements.txt with --require-hashes --no-deps, so nothing is resolved at build time. To change a
# version, re-resolve the lock as its header describes; do not add unpinned pip installs here.
#
# Upstream's requirements.txt is NOT installed. It pins requests==2.22.0 (2019; stale TLS and idna
# 2.8 advisories); the lock replaces it with the same three imports (rich, exurl, requests) at fixed
# versions. exurl 1.2.1 exists only as an sdist (the 1.2 wheel splits URLs differently), so it is the
# one package built here: against the hash-pinned setuptools from pip-bootstrap.txt with
# --no-build-isolation, so the build fetches nothing. Its source is three small pure-Python files and
# setup.py only calls setup(). setuptools, wheel and packaging are removed afterwards.
#
# Pinned to the last human-authored, signed commit. HEAD (8cee503, 2026-10-04) is a bot commit that
# changes only CONTRIBUTORS.svg.
ARG SQLIDETECTOR_COMMIT=ec29bda5e66af195f1e1508f401610a1e9f650dc
COPY pip-bootstrap.txt requirements.txt /opt/lock/
RUN apt-get update \
    && apt-get install -y --only-upgrade --no-install-recommends ca-certificates liblzma5 \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: --no-binary=exurl --no-build-isolation -r /opt/lock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging \
    && git init -q /opt/SQLiDetector \
    && git -C /opt/SQLiDetector remote add origin https://github.com/eslam3kl/SQLiDetector.git \
    && git -C /opt/SQLiDetector fetch -q --depth 1 origin "$SQLIDETECTOR_COMMIT" \
    && git -C /opt/SQLiDetector checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/SQLiDetector rev-parse HEAD)" = "$SQLIDETECTOR_COMMIT" \
    && python /opt/SQLiDetector/sqlidetector.py --help > /dev/null

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

# sqlidetector.py opens txt/payloads.txt and txt/sql_errors.txt by RELATIVE path, so it only works
# when the process runs from the repository root. Anywhere else it dies on a missing wordlist part
# way through rather than at startup.
WORKDIR /opt/SQLiDetector
ENTRYPOINT ["python", "/opt/SQLiDetector/sqlidetector.py"]
