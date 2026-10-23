# Base pinned by its multi-arch index digest (linux/amd64 + linux/arm64, built 2026-10-06). Python 3.11
# is supported until 2027-10.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# Supply chain: everything fetched at build time is pinned. ca-certificates and liblzma5 come from
# trixie-security (the base predates the removal of the compromised emSign ECC Root CA - G3). pip is
# replaced from the hash-pinned pip-bootstrap.txt, and every Python dependency installs from
# requirements.txt with --require-hashes --no-deps, so nothing is resolved at build time. To change a
# version, re-resolve the lock as its header describes; do not add unpinned pip installs here.

WORKDIR /app

# What the lock (requirements.txt) is for:
# wafw00f      = WAF vendor fingerprinting (~150 signatures). 2.4.x no longer pulls the sdist-only
#                pluginbase, so nothing is built from source.
# requests     = the probe's HTTP client.
# brotli       = so a failure to decode a Brotli response is attributable to us rather than
#                reported as a defect in the target. Without it the encoding test would fabricate
#                a finding. 1.2.1 is a documented young-version exception: every earlier release has
#                a decoder out-of-bounds write (CVE-2026-111497) reachable from a hostile target's
#                response.
# cryptography = certificate parsing, including the SAN list on an unverified handshake, which is
#                exactly the case where the SANs matter most. The stdlib alternative is a private
#                API that breaks on a base-image bump.
COPY pip-bootstrap.txt requirements.txt /opt/lock/
RUN apt-get update \
    && apt-get install -y --only-upgrade --no-install-recommends ca-certificates liblzma5 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging

# Deliberately NOT bundled: curl_cffi. Its purpose is TLS-fingerprint impersonation, which is
# defeating bot management rather than characterising it. Leaving it out means this container
# structurally cannot perform fingerprint evasion. An operator who needs it installs it knowingly,
# with `docker exec ars0n-framework-v2-waf-probe-1 pip install curl_cffi==<version>`, choosing a
# release whose bundled libcurl is curl 8.23.0 or newer: as of 2026-10 no stable curl_cffi release
# qualifies (0.16.x bundles curl 8.21.0, which has known server-triggerable memory-safety bugs).

COPY probe/ /app/probe/
COPY probe_tests/ /app/probe_tests/
COPY waf_probe.py /app/waf_probe.py

# The payload-safety suite is the machine-checkable form of this tool's promise: that it
# characterises and does not exploit. Running it at build time means an image can never ship with a
# payload that reads a file, runs a command, or reaches real infrastructure.
RUN python -m probe_tests.test_probe

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

# Shared long-running container; the API server drives it via
#   docker exec -i ... python /app/waf_probe.py --config -
# with the config JSON on stdin, because the schema has far more knobs than argv can carry.
ENTRYPOINT ["sleep", "infinity"]
