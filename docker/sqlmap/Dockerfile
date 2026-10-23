# Base pinned by its multi-arch index digest (linux/amd64 + linux/arm64, built 2026-10-06). Python 3.11
# is supported until 2027-10.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# Supply chain: everything fetched at build time is pinned. ca-certificates and liblzma5 come from
# trixie-security (the base predates the removal of the compromised emSign ECC Root CA - G3). pip is
# replaced from the hash-pinned pip-bootstrap.txt, and every Python dependency installs from
# requirements.txt with --require-hashes --no-deps, so nothing is resolved at build time. To change a
# version, re-resolve the lock as its header describes; do not add unpinned pip installs here.

# sqlmap is pure Python with no dependencies to install, so it is cloned rather than pip installed,
# and pip-bootstrap.txt only replaces the base image's pip.
#
# PINNED to the commit of tag 1.10.10 (2026-10-05), fetched by SHA the way docker/x8 does and
# verified to be on sqlmap's master history. sqlmap's option names are this framework's vocabulary,
# so a renamed flag would turn every scan into a usage error; the pin means that can only change
# when someone bumps this SHA. vectorCanary.go still holds a positive control for sqlmap, so a broken
# invocation shows up as a failed control rather than as a clean scan.
#
# Do not replace this with `--branch <newest tag>` on a full clone of master or with a bare HEAD
# clone. To move it, pick a newer commit on master, check every flag sqliTools.go emits against
# lib/parse/cmdline.py at that commit, and re-run the canary. .git is kept because sqlmap reads its
# revision string from it.
ARG SQLMAP_COMMIT=65b6e7b4acb13a736614a1ab73b0908476f3c24a
COPY pip-bootstrap.txt /opt/lock/
RUN apt-get update \
    && apt-get install -y --only-upgrade --no-install-recommends ca-certificates liblzma5 \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/pip-bootstrap.txt \
    && pip uninstall -y setuptools wheel packaging \
    && git init -q /opt/sqlmap \
    && git -C /opt/sqlmap remote add origin https://github.com/sqlmapproject/sqlmap.git \
    && git -C /opt/sqlmap fetch -q --depth 1 origin "$SQLMAP_COMMIT" \
    && git -C /opt/sqlmap checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/sqlmap rev-parse HEAD)" = "$SQLMAP_COMMIT" \
    && python /opt/sqlmap/sqlmap.py --version

# sqlmap writes its session and output under this directory. It lives on the shared temp_data volume
# so a run's artefacts survive for the API to read and so two scans do not fight over one session
# file, which is what --flush-session exists to paper over.
RUN mkdir -p /tmp/sqlmap-out

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

WORKDIR /opt/sqlmap
ENTRYPOINT ["python", "/opt/sqlmap/sqlmap.py"]
