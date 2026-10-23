# Upload_Bypass works from a SAVED RAW REQUEST: it needs a real, working file upload to mutate,
# because the whole technique is changing one thing at a time about a request the application already
# accepts. That is why the operator marks which requests are uploads rather than the framework
# guessing.
# Base pinned by its multi-arch index digest (linux/amd64 + linux/arm64, built 2026-10-06). Python 3.11
# is supported until 2027-10.
FROM python:3.11.17-slim-trixie@sha256:0dd364ba7e10242f07755449e3a3d0e35f9efd987952737b90def6709ab0c5ce

# Supply chain: everything fetched at build time is pinned. ca-certificates and liblzma5 come from
# trixie-security (the base predates the removal of the compromised emSign ECC Root CA - G3). pip is
# replaced from the hash-pinned pip-bootstrap.txt, and every Python dependency installs from
# requirements.txt with --require-hashes --no-deps, so nothing is resolved at build time. To change a
# version, re-resolve the lock as its header describes; do not add unpinned pip installs here.
#
# Upstream's requirements.txt pins Requests==2.31.0 (three advisories) and is NOT installed; requests
# is the tool's only third-party import, and the lock pins it. There is no fallback install: a failed
# install fails the build instead of silently producing a different image.
ARG UPLOAD_BYPASS_COMMIT=ec90bc074292a448814624905b2f27dc2ad1888c
COPY pip-bootstrap.txt requirements.txt /opt/lock/
RUN apt-get update \
    && apt-get install -y --only-upgrade --no-install-recommends ca-certificates liblzma5 \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/lock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging \
    && git init -q /opt/upload_bypass \
    && git -C /opt/upload_bypass remote add origin https://github.com/sAjibuu/Upload_Bypass.git \
    && git -C /opt/upload_bypass fetch -q --depth 1 origin "$UPLOAD_BYPASS_COMMIT" \
    && git -C /opt/upload_bypass checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/upload_bypass rev-parse HEAD)" = "$UPLOAD_BYPASS_COMMIT"

# Two patches, both measured against v3.0.9#dev rather than guessed.
#
# 1. print_response_options calls os.get_terminal_size() directly, which raises
#    "OSError: [Errno 25] Inappropriate ioctl for device" when there is no TTY. The framework runs
#    every tool through `docker exec` without one, so the scan died on the FIRST module's response
#    having tested nothing, and the run still exited cleanly. The module already has its own
#    get_terminal_size() helper that catches exactly this OSError and falls back to 80 columns; the
#    crashing call site simply does not use it.
RUN sed -i 's/term_size = os\.get_terminal_size()/term_size_columns = get_terminal_size()/; s/term_size\.columns/term_size_columns/g' \
        /opt/upload_bypass/lib/file_upload.py \
    && python -c "import ast,sys; ast.parse(open('/opt/upload_bypass/lib/file_upload.py').read())" \
    && ! grep -n 'os\.get_terminal_size()' /opt/upload_bypass/lib/file_upload.py

# 2. The protocol is a hard-coded module constant (config.protocol = 'https') with no flag, and
#    format_detector builds its URL as f'{protocol}://{host}{path}'. Against an HTTP-only target that
#    is the wrong scheme; the tool only falls back to HTTP when the TLS handshake raises SSLError, so
#    a host that happens to serve HTTPS too would be scanned on the wrong port with no complaint.
#    Reading it from the environment lets the framework pass the vector's real scheme per exec, which
#    a shared container needs: editing the file per scan would race between concurrent scans.
RUN sed -i "s/^protocol = 'https'/import os as _os\nprotocol = _os.environ.get('UPLOAD_BYPASS_PROTOCOL', 'https')/" \
        /opt/upload_bypass/lib/config.py \
    && python -c "import ast; ast.parse(open('/opt/upload_bypass/lib/config.py').read())" \
    && UPLOAD_BYPASS_PROTOCOL=http python -c "import sys; sys.path.insert(0,'/opt/upload_bypass'); from lib import config; assert config.protocol == 'http', config.protocol" \
    && python -c "import sys; sys.path.insert(0,'/opt/upload_bypass'); from lib import config; assert config.protocol == 'https', config.protocol"

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

WORKDIR /opt/upload_bypass
ENTRYPOINT ["python", "/opt/upload_bypass/upload_bypass.py"]
