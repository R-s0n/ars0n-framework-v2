# python 3.14.8 (Debian 13.7), pinned to the 2026-10-06 multi-arch index (linux/amd64 + linux/arm64).
# Never resolve by tag: 3.14.8-slim-trixie was re-pushed 2026-10-21. It ships pip 26.2.1 and nothing
# else (no setuptools/wheel). The same digest is on public.ecr.aws/docker/library/python if Hub rate-limits.
FROM python:3.14.8-slim-trixie@sha256:f85c5697265c178cc6887276c55fe16cf3d14ca35c3df6a5eab3b360534a55d2

WORKDIR /app

# Set environment variables. The model is baked into the image below, so the Hub is never contacted.
ENV PYTHONUNBUFFERED=1
ENV TRANSFORMERS_VERBOSITY=info
ENV HF_HUB_OFFLINE=1
ENV TRANSFORMERS_OFFLINE=1
ENV HF_HUB_DISABLE_TELEMETRY=1

# Debian security updates from the signed trixie-security repo (retry so a transient apt mirror hiccup
# does not abort the build; same bounded-retry pattern as the Go tool images). As of 2026-10-22 this is
# ca-certificates 20250419+deb13u1 (DSA-6572-1: drops the compromised emSign ECC Root CA - G3) and
# liblzma5 5.8.1-1+deb13u2 (DSA-6549-1). No compilers or git: everything installs from wheels.
RUN for i in 1 2 3 4 5; do apt-get update && apt-get -y upgrade --no-install-recommends && apt-get clean && rm -rf /var/lib/apt/lists/* && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apt error"; sleep $((i * 5)); done \
 && dpkg --compare-versions "$(dpkg-query -W -f='${Version}' ca-certificates)" ge 20250419+deb13u1 \
 && test ! -e /etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem \
 && test ! -e /usr/share/ca-certificates/mozilla/emSign_ECC_Root_CA_-_G3.crt

# google-t5/t5-small at commit df1b051c49625cf57a3d0d8d3863ed4d13564fe4, every file sha256-verified.
# safetensors weights only (the pickle pytorch_model.bin is never fetched); the config has no custom code.
ADD --checksum=sha256:530e25060e3a8d5f7b0fcf53bfea9f3601165161f3b1914676e98d97cf07bcf1 https://huggingface.co/google-t5/t5-small/resolve/df1b051c49625cf57a3d0d8d3863ed4d13564fe4/config.json /opt/models/t5-small/config.json
ADD --checksum=sha256:f5a1c7e2be8092018d8835128987edf0111637dd98e90599cc80310fef75d95a https://huggingface.co/google-t5/t5-small/resolve/df1b051c49625cf57a3d0d8d3863ed4d13564fe4/generation_config.json /opt/models/t5-small/generation_config.json
ADD --checksum=sha256:d2acde0d8d71dd30a711834b07781b9c89feaac33fd332f60507699282740066 https://huggingface.co/google-t5/t5-small/resolve/df1b051c49625cf57a3d0d8d3863ed4d13564fe4/tokenizer.json /opt/models/t5-small/tokenizer.json
ADD --checksum=sha256:d1e7146101aa96282057f374aa9c3b260fba2109e5990edb1775d6efc70ffa3c https://huggingface.co/google-t5/t5-small/resolve/df1b051c49625cf57a3d0d8d3863ed4d13564fe4/tokenizer_config.json /opt/models/t5-small/tokenizer_config.json
ADD --checksum=sha256:d60acb128cf7b7f2536e8f38a5b18a05535c9e14c7a355904270e15b0945ea86 https://huggingface.co/google-t5/t5-small/resolve/df1b051c49625cf57a3d0d8d3863ed4d13564fe4/spiece.model /opt/models/t5-small/spiece.model
ADD --checksum=sha256:bd944e5f1b3ad9b70dd9d00010a517059e19265671076b8b0a4a58d9491842bc https://huggingface.co/google-t5/t5-small/resolve/df1b051c49625cf57a3d0d8d3863ed4d13564fe4/model.safetensors /opt/models/t5-small/model.safetensors

# Two hash-locked, wheel-only, --no-deps installs, each from exactly one index (never --extra-index-url:
# the PyTorch index mirrors PyPI names). torch is the CPU build (no multi-GB nvidia-* packages).
# pip trusts only the patched system CA bundle: --use-deprecated=legacy-certs drops pip's truststore +
# vendored-certifi context, which would otherwise still trust emSign G3. Retry so a mid-download network
# blip does not abort the build. pip is uninstalled afterwards; the runtime image has no installer.
# Last, fail on any interpreter startup hook (*.pth, sitecustomize/usercustomize: the LiteLLM 1.107.0
# payload vector) other than setuptools' stock distutils-precedence.pth, matched by sha256.
COPY requirements-torch.txt requirements.txt ./
ENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_ROOT_USER_ACTION=ignore
RUN python -m pip --version | grep -q '^pip 26\.2\.1 ' \
 && for i in 1 2 3 4 5; do python -m pip install --use-deprecated=legacy-certs --no-cache-dir --no-deps --require-hashes --only-binary=:all: --index-url https://download.pytorch.org/whl/cpu -r requirements-torch.txt && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient PyTorch index error"; sleep $((i * 5)); done \
 && for i in 1 2 3 4 5; do python -m pip install --use-deprecated=legacy-certs --no-cache-dir --no-deps --require-hashes --only-binary=:all: --index-url https://pypi.org/simple -r requirements.txt && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient PyPI error"; sleep $((i * 5)); done \
 && python -m pip check \
 && python -m pip uninstall -y pip \
 && python -c "import site,pathlib,hashlib,sys; ok={'distutils-precedence.pth': '2638ce9e2500e572a5e0de7faed6661eb569d1b696fcba07b0dd223da5f5d224'}; bad=[str(p) for d in site.getsitepackages() for p in pathlib.Path(d).iterdir() if (p.suffix=='.pth' and ok.get(p.name)!=hashlib.sha256(p.read_bytes()).hexdigest()) or p.name in ('sitecustomize.py','usercustomize.py')]; sys.exit('unexpected startup hooks: %s' % bad if bad else 0)"

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "debug"]
