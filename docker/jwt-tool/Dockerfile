# jwt_tool builds a config file on FIRST RUN and then exits without doing any work. Measured: a fresh
# container given a token and a mode prints "No config file yet created. Running config setup." and
# stops, exit code 0, no analysis. The first scan after any image rebuild would have reported nothing
# and looked clean, so the config is built here at image build time with a real token.
#
# Pinned throughout: base by digest, jwt_tool v2.3.0 by commit, dependencies by hash in
# requirements.txt (termcolor, pycryptodomex, requests, ratelimit; cprint was never imported).
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

# ratelimit only ships an sdist, so it is built with the base image's setuptools rather than letting
# pip fetch an unpinned build backend. setuptools, wheel and packaging are then removed.
COPY pip-bootstrap.txt requirements.txt /opt/pylock/
RUN python -m pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /opt/pylock/pip-bootstrap.txt \
    && pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: \
        --no-binary=ratelimit --no-build-isolation -r /opt/pylock/requirements.txt \
    && pip uninstall -y setuptools wheel packaging

RUN sha=3bc7407cf2222d6a821dcc19c776e5a1b1cb9a9b \
    && git init -q /opt/jwt_tool \
    && git -C /opt/jwt_tool fetch -q --depth 1 https://github.com/ticarpi/jwt_tool.git "$sha" \
    && git -C /opt/jwt_tool checkout -q --detach FETCH_HEAD \
    && test "$(git -C /opt/jwt_tool rev-parse HEAD)" = "$sha" \
    && rm -rf /opt/jwt_tool/.git

# The sample token from jwt_tool's own help text, used only to trigger the config setup.
RUN python /opt/jwt_tool/jwt_tool.py \
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po \
        > /dev/null 2>&1 ; test -f /root/.jwt_tool/jwtconf.ini

# The generated config points every request at a proxy on 127.0.0.1:8080, which does not exist in this
# container. Measured: any run with a target URL died with
# "[ERROR] ProxyError - check proxy is up" having sent nothing, so no forgery was ever tested and the
# scan read as clean. The framework always passes -np to disable it, which sets the value to the
# string False; this line writes that same value into the config, so a hand-run inside the container
# behaves the same way. (An empty value is not a disable: jwt_tool then builds the proxy URL "http://"
# and requests rejects it.) The greps fail the build if the generated config changed shape and the
# patch did not apply.
RUN sed -i 's|^proxy = .*|proxy = False|' /root/.jwt_tool/jwtconf.ini \
    && grep -qx 'proxy = False' /root/.jwt_tool/jwtconf.ini \
    && ! grep -q '127.0.0.1:8080' /root/.jwt_tool/jwtconf.ini

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

WORKDIR /opt/jwt_tool
ENTRYPOINT ["python", "/opt/jwt_tool/jwt_tool.py"]
