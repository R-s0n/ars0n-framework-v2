# jwt_tool builds a config file on FIRST RUN and then exits without doing any work. Measured: a fresh
# container given a token and a mode prints "No config file yet created. Running config setup." and
# stops, exit code 0, no analysis. The first scan after any image rebuild would have reported nothing
# and looked clean, so the config is built here at image build time with a real token.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
    && pip install --no-cache-dir termcolor cprint pycryptodomex requests ratelimit

# The sample token from jwt_tool's own help text, used only to trigger the config setup.
RUN python /opt/jwt_tool/jwt_tool.py \
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po \
        > /dev/null 2>&1 ; test -f /root/.jwt_tool/jwtconf.ini

# The generated config points every request at a proxy on 127.0.0.1:8080, which does not exist in this
# container. Measured: any run with a target URL died with
# "[ERROR] ProxyError - check proxy is up" having sent nothing, so no forgery was ever tested and the
# scan read as clean. The framework always passes -np to disable it, and this second line means a
# hand-run inside the container behaves the same way.
RUN sed -i 's|^proxy = .*|proxy = |' /root/.jwt_tool/jwtconf.ini || true

WORKDIR /opt/jwt_tool
ENTRYPOINT ["python", "/opt/jwt_tool/jwt_tool.py"]
