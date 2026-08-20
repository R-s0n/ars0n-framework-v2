# Upload_Bypass works from a SAVED RAW REQUEST: it needs a real, working file upload to mutate,
# because the whole technique is changing one thing at a time about a request the application already
# accepts. That is why the operator marks which requests are uploads rather than the framework
# guessing.
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 https://github.com/sAjibuu/Upload_Bypass.git /opt/upload_bypass \
    && pip install --no-cache-dir -r /opt/upload_bypass/requirements.txt 2>/dev/null || \
       pip install --no-cache-dir requests termcolor

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

WORKDIR /opt/upload_bypass
ENTRYPOINT ["python", "/opt/upload_bypass/upload_bypass.py"]
