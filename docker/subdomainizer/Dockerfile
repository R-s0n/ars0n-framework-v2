FROM python:3.9

# python3-pip is deliberately not installed. This base already ships pip at /usr/local/bin/pip,
# bound to the 3.9 interpreter at /usr/local/bin/python3, and /usr/local/bin comes first on PATH -
# so that is the pip the install below has always resolved to, and the packages land in
# /usr/local/lib/python3.9/site-packages, exactly where the ENTRYPOINT's python3 looks for them.
# Debian's python3-pip would add a second, unrelated pip at /usr/bin/pip3 bound to the distro's
# python3.13, which nothing here ever invokes, and drags in dev headers for that wrong interpreter.
# What a C extension build here actually needs comes from the base instead: the 3.9 headers under
# /usr/local/include/python3.9, and gcc, which this non-slim image installs directly and the -slim
# variants do not ship at all - so keep this base non-slim.
RUN apt-get update && apt-get install -y \
    git

RUN pip install --no-cache-dir \
    termcolor \
    htmlmin \
    tldextract \
    colorama \
    cffi \
    beautifulsoup4 \
    requests \
    argparse

WORKDIR /app

RUN git clone https://github.com/nsonaniya2010/SubDomainizer.git . && \
    chmod +x SubDomainizer.py

ENTRYPOINT ["python3", "SubDomainizer.py"]