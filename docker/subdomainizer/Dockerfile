FROM python:3.9

# python3-pip is deliberately not installed. This base already ships pip at /usr/local/bin/pip,
# bound to the 3.9 interpreter at /usr/local/bin/python3, and /usr/local/bin comes first on PATH -
# so that is the pip the install below resolves to, and the packages land in
# /usr/local/lib/python3.9/site-packages, exactly where the ENTRYPOINT's python3 looks for them.
# Debian's python3-pip would add a second, unrelated pip at /usr/bin/pip3 bound to the distro's
# python3.13, which nothing here ever invokes.
RUN apt-get update && apt-get install -y \
    git

# SubDomainizer's actual runtime dependencies, matching its upstream requirements.txt. The previous
# list also carried htmlmin, cffi and argparse; all three are gone now, deliberately:
#   - argparse is in the standard library, so the PyPI backport is pointless on 3.9;
#   - cffi was never imported by SubDomainizer and pulled a C toolchain in for nothing;
#   - htmlmin is the one that broke this build. It is not a dependency anymore (dropped from
#     upstream requirements.txt and not imported), and it is also uninstallable: htmlmin 0.1.12 ships
#     only an sdist whose setup.py uses use_2to3, which setuptools removed in v58 (2021), so this
#     base image's modern setuptools cannot build its metadata and pip reports
#     "No matching distribution found for htmlmin (from versions: none)".
RUN pip install --no-cache-dir \
    termcolor \
    beautifulsoup4 \
    requests \
    tldextract \
    colorama

WORKDIR /app

RUN git clone https://github.com/nsonaniya2010/SubDomainizer.git . && \
    chmod +x SubDomainizer.py

ENTRYPOINT ["python3", "SubDomainizer.py"]