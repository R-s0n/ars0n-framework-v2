FROM python:3.11-slim

# chromium and chromium-driver are only needed for xssFuzz's -V (validate) mode, which loads a
# candidate URL in a real browser and reports whether an alert actually fired. Without validation
# xssFuzz reports "this parameter reflects a dangerous character", which is a lead rather than a
# finding, so the browser is what makes its output worth storing.
#
# validate.py hardcodes options.binary_location = "/usr/bin/chromium" on Linux, so the distro
# package is the one that must be installed. A chromium at any other path is not discovered and the
# failure surfaces as a selenium session error mid-scan rather than at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates chromium chromium-driver \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN git clone --depth 1 https://github.com/Asperis-Security/xssFuzz.git . \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir requests \
    && python /app/xssFuzz.py --help > /dev/null
# requests is installed separately because xssFuzz's requirements.txt lists only colorama and
# selenium while xssFuzz.py imports requests on line 4. Installing requirements.txt alone builds a
# container that dies with ModuleNotFoundError on every invocation, including --help. The --help
# call is here so that failure surfaces at build time rather than on the operator's first scan.

# xssFuzz opens src/tags.txt, src/events.txt and src/payloads.txt by RELATIVE path, so it only works
# when the process runs from the repository root. Running it from anywhere else fails on a missing
# wordlist partway through instead of at startup.
WORKDIR /app
ENTRYPOINT ["python", "/app/xssFuzz.py"]
