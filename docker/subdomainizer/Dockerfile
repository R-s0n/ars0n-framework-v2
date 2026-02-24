FROM python:3.9

RUN apt-get update && apt-get install -y \
    git \
    python3-pip

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