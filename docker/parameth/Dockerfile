FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/maK-/parameth.git && \
    cd parameth && \
    pip3 install requests

WORKDIR /app/parameth

ENTRYPOINT ["python3", "parameth.py"]
