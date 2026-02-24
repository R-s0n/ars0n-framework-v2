FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN git clone https://github.com/R-s0n/cloud_enum.git . && \
    pip install -r requirements.txt

COPY docker/shuffledns/wordlists/resolvers.txt /app/resolvers.txt
COPY docker/cloud_enum/rs0nfuzz.txt /app/rs0nfuzz.txt

ENTRYPOINT ["python", "cloud_enum.py"] 