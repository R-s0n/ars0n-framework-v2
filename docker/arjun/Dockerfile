FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/s0md3v/Arjun.git && \
    cd Arjun && \
    pip3 install .

WORKDIR /app

ENTRYPOINT ["arjun"]
