FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && \
    git clone https://github.com/GerbenJavado/LinkFinder.git && \
    cd LinkFinder && \
    pip3 install -r requirements.txt && \
    chmod +x linkfinder.py

WORKDIR /app/LinkFinder

ENTRYPOINT ["python3", "linkfinder.py"]

