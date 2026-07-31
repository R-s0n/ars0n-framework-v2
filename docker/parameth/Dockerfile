FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# parameth is a Python-2-era tool (print statements, old except syntax) and needs numpy + fuzzywuzzy
# (its Dockerfile previously installed neither, and it crashed with a SyntaxError under python3).
# Install the deps, clone it, and convert the source to Python 3 with 2to3 so it runs under python3.
# (fuzzywuzzy without python-Levenshtein falls back to pure-python difflib — a warning, not an error,
#  and avoids needing a C toolchain in the slim image.)
RUN pip3 install --no-cache-dir requests numpy fuzzywuzzy

RUN git clone https://github.com/maK-/parameth.git && \
    2to3 -w -n /app/parameth

WORKDIR /app/parameth

ENTRYPOINT ["python3", "parameth.py"]
