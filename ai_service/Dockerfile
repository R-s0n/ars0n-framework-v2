FROM python:3.10-slim

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV TRANSFORMERS_VERBOSITY=info
ENV TRANSFORMERS_OFFLINE=0

# Install system dependencies (retry so a transient apt mirror hiccup does not abort the build;
# same bounded-retry pattern as the Go tool images).
RUN for i in 1 2 3 4 5; do apt-get update && apt-get install -y build-essential git && apt-get clean && rm -rf /var/lib/apt/lists/* && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient apt error"; sleep $((i * 5)); done

COPY requirements.txt .
# pip install of torch/transformers is a large download; retry so a mid-download network blip does
# not waste the whole layer and abort the build.
RUN for i in 1 2 3 4 5; do pip install --no-cache-dir -r requirements.txt && break; [ "$i" = 5 ] && exit 1; echo "retry $i: transient PyPI error"; sleep $((i * 5)); done

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "debug"]
