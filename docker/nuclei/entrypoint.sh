#!/bin/bash

# Enable debug output
set -x

echo "[DEBUG] System information:"
uname -a
cat /etc/os-release

echo "[DEBUG] Checking Chrome installation..."
which google-chrome
google-chrome --version

echo "[DEBUG] Checking nuclei installation..."
which nuclei
nuclei -version

echo "[DEBUG] Checking directories and permissions..."
ls -la /tmp/nuclei-mounts
ls -la /app

echo "[DEBUG] Processing URLs file..."
if [ -f /urls.txt ]; then
    echo "[DEBUG] URLs file contents:"
    cat /urls.txt
    
    echo "[DEBUG] Running nuclei scan..."
    exec nuclei "$@"
else
    echo "[ERROR] No URLs file found at /urls.txt"
    exit 1
fi 