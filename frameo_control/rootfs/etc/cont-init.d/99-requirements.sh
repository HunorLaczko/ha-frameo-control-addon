#!/bin/sh
# Install required Python packages

set -e

if [ -f "/requirements.txt" ]; then
    echo "[INFO] Installing Python packages from /requirements.txt..."
    pip install --no-cache-dir --break-system-packages -r /requirements.txt
fi

echo "[INFO] Requirements installation complete."
