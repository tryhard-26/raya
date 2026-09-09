#!/usr/bin/env bash
set -euo pipefail

# Raya Isolated Malware Scan Harness
# Builds a sandboxed Docker container and scans samples with NO network access (--network none).

IMAGE_NAME="raya-sandbox"
SAMPLES_DIR="${1:-samples/malware}"

if [ ! -d "$SAMPLES_DIR" ]; then
    echo "[-] Directory not found: $SAMPLES_DIR"
    echo "Usage: $0 [path/to/samples_dir]"
    exit 1
fi

echo "[+] Building isolated Raya sandbox image..."
docker build -t "$IMAGE_NAME" -f Dockerfile.sandbox .

echo "[+] Running static analysis inside sandboxed container with network isolation..."
docker run --rm \
    --network none \
    --read-only \
    -v "$(pwd)/$SAMPLES_DIR:/samples:ro" \
    "$IMAGE_NAME" scan /samples --rules /analyzer/rules --recursive
