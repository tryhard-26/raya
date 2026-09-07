#!/usr/bin/env bash
set -euo pipefail

# Raya Malware Sample Retrieval Script
# WARNING: Only execute this script inside an isolated, non-networked malware analysis VM.
# Real malware samples must NEVER be executed on your host machine.

MANIFEST="samples/manifest.json"
OUTPUT_DIR="samples/malware"
API_URL="https://mb-api.abuse.ch/api/v1/"

if [ ! -f "$MANIFEST" ]; then
    echo "[-] Manifest not found: $MANIFEST"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Reading sample manifest: $MANIFEST"
COUNT=$(grep -c '"sha256"' "$MANIFEST" || true)
echo "[+] Found $COUNT samples documented in manifest."

cat "$MANIFEST" | grep '"sha256"' | cut -d '"' -f 4 | while read -r HASH; do
    OUT_ZIP="$OUTPUT_DIR/${HASH}.zip"
    if [ -f "$OUT_ZIP" ]; then
        echo "[*] Sample $HASH already downloaded."
    else
        echo "[*] To retrieve $HASH from MalwareBazaar:"
        echo "    curl -s -X POST -d \"query=get_file&sha256_hash=${HASH}\" \"$API_URL\" -o \"$OUT_ZIP\""
    fi
done

echo "[+] Manifest verification complete. Samples should remain in encrypted/protected storage."
