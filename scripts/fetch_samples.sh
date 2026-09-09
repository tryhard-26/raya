#!/usr/bin/env bash
set -euo pipefail

# Raya Malware Sample Retrieval Script
# WARNING: Only execute this script inside an isolated, non-networked malware analysis VM.
# Real malware samples must NEVER be executed on your host machine.

MANIFEST="samples/manifest.json"
OUTPUT_DIR="samples/malware"
API_URL="https://mb-api.abuse.ch/api/v1/"
API_KEY="${MALWAREBAZAAR_API_KEY:-}"

if [ ! -f "$MANIFEST" ]; then
    echo "[-] Manifest not found: $MANIFEST"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[+] Reading sample manifest: $MANIFEST"
COUNT=$(grep -c '"sha256"' "$MANIFEST" || true)
echo "[+] Found $COUNT samples documented in manifest."

if [ -z "$API_KEY" ]; then
    echo "[!] Note: MalwareBazaar requires an Auth-Key header for sample retrieval."
    echo "[!] To download directly, set: export MALWAREBAZAAR_API_KEY=\"<your_abuse_ch_api_key>\""
fi

cat "$MANIFEST" | grep '"sha256"' | cut -d '"' -f 4 | while read -r HASH; do
    OUT_ZIP="$OUTPUT_DIR/${HASH}.zip"
    if [ -f "$OUT_ZIP" ]; then
        echo "[*] Sample $HASH already cached: $OUT_ZIP"
    elif [ -n "$API_KEY" ]; then
        echo "[+] Fetching $HASH from MalwareBazaar..."
        curl -s -f -X POST \
            -H "Auth-Key: ${API_KEY}" \
            -d "query=get_file&sha256_hash=${HASH}" \
            "$API_URL" -o "$OUT_ZIP" || {
                echo "[-] Failed to fetch $HASH"
                rm -f "$OUT_ZIP"
            }
    else
        echo "[*] Manual download command for $HASH:"
        echo "    curl -s -X POST -H \"Auth-Key: \$MALWAREBAZAAR_API_KEY\" -d \"query=get_file&sha256_hash=${HASH}\" \"$API_URL\" -o \"$OUT_ZIP\""
    fi
done

echo "[+] Manifest processing complete. Samples should remain in encrypted/protected storage (password: 'infected')."

