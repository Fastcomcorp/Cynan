#!/bin/bash
set -e

# Fastcomcorp Cynan IMS Core
# Source Code Integrity Verification Script
# This script verifies that all source files contain the required Digital Watermark
# and generates a cryptographic manifest of the codebase.

echo "========================================================"
echo "    CYNAN SOURCE CODE INTEGRITY VERIFIER"
echo "    Fastcomcorp Secure Supply Chain"
echo "========================================================"

WATERMARK="CYNAN-FCC-2026-XQ-VERIFIED"
SEARCH_DIR="src"
FAILED=0

echo "[*] Verifying Digital Watermarks in $SEARCH_DIR..."

# Find all Rust source files
# Use process substitution to avoid subshell variable scope issues
while read -r file; do
    if ! grep -q "$WATERMARK" "$file"; then
        echo "    [FAIL] Missing Watermark: $file"
        FAILED=1
    else
        echo "    [OK]   Verified: $file"
    fi
done < <(find "$SEARCH_DIR" -name "*.rs")

# Check tests directory as well
echo "[*] Verifying Digital Watermarks in tests/..."
while read -r file; do
    if ! grep -q "$WATERMARK" "$file"; then
        echo "    [FAIL] Missing Watermark: $file"
        FAILED=1
    else
        echo "    [OK]   Verified: $file"
    fi
done < <(find "tests" -name "*.rs")


if [ $FAILED -ne 0 ]; then
    echo ""
    echo "[!] CRITICAL: Integrity Check Failed. Some files are missing the Digital Watermark."
    exit 1
fi

echo ""
echo "[*] All source files are correctly watermarked."
echo "[*] Generating Cryptographic Manifest (SHA-256)..."

# Generate checksum of all source files
find src tests -type f -name "*.rs" -print0 | sort -z | xargs -0 shasum -a 256 > CODE_MANIFEST.sha256

echo "[SUCCESS] Manifest generated at CODE_MANIFEST.sha256"
echo "========================================================"
