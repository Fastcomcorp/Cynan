# 🛡️ Supply Chain Integrity Manifest

This document outlines the cryptographic verification process for the Cynan IMS Core.

## 🛡️ Automated Verification System

As of **v0.8.5**, supply chain integrity is enforced automatically via the `scripts/verify_integrity.sh` utility. This system performs two critical checks:

1.  **Digital Watermark Verification**: Scans all source code for the proprietary `CYNAN-FCC-2026-XQ-VERIFIED` header.
2.  **Manifest Generation**: Generates a machine-readable SHA-256 checksum manifest.

## 📄 The Code Manifest (`CODE_MANIFEST.sha256`)

The authoritative source of truth for file integrity is the **`CODE_MANIFEST.sha256`** file located in the project root. This file is generated dynamically and contains the current cryptographic signatures of all authorized source files.

### How to Verify Integrity

To verify the codebase against the manifest, run:

```bash
# verify that current files match the manifest
shasum -a 256 -c CODE_MANIFEST.sha256
```

To regenerate the manifest (e.g. before a release):

```bash
./scripts/verify_integrity.sh
```
