# PQC Troubleshooting Guide

Common issues and solutions when deploying and operating PQC in Cynan IMS Core.

## 1. Authentication Failures

### Symptom: `401 Unauthorized` repeatedly for PQC-capable clients
- **Cause**: Time drift between client and server (ML-DSA signatures are sensitive to nonce freshness).
- **Solution**: Synchronize clocks via NTP.
- **Cause**: Public key mismatch in HSS.
- **Solution**: Verify the `ml_dsa_public_key` in the `users` table matches the client's public key.

### Symptom: `Invalid PQC signature in HSS response`
- **Cause**: Diameter header RFC compliance issues in some versions of Cynan.
- **Solution**: Ensure you are running v0.8.0+ which includes the fix for `DiameterHeader` serialization.

## 2. Handshake Errors

### Symptom: `rustls: peer unsupported curve`
- **Cause**: Client does not support ML-KEM-768 hybrid curve.
- **Solution**: Ensure client is using a PQC-compatible library (e.g., rustls 0.26+ with aws-lc-rs). Check if `security.pqc.mode` is set to `pqc-only` while the client is classical.

### Symptom: `Certificate validation failed: unknown algorithm`
- **Cause**: System trust store does not recognize ML-DSA-signed certificates.
- **Solution**: Install the PQC Root CA into the system/application trust store.

## 3. Performance Issues

### Symptom: High CPU usage on S-CSCF
- **Cause**: Frequent ML-DSA signing operations.
- **Solution**: Increase nonce expiration time to reduce re-authentication frequency. Evaluate upgrading to **Falcon-512** (Phase 10 optimization).

### Symptom: Increased latency in IBCF routing
- **Cause**: Topology hiding pseudonymization overhead.
- **Solution**: Ensure `pseudonym_key` is configured and is exactly 32 bytes to avoid unnecessary HKDF re-computations.

## 4. Database Errors

### Symptom: `column "ml_dsa_public_key" does not exist`
- **Cause**: Schema migration 002 was not applied.
- **Solution**: Run `psql cynan_hss < migrations/002_add_pqc_keys.sql`.
