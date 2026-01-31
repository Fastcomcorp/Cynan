# PQC Migration Guide

This guide outlines the steps required to migrate an existing Cynan IMS Core deployment from classical cryptography to Post-Quantum Cryptography (PQC).

## 1. Prerequisites
- Cynan IMS Core v0.8.0+
- PostgreSQL 15+ (for PQC key storage)
- OpenSSL 3.0+ (standard requirement)
- Modern hardware with AVX2 or NEON support (recommended for performance)

## 2. Step-by-Step Migration

### Step 1: Database Schema Upgrade
Apply the PQC key storage migration to the HSS database:
```bash
psql cynan_hss < migrations/002_add_pqc_keys.sql
```

### Step 2: Key Generation
Generate a standard PQC keypair for the server node:
```bash
./cynan --generate-pqc-keys --output-dir /etc/cynan/pqc-keys/
```
Ensure the private key is readable only by the `cynan` user (`chmod 600`).

### Step 3: Enable Hybrid Mode
Update `cynan.yaml` to enable `hybrid` mode. This is the **strongly recommended** first step to maintain compatibility with classical clients.

```yaml
security:
  pqc:
    mode: hybrid
    kem_level: 768
    dsa_level: 65
    keypair_path: /etc/cynan/pqc-keys/
```

### Step 4: Certificate Update
Generate or obtain hybrid certificates for SIP and gRPC. The certificates should contain:
- Classical RSA/EC public key
- ML-KEM-768/ML-DSA-65 public key (via OID extension)

### Step 5: Service Restart
Restart all Cynan components (S-CSCF, I-CSCF, IBCF, Armoricore Bridge).

## 3. Verification
Check logs for the following indicators:
- `[INFO] PQC mode: hybrid enabled`
- `[INFO] Loaded ML-DSA-65 keypair from /etc/cynan/pqc-keys/`
- `[INFO] rustls configured with hybrid ML-KEM-768 key exchange`

## 4. Full PQC Mode (Optional)
Once all clients and peers have been upgraded, switch to `pqc-only` mode:
```yaml
security:
  pqc:
    mode: pqc-only
```
**Warning**: This will reject all classical-only connections and is only recommended for high-security environments where the entire infrastructure is quantum-resistant.
