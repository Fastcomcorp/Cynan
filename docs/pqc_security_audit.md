# PQC Implementation Security Audit

This document summarizes the security audit of the Post-Quantum Cryptography (PQC) implementation in Cynan IMS Core.

## 1. Cryptographic Primitives
The implementation uses NIST FIPS 204 (ML-DSA) and FIPS 203 (ML-KEM) standard algorithms via the `fips204` and `fips203` crates.

### 1.1 ML-DSA-65 (Digital Signatures)
- **Primary Use**: SIP Authentication and IBCF Inter-operator signing.
- **Security Level**: NIST Level 3 (~192-bit quantum security).
- **Audit Findings**:
    - Signatures are correctly generated with empty context strings.
    - Public keys are imported with strict size validation (1952 bytes).
    - Signatures are verified with strict size validation (3309 bytes).

### 1.2 ML-KEM-768 (Key Encapsulation)
- **Primary Use**: Hybrid TLS 1.3 for gRPC communication.
- **Security Level**: NIST Level 3 (~192-bit quantum security).
- **Audit Findings**:
    - Certificates use ML-KEM-768 for hybrid key exchange.
    - Implementation leverages `rustls` with `aws-lc-rs` provider for side-channel resistant implementation.

## 2. Memory Safety & Zeroization
Sensitive data must be purged from memory when no longer needed.

### 2.1 Private Key Handling
- [x] **ML-DSA Private Keys**: `MlDsaKeyPair` implements `ZeroizeOnDrop`.
- [x] **ML-KEM Private Keys**: `MlKemKeyPair` implements `ZeroizeOnDrop`.
- [x] **Topology Hiding Keys**: `TopologyHidingRule` in `ibcf.rs` implements `ZeroizeOnDrop` for pseudonym keys.

### 2.2 Shared Secret Handling
- [x] **ML-KEM Shared Secrets**: Uses `ZeroizeOnDrop` via the underlying crates' key handling.

## 3. Side-Channel Resilience
- **Implementation**: The underlying crates (`fips203`, `fips204`, `aws-lc-rs`) are designed to be constant-time for secret-dependent operations.
- **Audit Findings**: High-level logic in Cynan does not introduce branching based on PQC secret data (other than validity checks which are post-computation).

## 4. Protocol-Level Security
### 4.1 Hybrid Security
- Both SIP and gRPC use hybrid modes (Classical + PQC), ensuring security remains at least at the level of classical ECDSA/ECDHE even if a weakness is found in ML-DSA/ML-KEM.

### 4.2 Forward Secrecy
- ML-KEM provides quantum-safe forward secrecy for TLS sessions.

## 5. Network Edge Security (IBCF)
Validated protection against external threats from SBC/Peers:

- [x] **IP Allowlisting**: `IbcfModule` strictly rejects requests from untrusted IPs (Default Deny).
- [x] **PQC Enforcement**: When `require_pqc: true` is set, requests without valid ML-DSA-65 signatures are rejected (428 Precondition Required).
- [x] **DoS Protection**: 
    - Trusted peers are rate-limited per configuration.
    - Unknown peers are subject to strict throttling (10 req/s) or immediate rejection.

## 6. Status
- All identified memory handling issues from Phase 1-11 have been addressed.
- Falcon-512 integration has been verified for both performance and signature validation correctness.
