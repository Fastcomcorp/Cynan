# PQC Performance Analysis: Falcon-512 vs ML-DSA-65

## Executive Summary
This document analyzes the performance characteristics of Post-Quantum Cryptography (PQC) algorithms integrated into the Cynan IMS Core. Specifically, we benchmarked **Falcon-512** (FN-DSA) against **ML-DSA-65** (Dilithium) and the classical **Ed25519** baseline.

**Key Findings:**
*   **Verification Speed:** Falcon-512 is the fastest algorithm for signature verification, outperforming ML-DSA-65 by **~9x** and even classical Ed25519 by **~3x**.
*   **Signing Speed:** Falcon-512 signing is **~3x** faster than ML-DSA-65.
*   **Key Generation:** Falcon-512 is significantly slower (~13x) than ML-DSA-65 for key generation, but this is an acceptable trade-off for long-lived identity keys.
*   **Recommendation:** Falcon-512 is the superior choice for SIP authentication in high-throughput IMS environments due to its extremely low verification overhead.

## Benchmark Results

All benchmarks were run on the same hardware environment. Times are averaged over 100 iterations.

| Operation | Algorithm | Time (mean) | Rel. Performance |
| :--- | :--- | :--- | :--- |
| **Signature Verification** | **Falcon-512** | **22.3 µs** | **1.0x (Baseline)** |
| | Ed25519 (Classical) | 62.8 µs | 2.8x slower |
| | ML-DSA-65 | 204.1 µs | 9.1x slower |
| | | | |
| **Signing** | **Falcon-512** | **292.0 µs** | **1.0x (Baseline)** |
| | ML-DSA-65 | 882.6 µs | 3.0x slower |
| | Ed25519 (Classical) | 16.3 µs | 18x faster |
| | | | |
| **Key Generation** | ML-DSA-65 | 295.8 µs | 1.0x (Baseline) |
| | **Falcon-512** | **3,836.1 µs** | **13x slower** |

## Detailed Analysis

### 1. Signature Verification (Critical Path)
Verification is the most critical operation for an IMS Core functionality (P-CSCF/S-CSCF), as it must verify signatures on every SIP `REGISTER` and authenticated request from UEs.

*   **Falcon-512 (22 µs)**: Exceptionally fast. This enables the IMS Core to handle extremely high Calls Per Second (CPS) without becoming CPU-bound by cryptography. It allows for "Quantum-Safe" security with *better* performance than current classical elliptic curves (Ed25519).
*   **ML-DSA-65 (204 µs)**: While secure, the overhead is noticeable. At 10,000 CPS, ML-DSA verification would consume ~2 full CPU cores just for crypto, whereas Falcon would consume ~0.2 cores.

### 2. Signing (UE/Server Load)
Signing occurs on the User Equipment (UE) during registration and on the server during mutual authentication.

*   **Falcon-512 (292 µs)**: Fast enough for mobile devices and servers. The lower latency vs ML-DSA benefits call setup times.
*   **ML-DSA-65 (883 µs)**: Still performant, but higher latency.

### 3. Key Generation (Registration)
Key generation happens infrequently—typically once when a subscriber provisions or re-registers after a long expiry.

*   **Falcon-512 (~3.8 ms)**: Slower due to the complexity of Gaussian sampling over lattices. However, 4ms is imperceptible to a user during a registration flow that takes hundreds of milliseconds (network latency, database lookups). The trade-off is well worth the verification speedup.

## Architecture Recommendations

Based on these results, we strongly recommend **Falcon-512 (FN-DSA)** as the default algorithm for SIP Authentication in the Cynan IMS Core.

**Configuration Strategy:**
1.  **Default:** Use `Falcon-512` for all new SIP registrations.
2.  **Fallback:** Support `ML-DSA-65` for devices that do not yet implement Falcon.
3.  **Hybrid:** Continue supporting Ed25519/RSA for legacy endpoints during migration.
