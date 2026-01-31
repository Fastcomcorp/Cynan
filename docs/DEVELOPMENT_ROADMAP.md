# Cynan IMS Core - Development Roadmap & Phases

This document outlines the evolutionary journey of the **Cynan IMS Core**, from initial prototyping to its current security-hardened, quantum-ready state.

---

## 🗺️ Development Journey

Cynan was built using a systematic, phased approach to manage the complexity of IMS signaling and the integration of Post-Quantum Cryptography (PQC).

### Phase 1–6: Foundational Core (MVP)
*   **Signaling Engine**: Implementation of the primary SIP asynchronous listener (UDP/TCP) using **Tokio**.
*   **Functional Modules**: First-generation implementation of the **P-CSCF**, **I-CSCF**, and **S-CSCF**.
*   **State Management**: In-memory user location caching via `DashMap`.
*   **IMS Registry**: Traits-based module registry for modular orchestration.

### Phase 7: Control Plane Activation
*   **Armoricore Bridge**: First implementation of the gRPC interface for media engine control.
*   **PQC Primitives**: Selection of **ML-KEM-768** and **ML-DSA-65** as core cryptographic targets.

### Phase 8: Hardening & Verification
*   **Integration Suite**: Creation of the automated gRPC and SIP integration testing framework.
*   **Module Orchestration**: Refining the request/response handling logic for multi-hop IMS flows.

### Phase 9: External Interfaces
*   **Diameter Integration**: Development of the type-safe **Cx, Sh, and Rx** interfaces (3GPP TS 29.228/29.328).
*   **HSS Connectivity**: Implementation of the asynchronous Diameter protocol client for user profile retrieval and authorization.

### Phase 10: Performance Optimization
*   **Falcon-512 Integration**: Adoption of the **Falcon-512** signature algorithm (FIPS 205 derivative) for high-performance SIP authentication (reducing PQC signature overhead).
*   **Zero-Unsafe Initiative**: Total removal of `unsafe` blocks from the signaling core.

### Phase 11: Security Remediation (Red Team Audit) ✅
*   **Skeleton Key Removal**: Eliminated hardcoded authentication fallbacks in `ims.rs`.
*   **Signaling DoS Protection**: Parallelized SIP request handling with `tokio::spawn` for every incoming listener event.
*   **Quantum Downgrade Defense**: Implemented strict PQC enforcement logic in `auth.rs`.
*   **Predictable SPI Hardening**: IPsec SPI generation upgraded to high-entropy CSPRNG.

### Phase 12: Network Edge Security
*   **IPsec XFRM Implementation**: Native Linux kernel integration for the **Gm interface** (User Equipment security).
*   **IBCF (Border Control)**: Implementation of topology hiding and PQC-enabled inter-operator peering.

---

## 🚀 The Future: v0.9.0 & Beyond

| Milestone | Target | Description |
| :--- | :--- | :--- |
| **Media Plane (Full)** | v0.8.5 | RTCP/RTP bridging implementation to complete the Armoricore Media Engine handoff. |
| **Performance Scaling** | v0.9.0 | Reaching 20,000+ CPS (Calls Per Second) via lock-free state optimizations. |
| **Cloud-Native HA** | v0.9.5 | Multi-node state synchronization for carrier-grade High Availability. |
| **PQC-mTLS Radius** | v1.0.0 | Full PQC-hardened AAA integration for legacy network support. |

---

## 📝 Key Architectural Notes

*   **Memory Safety First**: Every phase adhered to the "Simplicity through Rust" principle, ensuring that complexity never leads to memory vulnerabilities.
*   **People-Centered Security**: Our phases were prioritized to protect terminal user identities first, ensuring metadata privacy (Topology Hiding) and authentication integrity (PQC).
*   **Carrier Compliance**: Phasing followed 3GPP Release 16/17 timelines to ensure compatibility with modern 4G/5G deployments.

---

> [!NOTE]  
> This roadmap is updated at the conclusion of each architectural phase. Last Update: **January 2026** (Completion of Red Team Remediation).
