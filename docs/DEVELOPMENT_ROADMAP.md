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

### Phase 13: Telecom Scenario & Mathematical Hardening (`v0.8.6`) ✅
A comprehensive 5-angle engineering audit and scenario verification remediated 9 mathematical, wire-protocol, and concurrency bottlenecks across the signaling and media planes:
*   **PQC Transport Buffer & TCP/TLS Stream Framing (`src/core/transport.rs`)**:
    *   *Why*: An `ML-DSA-65` signature (`3,309 B` raw $\rightarrow$ `6,618 B` hex) produces a `~7,131 B` SIP message, exceeding the previous `4,096 B` UDP/TCP/TLS read buffer (causing a `3,035 B` truncation on UDP and mid-header splitting on TCP/TLS).
    *   *What Changed*: Expanded UDP datagram buffers to `65,535 B` (`64 KB`) and implemented `Content-Length`-aware TCP/TLS stream framing (`extract_framed_sip_messages`, capped at `128 KB`, with `0`-length body fallback for header-only requests).
*   **Falcon-512 Registrar Wiring, Fail-Closed Mock Store & AOR Indexing (`src/modules/ims.rs`, `src/state/mod.rs`)**:
    *   *Why*: `RegistrarModule` only matched `"ML-DSA-65"` and `"MD5"`, rejecting `"Falcon-512"`; calling `ctx.state.pool()` panicked when running in `localhost` mock mode (`pool: None`); and locations were stored only under a random `Uuid::new_v4()`.
    *   *What Changed*: Added `"Falcon-512" | "FN-DSA-512"` authentication verification to `RegistrarModule`, added a fail-closed `mock_users` store (`401 Unauthorized` when unprovisioned, zero panics, no skeleton keys), parsed `Security-Client` headers via `parse_security_header`, and indexed locations by subscriber username/AOR.
*   **1x Prometheus Metrics & S-CSCF Diameter Charging Wiring (`src/core/engine.rs`)**:
    *   *Why*: Request metrics were incremented inside `for handler in &handler_set`, inflating Prometheus counters by `2x–7x` per packet, and `ScsCfModule` was instantiated without `.with_diameter(...)`.
    *   *What Changed*: Moved request metric increments outside the handler loop (`1x` per packet), wired `DiameterInterface` into `ScsCfModule` for live `Ro`/`Rf` charging, and added automatic ephemeral port fallback if UPF port `127.0.0.1:50051` is busy during parallel test execution.
*   **BGCF Numbering Plan Set-Inclusion & Emergency Hijack Fix (`src/bgcf.rs`)**:
    *   *Why*: Substring matching on `"112|911|999"` hijacked `~0.86%–2.37%` of normal 10-digit numbers containing those digits to the Emergency PSAP MGCF; `"international"` (`^\+.*$`, priority `80`) subsumed `"nanp"` (`^\+1[0-9]{10}$`, priority `70`) causing a `0%` NANP selection rate; and `"pstn"` (`^[0-9...]$ `) bypassed the regex evaluator.
    *   *What Changed*: Added `extract_dialed_target` URI normalization, enforced exact target matching (`112`, `911`, `999`, `urn:service:sos`) for emergency routing (`0%` false hijacks), raised `"nanp"` priority to `85`, and routed all `^...$` patterns through `regex::Regex`.
*   **SLF 64-Bit FNV-1a Consistent Hashing (`src/slf.rs`)**:
    *   *Why*: The bit-shift XOR hash `hash ^= (byte as usize) << ((i % 8) * 8)` left 7 of every 8 bytes with zero contribution to the lowest 8 bits (`hash % 2`), routing `100%` of consecutive 15-digit IMSI blocks to a single HSS instance.
    *   *What Changed*: Sorted available HSS instances deterministically by ID and replaced the body of `simple_hash` with 64-bit FNV-1a (`0xcbf29ce484222325` offset basis, `0x100000001b3` prime), achieving a uniform `~50% / 50%` split across consecutive IMSIs.
*   **IBCF Source-Domain Resolution & Rate-Limit Window Reset (`src/ibcf.rs`)**:
    *   *Why*: `IbcfModule::handle_request` passed the peer IP string as the domain key into `trusted_peers` (failing on domain-keyed peers), and `cleanup_rate_limits()` executed `retain(|_, count| *count > 0)`, which never reset or evicted unknown peer counters.
    *   *What Changed*: Added `resolve_source_domain` (extracting the `From` URI domain or reverse-matching peer IP), reset unknown peer counters on window expiration, bounded `call_id_mappings` to `100,000` active entries, and spawned the periodic cleanup task in `IbcfModule::init`.
*   **RFC 6733 Diameter 32-Bit AVP Padding & Carrier Rate Limits (`src/diameter.rs`, `src/integration.rs`)**:
    *   *Why*: RFC 6733 Section 4.1 requires 4-byte boundary zero-padding after every AVP payload, and `DiameterRateLimiter` defaulted to `10 req/s` (`50` burst), capping the core at `10 CPS`.
    *   *What Changed*: Added 4-byte boundary zero-padding in `Avp::encode` and safe padding consumption in `Avp::decode`, raised `DiameterRateLimiter` defaults to `2,000 req/s` (`5,000` burst), and expanded the Diameter response buffer to `16 KB`.
*   **CUPS UDP Socket Cancellation & RFC 3550 Modular Sequence Math (`src/user_plane/mod.rs`, `src/rtp_router.rs`)**:
    *   *Why*: `UserPlaneServer::delete_session` released UDP ports without cancelling the spawned `run_rtp_listener` task blocked on `socket.recv_from`, causing `EADDRINUSE` on port reuse; and out-of-order packets across sequence wraparound overwrote `last_sequence`.
    *   *What Changed*: Tracked per-session `tokio::task::AbortHandle` in `UserPlaneServer` to abort the listener and drop `UdpSocket` on session deletion, added `allocate_even_port()` for RFC 3550 even RTP ports, and implemented modular 16-bit sequence arithmetic (`wrapping_sub`).

### Phase 14: Tier-1 Carrier Production Hardening (`v0.9.0`) ✅
Implemented the four core carrier-production protocol pillars to elevate Cynan from Lab-Interop Ready (`v0.8.6`) to Carrier Production (`v0.9.0`):
*   **RFC 3261 Stateful Transaction Cache, `Max-Forwards` & On-Net Call Control (`src/core/engine.rs`, `src/core/sip_utils.rs`, `src/modules/ims.rs`)**:
    *   *Why*: UDP retransmissions (Timer A/E) previously re-entered the handler chain, triggering duplicate Diameter `Ro` credit reservations and duplicate AS iFC hooks; `Max-Forwards: 0` requests were not intercepted; and `ScsCfModule` lacked on-net registered subscriber lookup and `ACK` / `CANCEL` / `OPTIONS` handling.
    *   *What Changed*: Added RFC 3261 Section 17.2.3 transaction key caching (`branch:method:cseq:call_id`) to absorb retransmissions, enforced `Max-Forwards: 0` (`483 Too Many Hops`), added `OPTIONS` (`200 OK` with capability headers), `ACK`, and `CANCEL` handling in `ScsCfModule`, and implemented on-net subscriber `INVITE` resolution via `SharedState::get_location_by_name`.
*   **3GPP TS 33.203 Cryptographic `CK`/`IK` Derivation & Stateful `IpsecManager` XFRM Framing (`src/modules/auth.rs`, `src/modules/ipsec.rs`, `src/modules/ims.rs`, `src/integration.rs`)**:
    *   *Why*: Gm IPsec negotiation in `RegistrarModule` previously assigned placeholder zero keys (`vec![0u8; 16]`), `DiameterInterface::parse_maa_response` left `confidentiality_key` and `integrity_key` empty, and `IpsecManager` did not retain active SAs/SPs or construct binary Netlink XFRM frames.
    *   *What Changed*: Added `derive_3gpp_ipsec_keys` (`HMAC-SHA256` KDF) in `src/modules/auth.rs` to derive non-zero 128-bit `CK` and `IK` keys for `sa_in`, `sa_out`, and Diameter `MAA` auth items; upgraded `IpsecManager` with lock-free `active_sas` and `active_sps` `DashMap` registries; and implemented `build_xfrm_newsa_payload` (`nlmsghdr` + SPI + `IPPROTO_ESP` + `XFRMA_ALG_AUTH` / `XFRMA_ALG_CRYPT`).
*   **RFC 6733 Length-Prefixed Diameter TCP Framing & `CER`/`DWR` Peer Watchdog (`src/integration.rs`, `src/diameter.rs`)**:
    *   *Why*: Single `stream.read()` calls in `DiameterInterface::send_message` could read partial frames when large `ML-DSA-65`-signed Diameter messages (`~6.5 KB`) spanned multiple TCP segments, and `send_probe` was a no-op log stub.
    *   *What Changed*: Implemented 2-stage `AsyncReadExt::read_exact` framing in `DiameterInterface::send_message` (reading the 20-byte `DiameterHeader`, extracting the 24-bit `message_length`, and reading exact `message_length - 20` payload bytes), and implemented RFC 6733 `Capabilities-Exchange-Request` (`CER`, code `257` with 3GPP `Vendor-Id = 10415`) and `Device-Watchdog-Request` (`DWR`, code `280`).
*   **Write-Through HA State Persistence & Live Active-Session Telemetry (`src/state/mod.rs`, `src/modules/ims.rs`, `src/metrics.rs`)**:
    *   *Why*: `RegistrarModule` updated in-memory `DashMap` bindings without writing through to PostgreSQL (`DatabaseQueries::upsert_location`) when an active DB pool was present, and `cynan_active_sessions` remained static at `0`.
    *   *What Changed*: Added write-through `DatabaseQueries::upsert_location` persistence in `RegistrarModule`, added `sessions` and `transactions` registries in `SharedState`, and wired `increment_active_sessions()` / `decrement_active_sessions()` into `ScsCfModule` on call setup (`INVITE`) and teardown (`BYE` / `CANCEL`).

---

## 🚀 The Future: v0.9.5 & Beyond

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
