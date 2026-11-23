# Changelog — Cynan IMS Core

All notable architectural, mathematical, and protocol-compliance changes to the **Cynan Post-Quantum Secure IMS Core** are documented in this file.

---

## [v0.9.0] - 2026-11-22 — Phase 14: Tier-1 Carrier Production Hardening

### Executive Summary
Version `0.9.0` delivers the four carrier-grade protocol pillars on top of the `v0.8.6` mathematical remediation: **(1) RFC 3261 Stateful SIP Transaction Deduplication, `Max-Forwards` Loop Protection & On-Net Call Control**, **(2) 3GPP TS 33.203 Cryptographic `CK`/`IK` Derivation & Stateful `IpsecManager` XFRM Framing**, **(3) RFC 6733 24-Bit Length-Prefixed Diameter TCP Framing & `CER`/`DWR` Peer Watchdog**, and **(4) Write-Through PostgreSQL HA Location Persistence & Live Active-Session Telemetry**.

---

### 1. RFC 3261 Stateful SIP Transaction & Call Control Layer (`src/core/engine.rs`, `src/core/sip_utils.rs`, `src/modules/ims.rs`)
- **UDP Retransmission Absorption (`compute_transaction_key` & `transactions` Cache)**:
  - *Why*: Under RFC 3261 Section 17.2, UEs retransmit UDP requests (`REGISTER`, `INVITE`, `BYE`) when network RTT exceeds Timer A/E ($500\text{ ms}$). Without server transaction caching, each retransmission re-triggered Diameter `Cx`/`Ro`/`Rf` requests and AS iFC webhooks.
  - *What Changed*: Computed deterministic transaction keys (`branch:method:cseq:call_id`) from the top `Via` `branch=` parameter and cached serialized final responses in `SharedState::transactions` (bounded at `50,000` active entries). Retransmitted requests are answered immediately from cache prior to metric increments or handler execution.
- **`Max-Forwards: 0` Loop Detection (`check_max_forwards_zero` & `create_483_too_many_hops`)**:
  - *Why*: RFC 3261 Section 16.3 requires proxies/CSCFs to reject requests with `Max-Forwards: 0` using `483 Too Many Hops` to prevent signaling loops.
  - *What Changed*: Added pre-pipeline `Max-Forwards: 0` enforcement in `SipCore::run`.
- **Complete S-CSCF Method & On-Net Session Control (`ScsCfModule::handle_request`)**:
  - *Why*: `ScsCfModule` previously only logged `INVITE` and returned `200 OK` on `BYE`, ignoring `ACK`, `CANCEL`, `OPTIONS`, and locally registered on-net call targets.
  - *What Changed*: Added on-net target resolution via `ctx.state.get_location_by_name(target_user)` on `INVITE` (returning `200 OK` with the callee's registered `Contact` binding), added `SessionState` lifecycle tracking (`Initiated` $\rightarrow$ `Established` on `ACK` $\rightarrow$ `Terminated` on `BYE`/`CANCEL`), and added `200 OK` capability responses (`Allow` / `Supported`) for `OPTIONS`.

### 2. 3GPP TS 33.203 Key Derivation & Stateful Linux XFRM Netlink Framing (`src/modules/auth.rs`, `src/modules/ipsec.rs`, `src/modules/ims.rs`, `src/integration.rs`)
- **HMAC-SHA256 `CK`/`IK` Key Derivation (`derive_3gpp_ipsec_keys`)**:
  - *Why*: `RegistrarModule` previously assigned placeholder zero keys (`vec![0u8; 16]`) to Gm IPsec Security Associations (`sa_in`, `sa_out`), and `DiameterInterface::parse_maa_response` left `confidentiality_key` and `integrity_key` empty.
  - *What Changed*: Implemented `derive_3gpp_ipsec_keys(seed_material, spi_c, spi_s)` using `ring::hmac::HMAC_SHA256` to derive distinct 128-bit `CK` (`encryption_key`, `aes-cbc`) and 128-bit `IK` (`integrity_key`, `hmac-sha-1-96`) keys for both `RegistrarModule` Gm SAs and Diameter `MAA` `SipAuthDataItem` vectors.
- **Stateful `IpsecManager` Registry & Binary XFRM Netlink Payload (`build_xfrm_newsa_payload`)**:
  - *Why*: `IpsecManager` did not store active SAs/SPs in memory or construct binary Netlink `XFRM_MSG_NEWSA` frames.
  - *What Changed*: Added thread-safe `active_sas: Arc<DashMap<u32, SecurityAssociation>>` and `active_sps: Arc<DashMap<String, SecurityPolicy>>` registries (`get_sa`, `active_sa_count`, `delete_sa`) and implemented `build_xfrm_newsa_payload` (`16-byte nlmsghdr` + network-order SPI + `IPPROTO_ESP` + `AF_INET`/`AF_INET6` selectors + `XFRMA_ALG_AUTH` / `XFRMA_ALG_CRYPT` key attributes).

### 3. RFC 6733 Length-Prefixed Diameter TCP Framing & `CER`/`DWR` Watchdog (`src/integration.rs`, `src/diameter.rs`)
- **2-Stage Exact Length-Prefixed TCP Read (`AsyncReadExt::read_exact`)**:
  - *Why*: A single `stream.read()` call can return a partial buffer when `ML-DSA-65`-signed Diameter messages (`~6.5 KB`) fragment across multiple TCP segments.
  - *What Changed*: Updated `DiameterInterface::send_message` to read the 20-byte `DiameterHeader` via `read_exact`, parse the 24-bit big-endian `message_length` (`20..=65535`), and call `read_exact` for the remaining `message_length - 20` payload bytes.
- **RFC 6733 `Capabilities-Exchange-Request` (`CER`) & `Device-Watchdog-Request` (`DWR`)**:
  - *Why*: `DiameterInterface::send_probe` was previously a no-op log stub.
  - *What Changed*: Added `HOST_IP_ADDRESS (257)`, `VENDOR_ID (266)`, and `PRODUCT_NAME (269)` AVP codes to `src/diameter.rs`, implemented `build_cer_message()` (Command Code `257`, 3GPP `Vendor-Id = 10415`) and `build_dwr_message()` (Command Code `280`), and wired `send_probe` to transmit the probe over active peer connections.

### 4. Distributed HA Write-Through Persistence & Active-Session Telemetry (`src/state/mod.rs`, `src/modules/ims.rs`, `src/metrics.rs`)
- **Write-Through PostgreSQL Location Persistence**:
  - *Why*: `RegistrarModule` stored locations in `SharedState` without writing through to PostgreSQL when an active DB pool was configured.
  - *What Changed*: Wired `DatabaseQueries::upsert_location(ctx.state.pool(), &user_id, &contact_uri, 3600).await` into `RegistrarModule::handle_request` whenever `ctx.state.has_active_pool()` is `true`.
- **Live `cynan_active_sessions` Prometheus Gauge**:
  - *What Changed*: Added `increment_active_sessions()` and saturating `decrement_active_sessions()` to `Metrics` in `src/metrics.rs`, invoked automatically by `ScsCfModule` on call initiation (`INVITE`) and termination (`BYE` / `CANCEL`).

---

## [v0.8.6] - 2026-11-22 — Phase 13: Telecom Scenario & Mathematical Hardening

### Executive Summary
Version `0.8.6` resolves **9 telecom signaling, mathematical, wire-protocol, and concurrency gaps** identified during quantitative scenario modeling and a 5-angle regression audit across the SIP, Diameter, PQC, BGCF/MGCF/IBCF/SLF, and CUPS subsystems.

---

### 1. Transport Layer (`src/core/transport.rs`)
- **64 KB UDP Datagram Buffer (`MAX_UDP_SIP_PACKET_SIZE = 65535`)**:
  - *Root Cause & Math*: An `ML-DSA-65` signature is $3,309\text{ B}$ raw ($6,618\text{ B}$ hex-encoded in the SIP `Authorization` or `X-Cynan-PQC-Sig` header). Combined with base SIP headers ($\sim 513\text{ B}$), a single PQC-authenticated SIP message is $\sim 7,131\text{ B}$. The previous `4,096 B` UDP buffer truncated the final $3,035\text{ B}$ of every `ML-DSA-65` datagram, resulting in a 100% parse failure.
  - *Resolution*: Increased UDP receive buffer to `65,535 B`.
- **TCP/TLS `Content-Length` Stream Framing (`extract_framed_sip_messages`)**:
  - *Root Cause*: TCP and TLS readers emitted raw `read()` chunks (`\le 4,096 B`) directly as `TransportMessage`s without message boundary framing, splitting `7,131 B` PQC messages across two incomplete buffers.
  - *Resolution*: Added a per-connection stream accumulator (capped at `128 KB` for DoS protection) that frames complete SIP messages using the `\r\n\r\n` header terminator and `Content-Length` (defaulting to `0` when omitted so header-only test messages never block).

### 2. PQC Registrar, Fail-Closed Mock Mode & SDP Parsing (`src/modules/ims.rs`, `src/state/mod.rs`, `src/grpc_tls.rs`, `src/sip_arcrtc.rs`)
- **Falcon-512 (`FN-DSA-512`) Authentication Wiring**:
  - *Root Cause*: `RegistrarModule::handle_request` only matched `"ML-DSA-65"` and `"MD5" | "md5"`, rejecting `"Falcon-512"` despite `verify_authentication` supporting it and `docs/PQC_PERFORMANCE_ANALYSIS.md` recommending it as default ($22.3\,\mu\text{s}$ verification, $1,845\text{ B}$ total SIP packet size).
  - *Resolution*: Added `"Falcon-512" | "FN-DSA-512"` matching in `RegistrarModule::handle_request` with anti-downgrade protection (`pqc_required = true`).
- **Fail-Closed Mock Database Support**:
  - *Root Cause*: When `database.host == "localhost"`, `SipCore::new` initializes `SharedState::mock()` (`pool: None`). Calling `ctx.state.pool()` in `RegistrarModule` panicked the worker task on authenticated `REGISTER` requests.
  - *Resolution*: Added an explicit, fail-closed `mock_users` store (`empty` by default, preserving Phase 11 Red Team compliance with zero skeleton keys) and checked `ctx.state.has_active_pool()` before querying SQLx.
- **AOR Location Indexing & RFC 3329 `Security-Client` Parsing**:
  - *Resolution*: Indexed registered locations by both subscriber `Uuid` and username/AOR (`insert_location_by_name`), wired `parse_security_header` into Gm IPsec negotiation, auto-installed the `aws-lc-rs` PQC provider in `create_pqc_grpc_tls_config`, and wired `parse_sdp_media_streams(&invite.body)` in `SipSessionInfo::from_invite`.

### 3. Signaling Engine, Prometheus Metrics & S-CSCF Charging (`src/core/engine.rs`, `src/modules/ims.rs`)
- **1x Prometheus Request Metrics**:
  - *Root Cause & Math*: `metrics.increment_requests()`, `increment_invite()`, and `increment_register()` were called inside `for handler in &handler_set` (7 handlers), inflating reported metrics by $200\%$ for `REGISTER`, $400\%$ for PSTN `INVITE`, and $700\%$ for on-net `INVITE`.
  - *Resolution*: Moved request metric increments outside and prior to the handler loop so each incoming SIP request is counted once.
- **S-CSCF Diameter `Ro`/`Rf` Charging Wiring & Parallel Test UPF Port Fallback**:
  - *Resolution*: Connected `DiameterInterface` to `ScsCfModule` via `.with_diameter(Arc::clone(&diameter_interface))` in `SipCore::new`, and added automatic ephemeral port fallback (`127.0.0.1:0`) when `127.0.0.1:50051` is already bound during parallel integration tests.

### 4. BGCF Numbering Plan & Emergency Routing (`src/bgcf.rs`)
- **Zero False Emergency PSAP Hijacking**:
  - *Root Cause & Math*: Pattern `"112|911|999"` previously evaluated `destination.contains("112") || destination.contains("911") || destination.contains("999")`, misrouting $0.86\%\text{ to }2.37\%$ of standard 10-digit E.164 numbers containing those digit triples (e.g., `+12129111234`) to `sip:mgcf-emergency.cynan.ims:5060`.
  - *Resolution*: Added `extract_dialed_target` to strip URI schemes (`tel:`, `sip:`, `sips:`), `@domain`, and `;params`, and enforced exact target comparison (`target == "112" || target == "911" || target == "999"` or `urn:service:sos`).
- **NANP vs. International Set-Inclusion Priority Fix & Regex Evaluation**:
  - *Root Cause & Math*: Since $\mathcal{L}(\text{\texttt{\^\textbackslash+1[0-9]\{10\}\$}}) \subsetneq \mathcal{L}(\text{\texttt{\^\textbackslash+.*\$}})$, giving `"international"` priority `80` and `"nanp"` priority `70` resulted in a $0\%$ selection rate for NANP. Additionally, `"pstn"` (`^[0-9+\-\.\(\)\s]{7,20}$`) did not start with `^\+` and fell through to literal substring matching ($0\%$ match rate).
  - *Resolution*: Raised `"nanp"` priority to `85` (between `"emergency"` at `100` and `"international"` at `80`) and evaluated all `^...$` patterns via `regex::Regex`.

### 5. SLF Consistent Hashing (`src/slf.rs`)
- **64-Bit FNV-1a Subscriber Hash & Deterministic HSS Sorting**:
  - *Root Cause & Math*: The previous hash $\bigoplus_i (\text{byte}[i] \ll (8 \cdot (i \bmod 8)))$ shifted 7 out of every 8 bytes out of the lowest 8 bits, meaning $\text{hash} \bmod 2$ depended only on indices $i \in \{0, 8, 16, \dots\}$ and routed $100\%$ of consecutive 15-digit IMSI blocks (`310260990000000..310260990009999`) to a single HSS instance.
  - *Resolution*: Sorted `available_hss` by `hss.id` and replaced the body of `simple_hash` with 64-bit FNV-1a (`offset_basis = 0xcbf29ce484222325`, `prime = 0x100000001b3`), achieving a uniform $50.0\% / 50.0\%$ distribution across 2 HSS instances.

### 6. IBCF Border Control & Rate Limiting (`src/ibcf.rs`)
- **Source Domain Resolution & Unknown Peer Window Reset**:
  - *Root Cause*: `IbcfModule::handle_request` passed `ctx.peer.ip().to_string()` as the domain key to `is_trusted_peer`, failing lookups against domain-keyed `trusted_peers`. Furthermore, `cleanup_rate_limits()` executed `state.rate_tracking.retain(|_, count| *count > 0)`, a tautology that never cleared or reset unknown peer counters.
  - *Resolution*: Added `resolve_source_domain` (extracting the `From` URI domain or reverse-matching peer IP in `trusted_peers`), cleared `rate_tracking` on window expiry, capped `call_id_mappings` at `100,000` active entries, and enabled the periodic cleanup task in `IbcfModule::init`.

### 7. Diameter RFC 6733 32-Bit Padding & Carrier Rate Limits (`src/diameter.rs`, `src/integration.rs`)
- **RFC 6733 Section 4.1 4-Byte Boundary Alignment**:
  - *Root Cause*: `Avp::encode` and `Avp::decode` omitted the mandatory $0..3$ byte zero-padding required to align AVPs on 32-bit boundaries.
  - *Resolution*: Appended `(4 - (self.length as usize % 4)) % 4` zero bytes in `Avp::encode` and consumed `padding.min(buf.remaining())` bytes in `Avp::decode`.
- **Carrier-Grade Diameter Token-Bucket Capacity**:
  - *Root Cause & Math*: `DiameterRateLimiter` defaulted to `max_tokens = 50.0`, `fill_rate = 10.0 req/s`, capping sustained I-CSCF signaling at $10\text{ CPS}$ and exhausting burst capacity in $50.51\text{ ms}$ at $1,000\text{ CPS}$.
  - *Resolution*: Raised defaults to `max_tokens = 5000.0`, `fill_rate = 2000.0 req/s` and expanded `send_message` response buffer to `16 KB`.

### 8. CUPS User Plane Socket Lifecycle & RFC 3550 Sequence Math (`src/user_plane/mod.rs`, `src/rtp_router.rs`)
- **UDP Listener Task Cancellation on Session Teardown**:
  - *Root Cause*: `UserPlaneServer::delete_session` freed the UDP port in `RtpPortManager` without terminating the spawned `run_rtp_listener` task blocked on `socket.recv_from(&mut buf).await`, causing `EADDRINUSE` when the port was re-allocated.
  - *Resolution*: Stored per-session `tokio::task::AbortHandle` in `session_tasks` and aborted the listener task in `delete_session` before releasing the port. Added `allocate_even_port()` for RFC 3550 even RTP ports and updated `RtpStreamMapping::update_stats` to use modular 16-bit sequence distance (`wrapping_sub`).
