# Cynan IMS Core - Development Best Practices

## Document Purpose

This guide documents best practices, architectural decisions, and coding standards established during the Post-Quantum Cryptography (PQC) integration and serves as the authoritative reference for maintaining code quality at senior engineering standards.

**Target Audience**: Senior engineers, security architects, code reviewers  
**Version**: 1.0  
**Last Updated**: 2026-01-29

---

## Architectural Patterns

### 1. Internal Mutability for IMS Modules

**Problem Statement**:
IMS modules require complex post-construction initialization after the initial `new()` call. This conflicts with Rust's preference for immutable-after-construction patterns.

**Solution**: `Arc<RwLock<State>>` Pattern

```rust
// ✅ CORRECT: Thread-safe internal mutability
pub struct IcsCfModule {
    config: Arc<CoreConfig>,
    diameter: Arc<RwLock<Option<Arc<DiameterInterface>>>>,
    state: Arc<RwLock<IcscfState>>,
}
```

**Rationale**:
- ✅ Satisfies `Clone + Send + Sync` for sharing across async tasks
- ✅ Enables post-construction initialization without `&mut self`
- ✅ Explicit lock scopes prevent accidental lock holding

---

### 2. Lock Management Strategy

**Principle**: Never hold locks across `.await` points.

**Decision**: Use `std::sync::RwLock` over `tokio::sync::RwLock` for most state.

**Rationale**:
- `std::sync::RwLock` guards are NOT `Send`, preventing accidental `.await` violations.

---

### 3. Error Handling Strategy

**Principle**: Use `Result<T>` everywhere, minimize `unwrap()`. Use `.context()` from `anyhow` to add error context.

---

## Security Best Practices

### 1. PQC Key Management
- **Secret Key Handling**: Use `ZeroizeOnDrop` for all secret material.
- **Logging**: Never log secret keys or sensitive material.
- **Constant-Time**: Use constant-time comparison for all secret-dependent logic.

### 2. Input Validation
- Validate ALL external input (SIP, Diameter, etc.) before processing.
- Enforce strict size limits and format validation.

---

## Testing Strategy
- **Unit Tests**: Coverage target >80%.
- **Integration Tests**: End-to-end flows in `tests/`.
- **Benchmarks**: Critical path performance tracking in `benches/`.

---

## Performance Optimization
- Minimize allocations in hot paths.
- Cache expensive PQC operations where possible.
- Use parallel iterators for batch processing.
