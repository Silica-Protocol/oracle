# POI Oracle — DESIGN_PLAN (living)

Updated: 2025-12-04

---

## Executive Summary

The Proof of Intelligence (PoI) Oracle bridges BOINC computational work and the Chert blockchain via PoUW (Proof of Useful Work). This consolidated plan synthesizes findings from **audit_actions.md**, **INTEGRATION_GUIDE.md**, **PQ_MIGRATION_PLAN.md**, **verification.md**, and **README.md** to provide a single source of truth for feature completeness.

**Current Status**: Foundation complete, critical security gaps remain before production.

---

## Checklist — Feature Completeness Status

### Core Infrastructure
| Feature | Status | Notes |
|---------|--------|-------|
| BOINC XML-RPC client (boinc_client.rs) | ✅ DONE | Pure Rust, no FFI |
| BOINC compatibility shim (boinc_compat.rs) | ✅ DONE | Fallback support |
| XML processing (xml_processor.rs) | ✅ DONE | 24KB, BOINC protocol |
| XML security validation (xml_security.rs) | ✅ DONE | Sanitization |
| Project manager (project_manager.rs) | ✅ DONE | Lifecycle mgmt |
| Secure HTTP client (secure_http.rs) | ✅ DONE | TLS 1.3 + rustls |
| Configuration management (config.rs) | ✅ DONE | Env-based, secure |

### Cryptographic Layer
| Feature | Status | Notes |
|---------|--------|-------|
| Ed25519 signing/verification | ✅ DONE | crypto.rs |
| Merkle tree batch verification | ✅ DONE | merkle.rs |
| WorkReceipt structure | ✅ DONE | crypto.rs |
| **Dilithium PQ signatures** | ❌ NOT STARTED | Design exists in PQ_MIGRATION_PLAN |
| **Hybrid PQ+classical signatures** | ❌ NOT STARTED | Required for PQ transition |
| **Key rotation mechanism** | ❌ NOT STARTED | Placeholder only |

### API Endpoints
| Feature | Status | Notes |
|---------|--------|-------|
| BOINC proxy routes (/boinc/*) | ✅ DONE | boinc_proxy.rs |
| Web API routes (/api/*) | ✅ DONE | web_api.rs |
| Miner API routes (/miner/*) | ✅ DONE | miner_api.rs |
| **API authentication** | ❌ CRITICAL GAP | No auth middleware |
| **Rate limiting** | ❌ CRITICAL GAP | Config exists, not implemented |
| **CORS configuration** | ❌ NOT STARTED | Config exists, not implemented |

### Verification & Anti-Gaming
| Feature | Status | Notes |
|---------|--------|-------|
| Basic work verification | ✅ DONE | poi_oracle.rs |
| PoI proof generation | ✅ DONE | poi_oracle.rs |
| PoI proof validation | ✅ DONE | poi_oracle.rs |
| Work aggregation | ✅ DONE | poi_aggregator.rs |
| **k-of-n replication** | ❌ NOT STARTED | verification.md spec |
| **Canary tasks** | ❌ NOT STARTED | verification.md spec |
| **Fraud detection engine** | ❌ NOT STARTED | PQ_MIGRATION_PLAN spec |
| **Timing plausibility checks** | ❌ NOT STARTED | PQ_MIGRATION_PLAN spec |
| **Sybil resistance** | ❌ NOT STARTED | verification.md spec |

### Rewards & Economics
| Feature | Status | Notes |
|---------|--------|-------|
| Basic reward calculation | ✅ DONE | poi_oracle.rs |
| Project multipliers | ✅ DONE | Config-driven |
| **Uncle/side-batch inclusion credits** | 🔄 IN PROGRESS | |
| **Role-based payout meters** | ❌ NOT STARTED | |
| **Provisional payout model** | ❌ NOT STARTED | verification.md spec |
| **Clawback mechanism** | ❌ NOT STARTED | verification.md spec |

### DAG/Consensus Integration
| Feature | Status | Notes |
|---------|--------|-------|
| PoUW DAG tip generation | ❌ NOT STARTED | INTEGRATION_GUIDE spec |
| Account chain tracking | ❌ NOT STARTED | INTEGRATION_GUIDE spec |
| aBFT finality integration | ❌ NOT STARTED | INTEGRATION_GUIDE spec |
| Oracle consensus (2/3 majority) | ❌ NOT STARTED | INTEGRATION_GUIDE spec |
| Pipelined admit→order→execute | ❌ NOT STARTED | |

### Testing & CI
| Feature | Status | Notes |
|---------|--------|-------|
| Unit tests | ❌ CRITICAL GAP | Only config tests exist |
| Integration tests | ❌ CRITICAL GAP | No test fixtures |
| CI pipeline | ❌ CRITICAL GAP | No .github/workflows |
| Security/fuzz testing | ❌ NOT STARTED | |
| Performance benchmarks | ❌ NOT STARTED | |

---

## Critical Security Gaps (from audit_actions.md)

### 🚨 P0 — Must Fix Before Any Deployment

1. **CRITICAL: Missing API Authentication**
   - File: \`src/main.rs\`
   - Issue: No authentication middleware on any route
   - Risk: Unauthorized access, API abuse
   - Fix: Add JWT/API key middleware to all routes
   
2. **CRITICAL: No Rate Limiting Implementation**
   - Files: All API endpoints
   - Issue: Config exists but not wired
   - Risk: DoS attacks
   - Fix: Implement tower rate limiting layer

3. **HIGH: Hardcoded MilkyWay URL in boinc_proxy.rs**
   - File: \`src/boinc_proxy.rs\` line ~180
   - Code: \`let real_url = "https://milkyway.cs.rpi.edu/milkyway_cgi/cgi";\`
   - Fix: Use config.boinc.projects dynamic lookup

4. **HIGH: Missing Request Size Validation**
   - File: \`src/boinc_proxy.rs\`
   - Issue: 1MB limit exists but only in proxy
   - Fix: Apply globally via tower middleware

### 🔶 P1 — High Priority

5. **Information Disclosure in Logs**
   - Files: Throughout
   - Issue: sanitize_for_logging exists but inconsistently applied
   - Fix: Audit all tracing::info/warn/error calls

6. **Missing Error Boundaries**
   - File: \`src/main.rs\`
   - Issue: No graceful degradation
   - Fix: Add tower catch_panic and error handling layers

7. **Single Responsibility Violations**
   - File: \`src/boinc_proxy.rs\` (295 lines)
   - Fix: Split into ProxyRouter, BoincCommunicator, RequestProcessor

---

## Verification System Gaps (from verification.md)

The verification.md document specifies a comprehensive multi-layer PoUW verification system. **None of this is implemented**:

### Work Assignment & Duplication
\`\`\`
❌ k-replication (assign each WorkUnit to k≥2 miners)
❌ m-of-k quorum validation
❌ Speculative backfill for stragglers
❌ Diversity constraints (different ASNs/geos)
❌ Sticky retries for invalid miners
\`\`\`

### Miner Identity & Sybil Resistance
\`\`\`
❌ Stake-or-reputation gate
❌ Per-cell concurrency quotas
❌ Device attestation (SGX/SEV/TPM)
\`\`\`

### Validation Pipeline
\`\`\`
❌ Canonical validator (bit-exact compare)
❌ Shadow validator (canary units, spot-checks)
❌ Cross-platform agreement checks
❌ V-Green/V-Amber/V-Red outcome classes
\`\`\`

### Provisional Payout Model
\`\`\`
❌ Split rewards (provisional + final)
❌ Trust tier system (Tier 0/1/2)
❌ Clawback mechanism
❌ Fraud-proof artifacts
\`\`\`

---

## Post-Quantum Migration Gaps (from PQ_MIGRATION_PLAN.md)

### Phase 1: Foundation (NOT STARTED)
\`\`\`
❌ Add pqcrypto-dilithium dependency
❌ Add pqcrypto-falcon dependency
❌ Create src/crypto/oracle_keys.rs
❌ Create src/crypto/work_verification.rs
❌ Implement OracleKeyManager with PQ support
❌ Implement WorkVerificationEngine
\`\`\`

### Phase 2: Core Updates (NOT STARTED)
\`\`\`
❌ SecurePouwOracle with PQ signatures
❌ SecurePoIProof with contributor signatures
❌ FraudDetectionEngine
❌ Timing/resource plausibility models
\`\`\`

### Phase 3: API Security (NOT STARTED)
\`\`\`
❌ Secure API endpoints (v2 API)
❌ Mutual authentication
❌ Request signing verification
\`\`\`

---

## DAG Integration Gaps (from INTEGRATION_GUIDE.md)

The oracle is designed to integrate with Chert's DAG + Account Chain architecture. **None of this is implemented**:

\`\`\`
❌ PoUW DAG tip creation from verified work
❌ Account chain per-user scientific ledger
❌ Distributed oracle network (multiple oracles)
❌ Oracle consensus (2/3 majority required)
❌ aBFT finality signatures
❌ Impact score calculation
\`\`\`

### Supported Services (Config exists, APIs not implemented)
| Service | API Type | Status |
|---------|----------|--------|
| World Community Grid | BOINC XML | ✅ Config |
| Folding@Home | REST JSON | ❌ Not implemented |
| Rosetta@Home | BOINC XML | ✅ Config |
| Einstein@Home | BOINC XML | ✅ Config |
| Climate Prediction | BOINC XML | ❌ Config only |
| LHC@Home | BOINC XML | ❌ Config only |

---

## Prioritized Implementation Roadmap

### Phase 1: Security Hardening (Week 1-2) — BLOCKING

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Implement API authentication middleware | P0 | 2d | ❌ |
| Implement rate limiting layer | P0 | 1d | ❌ |
| Remove hardcoded URLs from boinc_proxy.rs | P0 | 0.5d | ❌ |
| Add global request size limits | P0 | 0.5d | ❌ |
| Audit and fix log sanitization | P1 | 1d | ❌ |
| Add error boundary middleware | P1 | 1d | ❌ |

### Phase 2: Testing Foundation (Week 2-3) — BLOCKING

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Unit tests for crypto.rs | P0 | 2d | ❌ |
| Unit tests for merkle.rs | P0 | 1d | ❌ |
| Unit tests for poi_oracle.rs | P0 | 2d | ❌ |
| Integration tests with mock BOINC server | P0 | 3d | ❌ |
| CI pipeline (clippy, test, audit) | P0 | 1d | ❌ |
| End-to-end receipt verification test | P1 | 2d | ❌ |

### Phase 3: Verification System (Week 3-5)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| k-of-n replication system | P1 | 3d | ❌ |
| Canary task injection | P1 | 2d | ❌ |
| Basic fraud detection (timing checks) | P1 | 2d | ❌ |
| V-Green/V-Amber/V-Red result states | P2 | 1d | ❌ |
| Trust tier implementation | P2 | 2d | ❌ |

### Phase 4: PQ Cryptography (Week 5-7)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Add PQ dependencies to Cargo.toml | P1 | 0.5d | ❌ |
| Implement OracleKeyManager | P1 | 3d | ❌ |
| Implement hybrid signing | P1 | 2d | ❌ |
| Migrate WorkReceipt to PQ signatures | P2 | 2d | ❌ |
| Key rotation mechanism | P2 | 2d | ❌ |

### Phase 5: Rewards & Economics (Week 7-8)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| Uncle/side-batch inclusion credits | P2 | 2d | 🔄 |
| Role hints (Validator/Executor/Gateway) | P2 | 2d | ❌ |
| Provisional payout model | P3 | 3d | ❌ |
| Clawback mechanism | P3 | 2d | ❌ |

### Phase 6: DAG Integration (Week 8-12)

| Task | Priority | Effort | Status |
|------|----------|--------|--------|
| PoUW DAG tip generation | P2 | 5d | ❌ |
| Multi-oracle consensus | P2 | 5d | ❌ |
| Account chain integration | P3 | 3d | ❌ |
| aBFT finality signatures | P3 | 3d | ❌ |

---

## File Structure

### Current (19 files)
\`\`\`
oracle/src/
├── lib.rs                 # Module exports
├── main.rs                # Server entrypoint
├── boinc_apis.rs          # BOINC API definitions
├── boinc_client.rs        # Pure Rust XML-RPC client ✅
├── boinc_compat.rs        # Compatibility shim ✅
├── boinc_logger.rs        # BOINC logging
├── boinc_proxy.rs         # BOINC proxy routes ⚠️ needs refactor
├── config.rs              # Configuration ✅
├── crypto.rs              # Ed25519 crypto ✅ (needs PQ)
├── merkle.rs              # Merkle trees ✅
├── miner_api.rs           # Miner API routes ✅
├── poi_aggregator.rs      # Work aggregation ✅
├── poi_oracle.rs          # Core oracle ✅
├── pouw_challenge.rs      # Challenge structures
├── project_manager.rs     # Project lifecycle ✅
├── secure_http.rs         # Secure HTTP client ✅
├── web_api.rs             # Web API routes ✅
├── xml_processor.rs       # XML processing ✅
├── xml_security.rs        # XML security ✅
└── models/
    ├── mod.rs
    ├── boinc.rs           # BOINC data models
    └── poi.rs             # Re-exports from silica-models
\`\`\`

### Planned Additions
\`\`\`
oracle/src/
├── auth/                  # NEW: Authentication
│   ├── mod.rs
│   ├── middleware.rs      # Auth middleware
│   └── jwt.rs             # JWT handling
├── crypto/                # REFACTOR: PQ crypto
│   ├── mod.rs
│   ├── ed25519.rs         # Classical
│   ├── dilithium.rs       # PQ
│   ├── hybrid.rs          # Hybrid signing
│   └── oracle_keys.rs     # Key management
├── verification/          # NEW: Verification system
│   ├── mod.rs
│   ├── replication.rs     # k-of-n replication
│   ├── canary.rs          # Canary tasks
│   ├── fraud.rs           # Fraud detection
│   └── trust.rs           # Trust tiers
├── rewards/               # NEW: Rewards
│   ├── mod.rs
│   ├── provisional.rs     # Provisional payouts
│   └── clawback.rs        # Clawback mechanism
└── dag/                   # NEW: DAG integration
    ├── mod.rs
    ├── tip_generator.rs   # PoUW DAG tips
    └── consensus.rs       # Multi-oracle consensus
\`\`\`

---

## Testing Requirements

### Unit Tests (❌ None exist)
\`\`\`rust
// Required test modules:
#[cfg(test)] mod crypto_tests;      // Key gen, sign, verify
#[cfg(test)] mod merkle_tests;      // Tree construction, proofs
#[cfg(test)] mod oracle_tests;      // Verification logic
#[cfg(test)] mod config_tests;      // ✅ Exists
#[cfg(test)] mod xml_tests;         // Parsing, security
\`\`\`

### Integration Tests (❌ None exist)
\`\`\`rust
// Required integration tests:
tests/
├── boinc_integration.rs   // Mock BOINC server
├── api_endpoints.rs       // HTTP endpoint tests
├── receipt_pipeline.rs    // End-to-end receipt flow
└── fixtures/
    ├── boinc_responses/   // Recorded XML responses
    └── work_units/        // Sample work data
\`\`\`

### CI Pipeline (❌ Does not exist)
\`\`\`yaml
# Required .github/workflows/oracle.yml
jobs:
  check:
    - cargo check --workspace
    - cargo clippy -- -D warnings
    - cargo fmt --check
  test:
    - cargo test --workspace
    - cargo test --workspace -- --ignored  # Integration
  security:
    - cargo audit
    - cargo deny check
\`\`\`

---

## Acceptance Criteria for Production

### Security
- [ ] All API endpoints require authentication
- [ ] Rate limiting enforced (60 req/min default)
- [ ] No hardcoded credentials or URLs
- [ ] All external communication via HTTPS
- [ ] Log sanitization verified
- [ ] cargo audit shows no high/critical vulnerabilities

### Functionality
- [ ] BOINC work verification operational
- [ ] PoI proofs generate and validate correctly
- [ ] Merkle receipts sign and verify
- [ ] At least 2-of-3 oracle consensus for verification

### Quality
- [ ] >80% test coverage on core modules
- [ ] CI pipeline passing
- [ ] All clippy warnings resolved
- [ ] Documentation complete

---

## Design Principles

1. **Client-driven integration**: Oracle talks to miner-side clients via documented RPC endpoints or signed messages. No wide C APIs exposed.

2. **Centralized crypto**: All cryptography (PQ + classical) in a single \`crypto\` module with trait-based abstraction for swappable implementations.

3. **Optional FFI**: Any remaining FFI strictly optional behind \`ffi\` feature flag.

4. **Strong input validation**: Every entrypoint validates payload sizes, types, and Merkle proof structure. Rate limiting per account/peer.

5. **TigerBeetle-inspired quality**: Zero technical debt, no TODOs in production code, comprehensive assertions.

---

## Related Documents

| Document | Purpose | Status |
|----------|---------|--------|
| audit_actions.md | Security audit findings | Consolidated here |
| INTEGRATION_GUIDE.md | DAG integration spec | Consolidated here |
| PQ_MIGRATION_PLAN.md | PQ crypto migration | Consolidated here |
| verification.md | PoUW verification spec | Consolidated here |
| README.md | Quick start guide | Keep as user guide |

---

## Open Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Some BOINC interactions require native APIs not exposed via XML-RPC | Keep minimal, audited FFI fallback behind \`ffi\` feature |
| PQ library maturity and portability | Abstract signer/verifier with traits; evaluate multiple PQ backends |
| Migration complexity for running networks | Staged rollout with \`boinc_compat\` shim, clear migration guide |
| Single oracle failure | Multi-oracle consensus with 2/3 majority requirement |

---

## Developer Commands

\`\`\`bash
# Run unit tests
cd oracle && cargo test

# Run clippy
cargo clippy -- -D warnings

# Security audit
cargo audit

# Format check
cargo fmt --check

# Full pre-commit check
cargo fmt && cargo clippy -- -D warnings && cargo test && cargo audit
\`\`\`

---

## Edit History

- **2025-12-04**: MAJOR CONSOLIDATION — Merged all documentation into single DESIGN_PLAN
  - Integrated findings from audit_actions.md (security gaps)
  - Integrated findings from INTEGRATION_GUIDE.md (DAG integration)
  - Integrated findings from PQ_MIGRATION_PLAN.md (cryptography)
  - Integrated findings from verification.md (PoUW verification)
  - Created comprehensive gap analysis with 40+ specific features/fixes needed
  - Established 6-phase prioritized roadmap for production readiness
- 2025-09-21: Major milestone — Core POI Oracle architecture completed
- 2025-09-10: Initial draft
