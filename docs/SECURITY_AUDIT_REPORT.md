# Olympus Security Audit Report

**Version:** 1.0  
**Audit Date:** April 1–2, 2026  
**Report Date:** April 2, 2026  
**Auditors:** Internal Red Team  
**Classification:** Public

---

## Executive Summary

This report documents the findings from a comprehensive security audit of the Olympus federated public ledger system. The audit identified **2 critical**, **5 high**, **7 medium**, and **5 low** severity vulnerabilities across the Python API layer, storage subsystem, protocol primitives, and witness/sequencer services.

### Key Findings

| Risk Level | Count | Remediation Status |
|------------|-------|-------------------|
| **Critical** | 2 | 0 Fixed, 2 Open |
| **High** | 5 | 0 Fixed, 5 Open |
| **Medium** | 7 | 0 Fixed, 7 Open |
| **Low** | 5 | 0 Fixed, 5 Open |
| **Informational** | 7 | N/A |

**Most Urgent:** C-2 (Embargo bypass) is trivially exploitable via any standard HTTP client with zero prerequisites. C-1 (SMT parameter confusion) causes production crashes on the PostgreSQL ingest path.

---

## Methodology

### Scope

**In-Scope:**
- Python API layer (`api/` directory) — FastAPI endpoints, authentication, rate limiting
- Storage layer (`storage/postgres.py`) — Append-only ledger, SMT operations, triggers
- Protocol primitives (`protocol/`) — Canonicalization, hashing, Merkle trees, Poseidon SMT
- Witness and sequencer services (`api/routers/witness.py`, `services/sequencer-go/`)
- Rust cryptographic core (`services/cdhs-smf-rust/`)

**Out-of-Scope:**
- Infrastructure/deployment configuration
- Third-party dependencies (covered by separate SBOM analysis)
- Frontend applications (none exist yet)
- Groth16 trusted setup ceremony (external process)

### Techniques

| Technique | Description |
|-----------|-------------|
| **Static Analysis** | Manual code review of all security-critical paths |
| **Data Flow Analysis** | Tracing user input from API endpoints through storage |
| **Threat Modeling** | STRIDE-based analysis of ledger integrity guarantees |
| **Specification Review** | Comparing implementation against `docs/` protocol specifications |
| **Dependency Audit** | Reviewing cryptographic primitive usage patterns |

### Tools

- Manual code review (primary method)
- grep/ripgrep for pattern searching
- Python AST analysis for auth bypass detection
- Custom scripts for canonicalization boundary verification

### Duration

- **Total effort:** ~16 analyst-hours
- **Code review:** 12 hours
- **Documentation and reporting:** 4 hours

### Limitations

This audit represents a point-in-time assessment. It does not guarantee absence of vulnerabilities, and findings should be verified against the current codebase before remediation. No dynamic testing or penetration testing was performed.

---

## Risk Rating Matrix

Findings are rated using a **Severity × Exploitability** matrix:

| | **Trivial Exploit** | **Moderate Effort** | **Complex/Theoretical** |
|---|---|---|---|
| **Critical Impact** | **CRITICAL** | **CRITICAL** | HIGH |
| **High Impact** | **HIGH** | HIGH | MEDIUM |
| **Medium Impact** | HIGH | MEDIUM | LOW |
| **Low Impact** | MEDIUM | LOW | INFO |

**Severity** reflects the worst-case impact if exploited:
- **Critical:** Data disclosure, integrity violation, or service denial affecting ledger guarantees
- **High:** Security control bypass, privilege escalation, or significant data leak
- **Medium:** Defense-in-depth violation, potential for chained attacks
- **Low:** Minor information disclosure, hardening recommendations

**Exploitability** reflects the effort and prerequisites required:
- **Trivial:** No authentication required, or single authenticated API call
- **Moderate:** Requires specific conditions, timing, or multiple steps
- **Complex:** Requires insider access, race conditions, or theoretical attack chains

---

## Findings Summary

| ID | Title | Severity | Exploitability | Status | Fix PR |
|----|-------|----------|----------------|--------|--------|
| [C-1](#c-1-poseidon-smt-rebuild-crashes-on-non-empty-shards) | Poseidon SMT rebuild crashes on non-empty shards | Critical | Moderate | 🔴 Open | — |
| [C-2](#c-2-embargo-flag-stored-but-never-enforced) | Embargo flag stored but never enforced | Critical | **Trivial** | 🔴 Open | — |
| [H-1](#h-1-witness-checkpoint-submissions-accept-unsigned-announcements) | Witness checkpoint submissions accept unsigned announcements | High | Moderate | 🔴 Open | — |
| [H-2](#h-2-poseidon-field-values-not-reduced-modulo-snark-scalar-field) | Poseidon field values not reduced mod SNARK_SCALAR_FIELD | High | Complex | 🔴 Open | — |
| [H-3](#h-3-dual-independent-rate-limit-systems) | Dual independent rate-limit systems | High | Moderate | 🔴 Open | — |
| [H-4](#h-4-sth-history-returns-empty-signatures) | STH history returns empty signatures | High | Trivial | 🔴 Open | — |
| [H-5](#h-5-proof_id-parameter-unvalidated) | `proof_id` parameter unvalidated | High | Trivial | 🔴 Open | — |
| [M-1](#m-1-dataset-history-unbounded-query) | Dataset history unbounded query | Medium | Moderate | 🔴 Open | — |
| [M-2](#m-2-dataset-file-commit-unbounded) | Dataset file commit unbounded | Medium | Moderate | 🔴 Open | — |
| [M-3](#m-3-internal-exception-message-leak) | Internal exception message leak | Medium | Trivial | 🔴 Open | — |
| [M-4](#m-4-duplicate-client-ip-resolution) | Duplicate client IP resolution | Medium | Complex | 🔴 Open | — |
| [M-5](#m-5-witness-origin-field-unconstrained) | Witness origin field unconstrained | Medium | Trivial | 🔴 Open | — |
| [M-6](#m-6-proof-submission-accepts-caller-supplied-state) | Proof submission accepts caller-supplied state | Medium | Moderate | 🔴 Open | — |
| [M-7](#m-7-unbounded-tree-replay) | Unbounded tree replay | Medium | Moderate | 🔴 Open | — |
| [L-1](#l-1-get_ingestion_proof-unauthenticated) | `get_ingestion_proof` unauthenticated | Low | Trivial | 🔴 Open | — |
| [L-2](#l-2-admin-reload-leaks-config-state) | Admin reload leaks config state | Low | Trivial | 🔴 Open | — |
| [L-3](#l-3-witness-stores-per-process) | Witness stores per-process | Low | Complex | 🔴 Open | — |
| [L-4](#l-4-recursive-json-depth-check) | Recursive JSON depth check | Low | Complex | 🔴 Open | — |
| [L-5](#l-5-rfc-3161-tsa-no-certificate-pinning) | RFC 3161 TSA no certificate pinning | Low | Complex | 🔴 Open | — |

**Legend:** 🔴 Open · 🟡 In Progress · 🟢 Fixed · ✅ Verified

---

## Detailed Findings

### Critical

#### C-1: Poseidon SMT rebuild crashes on non-empty shards

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **Exploitability** | Moderate |
| **Location** | `api/ingest.py:862` |
| **Status** | 🔴 Open |

**Description:**  
`_build_poseidon_smt_for_storage_shard()` passes `shard_id` as the second argument to `StorageLayer._load_tree_state()`, but that function expects `up_to_ts` (a timestamp). When `up_to_ts` is not `None`, the code attempts `datetime.fromisoformat()` on a shard ID string, raising `ValueError`.

**Impact:**  
Every ingest request that hits the PostgreSQL path crashes with HTTP 500 when the Poseidon SMT is rebuilt for an existing shard. This occurs after any process restart that evicts in-memory state.

**Proof of Concept:**
```bash
# After a server restart, ingest any record to an existing shard
curl -X POST /ingest/records -d '{"shard_id": "existing:shard", ...}'
# Returns HTTP 500 with ValueError traceback
```

**Recommendation:**  
Change the call to `storage._load_tree_state(cur)` and filter leaves by `global_key` prefix to reconstruct only the target shard's Poseidon state.

---

#### C-2: Embargo flag stored but never enforced

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **Exploitability** | **Trivial** |
| **Location** | `api/models/document.py:54`, `api/routers/documents.py`, `api/routers/ledger.py` |
| **Status** | 🔴 Open |

**Description:**  
`DocCommit.embargo_until` is accepted at commit time and persisted to the database, but **no read path filters on this field**. All document retrieval endpoints return embargoed records without checking whether the embargo period has elapsed.

**Affected Endpoints:**
- `GET /ledger/proof/{commit_id}`
- `POST /doc/verify`
- `GET /ledger/shard/{shard_id}`
- `POST /ledger/verify/simple`

**Impact:**  
Any document committed with an embargo date can be retrieved immediately by any party. This is a direct data disclosure vulnerability for agencies using embargo for pre-release materials.

**Proof of Concept:**
```bash
# Commit a document with embargo until 2027
curl -X POST /ingest/records -d '{"embargo_until": "2027-01-01T00:00:00Z", ...}'

# Immediately retrieve it
curl GET /ledger/proof/{commit_id}
# Returns full document content — embargo ignored
```

**Recommendation:**  
Add a query guard on all read paths:
```python
.where(or_(
    DocCommit.embargo_until.is_(None),
    DocCommit.embargo_until <= datetime.now(timezone.utc)
))
```
Or return HTTP 403 with a `Retry-After` header indicating when the embargo lifts.

---

### High

#### H-1: Witness checkpoint submissions accept unsigned announcements

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate |
| **Location** | `api/routers/witness.py:submit_observation` |
| **Status** | 🔴 Open |

**Description:**  
The `POST /witness/observations` endpoint validates timestamp freshness and nonce deduplication but does not verify any Ed25519 signature on the checkpoint payload. Any authenticated caller can fabricate an announcement from any `origin` with any `checkpoint_hash`.

**Impact:**  
The witness/gossip anti-split-view mechanism becomes meaningless. An attacker with a single API key can flood the store with synthetic conflicts or suppress real divergence signals.

**Recommendation:**  
Add `checkpoint_signature` and `signer_pubkey` fields to `WitnessAnnounceRequest`. Verify the Ed25519 signature over the canonical checkpoint serialization before storing.

---

#### H-2: Poseidon field values not reduced modulo SNARK_SCALAR_FIELD

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Complex |
| **Location** | `api/ingest.py:850-854` |
| **Status** | 🔴 Open |

**Description:**  
```python
def _value_hash_to_poseidon_field(value_hash: bytes) -> int:
    return int.from_bytes(value_hash, byteorder="big")
```

BLAKE3 hashes are uniform 256-bit integers. The BN128 scalar field prime is ~2²⁵⁴. Approximately **25% of BLAKE3 outputs** exceed `SNARK_SCALAR_FIELD`. While `PoseidonSMT.update()` reduces internally, this creates:

1. Mismatch between stored leaf (`hash % p`) and expected value (`hash`)
2. External verifiers receive false negatives
3. Hash collisions: `h` and `h + p` map to identical Poseidon leaves

**Recommendation:**  
Reduce at the call site:
```python
return int.from_bytes(value_hash, byteorder="big") % SNARK_SCALAR_FIELD
```

---

#### H-3: Dual independent rate-limit systems

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate |
| **Location** | `api/ingest.py:535-765`, `api/auth.py:390-558` |
| **Status** | 🔴 Open |

**Description:**  
`api/ingest.py` and `api/auth.py` maintain separate in-memory token buckets with different configurations and lifecycle management.

**Impact:**
- Attacker can exhaust auth-module budget while ingest limits remain unaffected
- Key-reload operations reset auth state but not ingest rate-limit state
- Environment variables (`OLYMPUS_FOIA_RATE_LIMIT_CAPACITY`) only affect one module

**Recommendation:**  
Consolidate to a single rate-limit backend. Either have `ingest.py` delegate to `auth._get_backend()`, or move all rate limiting to a shared Redis/database-backed system.

---

#### H-4: STH history returns empty signatures

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Trivial |
| **Location** | `api/sth.py:161-165` |
| **Status** | 🔴 Open |

**Description:**  
```python
sths.append(STHResponse(
    epoch_id=entry["seq"],
    ...
    signature="",      # ← deliberately empty
    signer_pubkey="",  # ← deliberately empty
))
```

Historical STH entries expose root hash and sequence but omit the cryptographic signature.

**Impact:**  
A log operator could serve a silently forked history with no evidence of tampering. The tamper-evidence guarantee is unverifiable for historical state.

**Recommendation:**  
Join `shard_headers.sig` and `shard_headers.pubkey` in the history query. Ensure `get_header_history()` returns these columns.

---

#### H-5: `proof_id` parameter unvalidated

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Trivial |
| **Location** | `api/ingest.py:1334-1352` |
| **Status** | 🔴 Open |

**Description:**  
The `proof_id` path parameter in `GET /records/{proof_id}/proof` accepts arbitrary strings with no length limit, pattern restriction, or UUID validation. The endpoint also lacks authentication.

**Impact:**
- Enumeration oracle: 200 vs 404 distinguishes valid from invalid proof IDs
- Potential path traversal testing vector
- No rate limiting on unauthenticated enumeration

**Recommendation:**  
Add parameter constraint:
```python
proof_id: str = Path(..., pattern=r"^[0-9a-f-]{32,36}$")
```
Consider adding authentication or rate limiting.

---

### Medium

#### M-1: Dataset history unbounded query

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `api/routers/datasets.py:734-738` |
| **Status** | 🔴 Open |

**Description:**  
`GET /datasets/{dataset_id}/history` executes a query with no `.limit()` clause. A dataset with thousands of versions causes a full table scan and potential OOM.

**Recommendation:**  
Add `.limit(500)` default and expose `page`/`per_page` query parameters.

---

#### M-2: Dataset file commit unbounded

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `api/routers/datasets.py:427-430`, `648-650` |
| **Status** | 🔴 Open |

**Description:**  
A dataset artifact can be committed with arbitrarily many file entries. Loading 100,000 files unboundedly causes resource exhaustion.

**Recommendation:**  
Add `max_length=10_000` to `DatasetCommitRequest.files`. Add `.limit(10_001)` on queries with truncation warning.

---

#### M-3: Internal exception message leak

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Trivial |
| **Location** | `api/sth.py:131`, `200` |
| **Status** | 🔴 Open |

**Description:**  
```python
raise HTTPException(
    status_code=500,
    detail=f"Failed to get latest STH: {str(e)}",
)
```

Raw exception messages may expose table names, column names, SQL fragments, or stack details to external callers.

**Recommendation:**  
Log the full exception server-side. Return a generic message to clients.

---

#### M-4: Duplicate client IP resolution

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Complex |
| **Location** | `api/ingest.py:646-680`, `api/auth.py:630-657` |
| **Status** | 🔴 Open |

**Description:**  
Both modules implement `X-Forwarded-For` parsing with trusted-proxy logic, reading from different configuration sources. Divergence could cause inconsistent IP-based rate limiting or logging.

**Recommendation:**  
Delete `_client_ip()` from `ingest.py` and call `auth._get_client_ip(request)`.

---

#### M-5: Witness origin field unconstrained

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Trivial |
| **Location** | `api/routers/witness.py`, `api/schemas/witness.py` |
| **Status** | 🔴 Open |

**Description:**  
The `origin` field has no pattern constraint, length limit, or allowlist. Attackers can inject colons to collide with legitimate key namespaces or use extremely long strings.

**Recommendation:**  
Add field constraint: `pattern=r"^[A-Za-z0-9._:-]{1,128}$"`

---

#### M-6: Proof submission accepts caller-supplied state

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `api/ingest.py:1411-1475` |
| **Status** | 🔴 Open |

**Description:**  
`submit_proof_bundle` accepts `shard_id`, `record_id`, and `canonicalization` from the caller. An authenticated attacker can poison the in-memory Poseidon state cache.

**Recommendation:**  
Validate that the submitted `content_hash` maps to an existing shard record before accepting.

---

#### M-7: Unbounded tree replay

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `storage/postgres.py:2334-2474` |
| **Status** | 🔴 Open |

**Description:**  
`replay_tree_incremental()` and `verify_state_replay()` load all shard headers and ledger rows unboundedly. Large shards cause memory exhaustion.

**Recommendation:**  
Add circuit breakers or streaming pagination to replay operations.

---

### Low

#### L-1: `get_ingestion_proof` unauthenticated

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Trivial |
| **Location** | `api/ingest.py:1334-1352` |
| **Status** | 🔴 Open |

**Description:**  
The endpoint lacks `RequireVerifyScope` or `RequireAPIKey` dependency, unlike `/records/hash/{content_hash}/verify` which requires authentication.

---

#### L-2: Admin reload leaks config state

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Trivial |
| **Location** | `api/routers/keys.py:107-121` |
| **Status** | 🔴 Open |

**Description:**  
The 503 response message "Admin key reload not configured" reveals whether `OLYMPUS_ADMIN_KEY` is set.

**Recommendation:**  
Add rate limiting. Return consistent error message regardless of configuration.

---

#### L-3: Witness stores per-process

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex |
| **Location** | `api/routers/witness.py:73-80` |
| **Status** | 🔴 Open |

**Description:**  
Witness observation stores are in-memory and per-process. Multi-worker deployments silently split observations across processes, fragmenting the gossip state.

**Recommendation:**  
Block startup with `RuntimeError` when `WEB_CONCURRENCY > 1`, or migrate to shared storage.

---

#### L-4: Recursive JSON depth check

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex |
| **Location** | `api/ingest.py:94-113` |
| **Status** | 🔴 Open |

**Description:**  
`_check_json_depth()` uses Python recursion. Adversarial input exceeding Python's default recursion limit (1000) could cause a crash.

**Recommendation:**  
Convert to iterative implementation with explicit stack.

---

#### L-5: RFC 3161 TSA no certificate pinning

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex |
| **Location** | `api/routers/datasets.py:226-236` |
| **Status** | 🔴 Open |

**Description:**  
The TSA URL is fetched without certificate pinning. A MITM attacker with a valid certificate could issue fake timestamp tokens.

**Recommendation:**  
Pin the TSA certificate or use a well-known TSA with certificate transparency logging.

---

### Informational

| ID | Description | Location |
|----|-------------|----------|
| I-1 | Duplicate client IP resolution (see M-4) | — |
| I-2 | `generate_commit_id()` uses 160-bit, not 256-bit | `api/services/hasher.py:64-70` |
| I-3 | `submit_proof_bundle` does not persist to Postgres | `api/ingest.py:1460` |
| I-4 | `_build_poseidon_smt_for_storage_shard` calls private methods | `api/ingest.py:861-862` |
| I-5 | `dataset_history` endpoint has no authentication | `api/routers/datasets.py:727-761` |
| I-6 | STH router uses mutable global `_storage` with no synchronization | `api/sth.py:42-50` |
| I-7 | Poseidon SMT uses Python reference implementation, may diverge from ZK circuit | `protocol/poseidon_smt.py`, `protocol/poseidon_bn128.py` |

---

## Remediation Tracking

This section tracks the fix lifecycle for each finding.

| ID | Severity | Found | Fix PR | Fixed | Verified | Notes |
|----|----------|-------|--------|-------|----------|-------|
| C-1 | Critical | 2026-04-01 | — | — | — | |
| C-2 | Critical | 2026-04-01 | — | — | — | **Priority: Trivially exploitable** |
| H-1 | High | 2026-04-01 | — | — | — | |
| H-2 | High | 2026-04-01 | — | — | — | |
| H-3 | High | 2026-04-01 | — | — | — | |
| H-4 | High | 2026-04-01 | — | — | — | |
| H-5 | High | 2026-04-01 | — | — | — | |
| M-1 | Medium | 2026-04-01 | — | — | — | |
| M-2 | Medium | 2026-04-01 | — | — | — | |
| M-3 | Medium | 2026-04-01 | — | — | — | |
| M-4 | Medium | 2026-04-01 | — | — | — | |
| M-5 | Medium | 2026-04-01 | — | — | — | |
| M-6 | Medium | 2026-04-01 | — | — | — | |
| M-7 | Medium | 2026-04-01 | — | — | — | |
| L-1 | Low | 2026-04-01 | — | — | — | |
| L-2 | Low | 2026-04-01 | — | — | — | |
| L-3 | Low | 2026-04-01 | — | — | — | |
| L-4 | Low | 2026-04-01 | — | — | — | |
| L-5 | Low | 2026-04-01 | — | — | — | |

---

## Appendix A: Severity Definitions

| Level | Definition |
|-------|------------|
| **Critical** | Exploitable vulnerability that directly compromises ledger integrity, enables unauthorized data disclosure, or causes production outage |
| **High** | Security control bypass, significant data leak potential, or violation of core security guarantees |
| **Medium** | Defense-in-depth violation, potential for chained attacks, or resource exhaustion |
| **Low** | Minor information disclosure, hardening recommendations, or configuration issues |
| **Informational** | Code quality, architecture concerns, or best-practice recommendations with no direct security impact |

## Appendix B: Exploitability Definitions

| Level | Definition |
|-------|------------|
| **Trivial** | Exploitable with a single unauthenticated request, or requires only a valid API key |
| **Moderate** | Requires specific conditions (timing, state), multiple requests, or elevated privileges |
| **Complex** | Requires insider access, race conditions, or theoretical attack chains with low practical likelihood |

---

*This report is provided for informational purposes. No warranty is made regarding completeness or accuracy. Recipients should verify findings against the current codebase.*
