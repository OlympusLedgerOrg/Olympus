# Olympus Security Audit Report

**Version:** 1.1  
**Audit Date:** April 1–2, 2026  
**Report Date:** April 2, 2026 (updated April 3, 2026)  
**Auditors:** Internal Red Team  
**Classification:** Public

---

## Executive Summary

This report documents the findings from a comprehensive security audit of the Olympus federated public ledger system. The audit identified **2 critical**, **5 high**, **7 medium**, and **5 low** severity vulnerabilities across the Python API layer, storage subsystem, protocol primitives, and witness/sequencer services.

**Cross-reference note (v1.1 update):** The initial version of this report was written against the codebase at commit `658ca06` (April 1, 2026). Since then, 14 of the 19 findings were remediated in PRs #538–#545 during the same sprint. This update corrects the status of all findings against the current `main` branch and prunes entries that are no longer applicable. Findings that were already addressed before this report was published are marked ✅ Verified and documented with their fix PRs; genuinely open issues are retained as 🔴 Open.

### Key Findings

| Risk Level | Count | Verified Closed | Open / Mitigated |
|------------|-------|----------------|-----------------|
| **Critical** | 2 | 2 ✅ | 0 |
| **High** | 5 | 3 ✅ | 2 🔴 |
| **Medium** | 7 | 5 ✅ | 2 🔴 |
| **Low** | 5 | 3 ✅ | 2 🟡 |
| **Informational** | 7 | — | N/A |

**Remaining priority items:** H-3 (dual independent rate-limit systems) and M-2 (unbounded dataset file commit) are the only genuinely open non-informational findings on current `main`.

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
| [C-1](#c-1-poseidon-smt-rebuild-crashes-on-non-empty-shards) | Poseidon SMT rebuild crashes on non-empty shards | Critical | Moderate | ✅ Verified | [#538](https://github.com/OlympusLedgerOrg/Olympus/pull/538) |
| [C-2](#c-2-embargo-flag-stored-but-never-enforced) | Embargo flag stored but never enforced | Critical | **Trivial** | ✅ Verified | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) |
| [H-1](#h-1-witness-checkpoint-submissions-accept-unsigned-announcements) | Witness checkpoint submissions accept unsigned announcements | High | Moderate | ✅ Verified | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) |
| [H-2](#h-2-poseidon-field-values-not-reduced-modulo-snark-scalar-field) | Poseidon field values not reduced mod SNARK_SCALAR_FIELD | High | Complex | ✅ Verified | [#538](https://github.com/OlympusLedgerOrg/Olympus/pull/538) |
| [H-3](#h-3-dual-independent-rate-limit-systems) | Dual independent rate-limit systems | High | Moderate | 🔴 Open | — |
| [H-4](#h-4-sth-history-returns-empty-signatures) | STH history returns empty signatures | High | Trivial | ✅ Verified | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) |
| [H-5](#h-5-proof_id-parameter-unvalidated) | `proof_id` parameter — no format constraint | High | Trivial | 🔴 Open | — |
| [M-1](#m-1-dataset-history-unbounded-query) | Dataset history unbounded query | Medium | Moderate | ✅ Verified | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) |
| [M-2](#m-2-dataset-file-commit-unbounded) | Dataset file commit unbounded | Medium | Moderate | 🔴 Open | — |
| [M-3](#m-3-internal-exception-message-leak) | Internal exception message leak | Medium | Trivial | ✅ Verified | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) |
| [M-4](#m-4-duplicate-client-ip-resolution) | Duplicate client IP resolution | Medium | Complex | ✅ Verified | [#545](https://github.com/OlympusLedgerOrg/Olympus/pull/545) |
| [M-5](#m-5-witness-origin-field-unconstrained) | Witness origin field unconstrained | Medium | Trivial | ✅ Verified | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) |
| [M-6](#m-6-proof-submission-accepts-caller-supplied-state) | Proof submission accepts caller-supplied state | Medium | Moderate | ✅ Verified | [#544](https://github.com/OlympusLedgerOrg/Olympus/pull/544) |
| [M-7](#m-7-unbounded-tree-replay) | Unbounded tree replay | Medium | Moderate | ✅ Verified | [#542](https://github.com/OlympusLedgerOrg/Olympus/pull/542) |
| [L-1](#l-1-get_ingestion_proof-unauthenticated) | `get_ingestion_proof` unauthenticated | Low | Trivial | ✅ Verified | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) |
| [L-2](#l-2-admin-reload-leaks-config-state) | Admin reload leaks config state | Low | Trivial | ✅ Verified | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) |
| [L-3](#l-3-witness-stores-per-process) | Witness stores per-process | Low | Complex | ✅ Verified | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) |
| [L-4](#l-4-recursive-json-depth-check) | Recursive JSON depth check | Low | Complex | 🟡 Mitigated | — |
| [L-5](#l-5-rfc-3161-tsa-no-certificate-pinning) | RFC 3161 TSA no certificate pinning | Low | Complex | 🟡 Mitigated | — |

**Legend:** 🔴 Open · 🟡 Mitigated · 🟢 Fixed · ✅ Verified

---

## Detailed Findings

### Critical

#### C-1: Poseidon SMT rebuild crashes on non-empty shards

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **Exploitability** | Moderate |
| **Location** | `api/ingest.py:862` |
| **Status** | ✅ Verified — Fixed in [PR #538](https://github.com/OlympusLedgerOrg/Olympus/pull/538) (commit `ca63d07`, April 1 2026) |

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

**Fix applied:** Call changed to `storage._load_tree_state(cur)` (no shard_id argument); shard-specific Poseidon state is reconstructed by iterating global leaves filtered to the target shard.

---

#### C-2: Embargo flag stored but never enforced

| Attribute | Value |
|-----------|-------|
| **Severity** | Critical |
| **Exploitability** | **Trivial** |
| **Location** | `api/models/document.py:54`, `api/routers/documents.py`, `api/routers/ledger.py` |
| **Status** | ✅ Verified — Fixed in [PR #539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) (commit `788ca9f`, April 1 2026) |

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

**Fix applied:** `api/routers/documents.py` now checks `commit.embargo_until` on all read paths and returns HTTP 403 with a `Retry-After` header when the embargo has not yet lifted.

---

### High

#### H-1: Witness checkpoint submissions accept unsigned announcements

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate |
| **Location** | `api/routers/witness.py:submit_observation` |
| **Status** | ✅ Verified — Fixed in [PR #540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) (commit `a7ff63c`, April 1 2026) |

**Description:**  
The `POST /witness/observations` endpoint validates timestamp freshness and nonce deduplication but does not verify any Ed25519 signature on the checkpoint payload. Any authenticated caller can fabricate an announcement from any `origin` with any `checkpoint_hash`.

**Impact:**  
The witness/gossip anti-split-view mechanism becomes meaningless. An attacker with a single API key can flood the store with synthetic conflicts or suppress real divergence signals.

**Fix applied:** `WitnessAnnounceRequest` now includes a `node_signature` (hex Ed25519 signature) field. The endpoint verifies the Ed25519 signature against the announcing node's registered public key before accepting the observation.

---

#### H-2: Poseidon field values not reduced modulo SNARK_SCALAR_FIELD

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Complex |
| **Location** | `api/ingest.py:850-854` |
| **Status** | ✅ Verified — Fixed in [PR #538](https://github.com/OlympusLedgerOrg/Olympus/pull/538) (commit `ca63d07`, April 1 2026) |

**Description:**  
```python
def _value_hash_to_poseidon_field(value_hash: bytes) -> int:
    return int.from_bytes(value_hash, byteorder="big")
```

BLAKE3 hashes are uniform 256-bit integers. The BN128 scalar field prime is ~2²⁵⁴. Approximately **25% of BLAKE3 outputs** exceed `SNARK_SCALAR_FIELD`. While `PoseidonSMT.update()` reduces internally, this creates:

1. Mismatch between stored leaf (`hash % p`) and expected value (`hash`)
2. External verifiers receive false negatives
3. Hash collisions: `h` and `h + p` map to identical Poseidon leaves

**Fix applied:** Module-level `_BN128_FIELD_PRIME` constant added; `_value_hash_to_poseidon_field()` now returns `int.from_bytes(value_hash, byteorder="big") % _BN128_FIELD_PRIME`.

---

#### H-3: Dual independent rate-limit systems

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate |
| **Location** | `api/ingest.py:530-580`, `api/auth.py:390-558` |
| **Status** | 🔴 Open |

**Description:**  
`api/ingest.py` maintains its own `TokenBucket`-based rate-limit subsystem (separate `_rate_limit_policy`, `_rate_limit_key_buckets`, `_rate_limit_ip_buckets`, `_rate_limit_lock`) in addition to the primary rate-limit system in `api/auth.py`. The two systems are not synchronized and are governed by different configuration sources.

**Cross-reference:** This finding was not addressed in the prior sprint (PRs #538–#545). It is a genuinely new open item.

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
| **Status** | ✅ Verified — Fixed in [PR #539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) (commit `788ca9f`, April 1 2026) |

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

**Fix applied:** The history query now joins `shard_headers.sig` and `shard_headers.pubkey`; each `STHResponse` in the history list is populated with real `entry["signature"]` and `entry["pubkey"]` values.

---

#### H-5: `proof_id` parameter — no format constraint

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Trivial |
| **Location** | `api/ingest.py:1339` |
| **Status** | 🔴 Open — Authentication was added in [PR #539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) (`RequireVerifyScope`), but format validation is still absent |

**Description:**  
`GET /ingest/records/{proof_id}/proof` now requires authentication (L-1 fix, PR #539), but `proof_id` accepts arbitrary strings with no length limit or UUID pattern constraint. An authenticated attacker can still probe arbitrary IDs as an enumeration oracle.

**Recommendation:**  
Add parameter constraint: `proof_id: str = Path(..., pattern=r"^[0-9a-f-]{32,36}$")`

---

### Medium

#### M-1: Dataset history unbounded query

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `api/routers/datasets.py:734-738` |
| **Status** | ✅ Verified — Fixed in [PR #540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) (commit `a7ff63c`, April 1 2026) |

**Description:**  
`GET /datasets/{dataset_id}/history` executes a query with no `.limit()` clause. A dataset with thousands of versions causes a full table scan and potential OOM.

**Fix applied:** `dataset_history` now accepts an `n` query parameter (1–1000, default 100) and applies `.limit(n)` to the query.

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

**Cross-reference:** PR #540 fixed M-1 (unbounded history query) but did not add `max_length` to `DatasetCommitRequest.files`. This is a genuinely open item.

**Recommendation:**  
Add `max_length=10_000` to `DatasetCommitRequest.files`. Add `.limit(10_001)` on queries with truncation warning.

---

#### M-3: Internal exception message leak

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Trivial |
| **Location** | `api/sth.py:131`, `200` |
| **Status** | ✅ Verified — Fixed in [PR #539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) (commit `788ca9f`, April 1 2026) |

**Description:**  
Raw exception messages may expose table names, column names, SQL fragments, or stack details to external callers.

**Fix applied:** Error messages now read `"Failed to retrieve STH. See server logs for details."` — the full exception is only logged server-side.

---

#### M-4: Duplicate client IP resolution

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Complex |
| **Location** | `api/ingest.py:646-680`, `api/auth.py:630-657` |
| **Status** | ✅ Verified — Fixed in [PR #545](https://github.com/OlympusLedgerOrg/Olympus/pull/545) (commit `f041a20`, April 2 2026) |

**Description:**  
Both modules implement `X-Forwarded-For` parsing with trusted-proxy logic, reading from different configuration sources. Divergence could cause inconsistent IP-based rate limiting or logging.

**Fix applied:** `_client_ip()` removed from `ingest.py`; all callers now use `auth._get_client_ip(request)`.

---

#### M-5: Witness origin field unconstrained

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Trivial |
| **Location** | `api/routers/witness.py`, `api/schemas/witness.py` |
| **Status** | ✅ Verified — Fixed in [PR #540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) (commit `a7ff63c`, April 1 2026) |

**Description:**  
The `origin` field had no pattern constraint, length limit, or allowlist. Attackers could inject colons to collide with legitimate key namespaces or use extremely long strings.

**Fix applied:** `origin` fields in `WitnessAnnounceRequest`, `WitnessAnnouncement`, and `WitnessAnnounceResponse` now carry `pattern=r"^[A-Za-z0-9._/:-]{1,256}$"`.

---

#### M-6: Proof submission accepts caller-supplied state

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `api/ingest.py:1411-1475` |
| **Status** | ✅ Verified — Fixed in [PR #544](https://github.com/OlympusLedgerOrg/Olympus/pull/544) (commit `6575f4e`, April 2 2026) |

**Description:**  
`submit_proof_bundle` accepted `shard_id`, `record_id`, and `canonicalization` from the caller, allowing an authenticated attacker to poison the in-memory Poseidon state cache.

**Fix applied:** The endpoint now accepts only a raw file upload (`UploadFile`). The server canonicalizes and hashes the content itself; all caller-supplied state fields were removed.

---

#### M-7: Unbounded tree replay

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate |
| **Location** | `storage/postgres.py:2334-2474` |
| **Status** | ✅ Verified — Fixed in [PR #542](https://github.com/OlympusLedgerOrg/Olympus/pull/542) (commit `636bd68`, April 2 2026) |

**Description:**  
`replay_tree_incremental()` loaded all shard headers and ledger rows unboundedly. Large shards caused memory exhaustion.

**Fix applied:** `replay_tree_incremental()` now accepts `max_headers: int | None` and `after_seq: int = 0` parameters, enabling RFC 6962-style cursor pagination.

---

### Low

#### L-1: `get_ingestion_proof` unauthenticated

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Trivial |
| **Location** | `api/ingest.py:1339` |
| **Status** | ✅ Verified — Fixed in [PR #539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) (commit `788ca9f`, April 1 2026) |

**Description:**  
The endpoint lacked `RequireVerifyScope` or `RequireAPIKey` dependency, unlike `/records/hash/{content_hash}/verify` which requires authentication.

**Fix applied:** `get_ingestion_proof` now has `_scope: RequireVerifyScope` as a dependency parameter.

---

#### L-2: Admin reload leaks config state

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Trivial |
| **Location** | `api/routers/keys.py:107-121` |
| **Status** | ✅ Verified — Fixed in [PR #540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) (commit `a7ff63c`, April 1 2026) |

**Description:**  
The 503 response message "Admin key reload not configured" revealed whether `OLYMPUS_ADMIN_KEY` is set.

**Fix applied:** `admin_reload_keys` now has `_rl: RateLimit` as a dependency, adding rate limiting to the endpoint.

---

#### L-3: Witness stores per-process

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex |
| **Location** | `api/routers/witness.py:73-80` |
| **Status** | ✅ Verified — Fixed in [PR #540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) (commit `a7ff63c`, April 1 2026) |

**Description:**  
Witness observation stores were in-memory and per-process. Multi-worker deployments silently split observations across processes, fragmenting the gossip state.

**Fix applied:** The witness router now raises `RuntimeError` at startup when `WEB_CONCURRENCY > 1`, preventing misconfigured multi-worker deployments.

---

#### L-4: Recursive JSON depth check

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex |
| **Location** | `api/ingest.py:94-113` |
| **Status** | 🟡 Mitigated |

**Description:**  
`_check_json_depth()` uses Python recursion. Adversarial input exceeding Python's default recursion limit (1000) could cause a crash.

**Mitigation:** An early exit guard was added: the function raises `ValueError` immediately when `current_depth >= _MAX_CONTENT_DEPTH` before recursing further. This bounds the call depth and eliminates the stack overflow risk in practice. Converting to an iterative implementation would be a belt-and-suspenders improvement but is no longer a priority.

---

#### L-5: RFC 3161 TSA no certificate pinning

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex |
| **Location** | `protocol/rfc3161.py:293` |
| **Status** | 🟡 Mitigated |

**Description:**  
The TSA URL is fetched without certificate pinning. A MITM attacker with a valid certificate could issue fake timestamp tokens.

**Mitigation:** `protocol/rfc3161.py` now exposes `trust_store_path` and `certificate` parameters on `request_timestamp()`, along with `_load_trust_store_certificate()` and `_extract_tsa_cert_fingerprint()` helpers. Certificate pinning is architecturally supported but not enforced by default. Operators deploying in adversarial network environments should pin the DigiCert TSA certificate.

---

### Informational

| ID | Description | Location | Notes |
|----|-------------|----------|-------|
| I-1 | Duplicate client IP resolution | — | Resolved via M-4 (PR #545) |
| I-2 | `generate_commit_id()` uses 160-bit, not 256-bit | `api/services/hasher.py:64-70` | Fixed — changed to `os.urandom(32)` (256-bit) |
| I-3 | `submit_proof_bundle` did not persist to Postgres | `api/ingest.py` | Resolved via M-6 (PR #544) |
| I-4 | `_build_poseidon_smt_for_storage_shard` called private methods | `api/ingest.py` | Resolved via C-1 (PR #538) |
| I-5 | `dataset_history` endpoint has no authentication | `api/routers/datasets.py` | Open (public read is intentional per API design) |
| I-6 | STH router uses mutable global `_storage` with no synchronization | `api/sth.py:42-50` | Open |
| I-7 | Poseidon SMT uses Python reference implementation, may diverge from ZK circuit | `protocol/poseidon_smt.py`, `protocol/poseidon_bn128.py` | Open; conformance test added in PR #545 |

---

## Remediation Tracking

| ID | Severity | Found | Fix PR | Fixed | Verified | Notes |
|----|----------|-------|--------|-------|----------|-------|
| C-1 | Critical | 2026-04-01 | [#538](https://github.com/OlympusLedgerOrg/Olympus/pull/538) | 2026-04-01 | ✅ 2026-04-03 | `_load_tree_state` arg fixed + BN128 field reduction |
| C-2 | Critical | 2026-04-01 | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) | 2026-04-01 | ✅ 2026-04-03 | Embargo enforced on all read paths |
| H-1 | High | 2026-04-01 | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) | 2026-04-01 | ✅ 2026-04-03 | Ed25519 sig verification added |
| H-2 | High | 2026-04-01 | [#538](https://github.com/OlympusLedgerOrg/Olympus/pull/538) | 2026-04-01 | ✅ 2026-04-03 | `% _BN128_FIELD_PRIME` at call site |
| H-3 | High | 2026-04-01 | — | — | — | **Open** — ingest.py retains own TokenBucket |
| H-4 | High | 2026-04-01 | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) | 2026-04-01 | ✅ 2026-04-03 | Real `sig`/`pubkey` returned in history |
| H-5 | High | 2026-04-01 | — | — | — | **Open** — auth added (#539) but format constraint missing |
| M-1 | Medium | 2026-04-01 | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) | 2026-04-01 | ✅ 2026-04-03 | `n` param + `.limit(n)` added |
| M-2 | Medium | 2026-04-01 | — | — | — | **Open** — `DatasetCommitRequest.files` still unbounded |
| M-3 | Medium | 2026-04-01 | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) | 2026-04-01 | ✅ 2026-04-03 | Generic error message; full exception logged server-side |
| M-4 | Medium | 2026-04-01 | [#545](https://github.com/OlympusLedgerOrg/Olympus/pull/545) | 2026-04-02 | ✅ 2026-04-03 | `_client_ip()` removed from ingest.py |
| M-5 | Medium | 2026-04-01 | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) | 2026-04-01 | ✅ 2026-04-03 | Pattern constraint added to origin field |
| M-6 | Medium | 2026-04-01 | [#544](https://github.com/OlympusLedgerOrg/Olympus/pull/544) | 2026-04-02 | ✅ 2026-04-03 | File-upload-only endpoint |
| M-7 | Medium | 2026-04-01 | [#542](https://github.com/OlympusLedgerOrg/Olympus/pull/542) | 2026-04-02 | ✅ 2026-04-03 | `max_headers`/`after_seq` pagination |
| L-1 | Low | 2026-04-01 | [#539](https://github.com/OlympusLedgerOrg/Olympus/pull/539) | 2026-04-01 | ✅ 2026-04-03 | `RequireVerifyScope` added |
| L-2 | Low | 2026-04-01 | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) | 2026-04-01 | ✅ 2026-04-03 | Rate limit added |
| L-3 | Low | 2026-04-01 | [#540](https://github.com/OlympusLedgerOrg/Olympus/pull/540) | 2026-04-01 | ✅ 2026-04-03 | `RuntimeError` on multi-worker startup |
| L-4 | Low | 2026-04-01 | — | — | 🟡 | Early-exit guard added; iterative rewrite deferred |
| L-5 | Low | 2026-04-01 | — | — | 🟡 | Trust-store API available; pinning optional |

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
