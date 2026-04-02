# Security Audit Issues - ToB-Style Red Team Audit

**Date:** 2026-04-01  
**Scope:** Full codebase — Python API, storage layer, protocol primitives, witness/sequencer services, Rust/Go services

---

## CRITICAL

### C-1: `_build_poseidon_smt_for_storage_shard` passes `shard_id` where `up_to_ts` is expected

**File:** `api/ingest.py:862`

**Summary:**  
`_build_poseidon_smt_for_storage_shard` passes `shard_id` as the second argument to `StorageLayer._load_tree_state()`, but that function only accepts `up_to_ts` as its second argument.

```python
tree = storage._load_tree_state(cur, shard_id)
```

**Impact:**  
When `up_to_ts` is not `None`, the code calls `datetime.fromisoformat(cutoff.replace("Z", "+00:00"))` which will raise `ValueError`. Every ingest request that hits the PostgreSQL path (non-deduplicated records) will crash with a 500 error when the Poseidon SMT is rebuilt for an existing shard.

**Proof-of-exploit:** Ingest any record to an existing shard after any restart that evicts the in-memory Poseidon state.

**Fix:** The call should be `storage._load_tree_state(cur)` (global tree) and the iteration should use `global_key`-filtered leaves to reconstruct only that shard's Poseidon state.

---

### C-2: Embargo flag is stored but never enforced

**Files:** `api/models/document.py:54`, `api/routers/documents.py`, `api/routers/ledger.py`, `api/services/verification.py`, `api/services/ingestion.py`

**Summary:**  
`DocCommit.embargo_until` is accepted at commit time, persisted, and documented, but **no read path filters on it**. Calls to `GET /ledger/proof/{commit_id}`, `POST /doc/verify`, `GET /ledger/shard/{shard_id}`, and `POST /ledger/verify/simple` all return full document data for embargoed records without any time check.

**Impact:** Any document committed with an embargo date can be retrieved immediately by any party before the embargo lifts. If agencies use this feature for pre-release materials, this is a disclosure vulnerability.

**Fix:** Add a `.where(or_(DocCommit.embargo_until.is_(None), DocCommit.embargo_until <= datetime.now(timezone.utc)))` guard on all read paths, or return 403 with a `retry-after` header.

---

## HIGH

### H-1: Witness checkpoint submissions accept unsigned announcements

**File:** `api/routers/witness.py:submit_observation`

**Summary:**  
The `POST /witness/observations` endpoint validates timestamp freshness and nonce deduplication but does **not verify any Ed25519 signature** on the checkpoint payload. Any authenticated caller can fabricate an announcement from any `origin` with any `checkpoint_hash`, poisoning the gossip state.

**Impact:** The entire witness/gossip anti-split-view mechanism can be defeated or monopolized by any API key holder.

**Fix:** Add a `checkpoint_signature: str` field to `WitnessAnnounceRequest` and a `signer_pubkey: str` field. Verify the Ed25519 signature over the canonical serialization of the checkpoint before storing.

---

### H-2: Poseidon field values NOT reduced modulo `SNARK_SCALAR_FIELD`

**File:** `api/ingest.py:850-854`

**Summary:**  
```python
def _value_hash_to_poseidon_field(value_hash: bytes) -> int:
    return int.from_bytes(value_hash, byteorder="big")
```

BLAKE3 hashes are uniform-random 256-bit integers. The BN128 scalar field prime is ~2^254. Approximately **25% of all BLAKE3 hashes** are ≥ `SNARK_SCALAR_FIELD`. While `PoseidonSMT.update()` reduces internally, this causes:
1. The Poseidon leaf stored is `hash % p`, not `hash`
2. External verifiers get false negatives
3. Two different hashes `h` and `h + p` create a **collision**

**Fix:** Reduce at the call site: `return int.from_bytes(value_hash, byteorder="big") % SNARK_SCALAR_FIELD`

---

### H-3: Dual independent rate-limit systems can desync

**Files:** `api/ingest.py:535-765`, `api/auth.py:390-558`

**Summary:**  
`api/ingest.py` and `api/auth.py` both maintain separate in-memory token buckets for rate limiting.

**Impact:**
- Ingest-module limits are separate from auth-module limits
- An attacker can exhaust one while the other is independent
- Key-reload operations don't reset ingest rate-limit state
- Configuration env vars only affect one module

**Fix:** Consolidate to a single rate-limit system.

---

### H-4: STH history endpoint returns empty signature/pubkey

**File:** `api/sth.py:161-165`

**Summary:**  
Historical STH entries expose root hash and sequence but omit the signature, making the tamper-evidence guarantee unverifiable.

```python
sths.append(STHResponse(
    ...
    signature="",      # ← deliberately empty
    signer_pubkey="",  # ← deliberately empty
))
```

**Impact:** A log operator could serve a silently forked history with no cryptographic evidence.

**Fix:** Join `shard_headers.sig` and `shard_headers.pubkey` in the history query.

---

### H-5: `proof_id` path parameter has no format validation

**File:** `api/ingest.py:1334-1352`

**Summary:**  
`proof_id` accepts arbitrary strings with no length limit, pattern restriction, or UUID validation. The endpoint has **no authentication**.

**Impact:** Enumeration oracle, potential path traversal testing.

**Fix:** Add `Path(..., pattern=r"^[0-9a-f-]{32,36}$")` constraint.

---

## MEDIUM

### M-1: `GET /datasets/{dataset_id}/history` is unbounded

**File:** `api/routers/datasets.py:734-738`

**Summary:**  
```python
result = await db.execute(
    select(DatasetArtifact)
    .where(DatasetArtifact.dataset_id == dataset_id)
    .order_by(DatasetArtifact.epoch_timestamp.asc())
)  # NO .limit()
rows = result.scalars().all()
```

A dataset with thousands of versions causes a full table scan.

**Fix:** Add `.limit(500)` and expose `page`/`per_page` query parameters.

---

### M-2: Dataset file fetch unbounded, no max files on commit

**Files:** `api/routers/datasets.py:427-430`, `648-650`

**Summary:**  
A dataset artifact committed with 100,000 file entries will load all rows unboundedly.

**Fix:** Add `max_length=10_000` to `DatasetCommitRequest.files`, and add `.limit(10_001)` with truncation warning.

---

### M-3: Internal exception message leak in `api/sth.py`

**File:** `api/sth.py:131`, `200`

**Summary:**  
```python
raise HTTPException(
    status_code=500,
    detail=f"Failed to get latest STH: {str(e)}",
)
```

Raw exception messages expose table names, column names, SQL fragments, or stack details.

**Fix:** Log server-side and return a generic message.

---

### M-4: Duplicate `_client_ip()` implementations can diverge

**Files:** `api/ingest.py:646-680`, `api/auth.py:630-657`

**Summary:**  
Both modules implement X-Forwarded-For parsing with trusted-proxy logic, reading from different sources.

**Fix:** Delete `_client_ip()` from `ingest.py` and call `auth._get_client_ip(request)`.

---

### M-5: No validation of `origin` field in witness observations

**Files:** `api/routers/witness.py`, `api/schemas/witness.py`

**Summary:**  
`origin` has no pattern constraint, no length limit, and no allowlist. Attackers can inject colons to collide with valid keys, or use extremely long strings.

**Fix:** Add `pattern=r"^[A-Za-z0-9._:-]{1,128}$"` to the `origin` field.

---

### M-6: `submit_proof_bundle` uses externally supplied values for Poseidon state

**File:** `api/ingest.py:1411-1475`

**Summary:**  
`shard_id`, `record_id`, and `canonicalization` are caller-supplied. A caller with a valid API key can poison the in-memory Poseidon state.

**Fix:** Validate that the submitted `content_hash` maps to an existing shard before accepting.

---

### M-7: Unbounded full tree replay for large shards

**File:** `storage/postgres.py:2334-2474`

**Summary:**  
`replay_tree_incremental` and `verify_state_replay` load all shard headers and ledger rows unboundedly.

**Fix:** Add circuit breakers or paging to streaming replay.

---

## LOW

### L-1: `get_ingestion_proof` endpoint is unauthenticated

**File:** `api/ingest.py:1334-1352`

**Summary:**  
No `RequireVerifyScope` or `RequireAPIKey` dependency, contrasting with `/records/hash/{content_hash}/verify` which does require auth.

---

### L-2: `admin_reload_keys` leaks config state via status codes

**File:** `api/routers/keys.py:107-121`

**Summary:**  
The 503 response "Admin key reload not configured" tells an attacker that `OLYMPUS_ADMIN_KEY` is not set.

**Fix:** Add rate limiting to `admin_reload_keys`.

---

### L-3: Witness stores are per-process, not safe for multi-worker

**File:** `api/routers/witness.py:73-80`

**Summary:**  
A deployment with multiple workers silently splits witness observations across processes.

**Fix:** Block startup with `RuntimeError` when `WEB_CONCURRENCY > 1`.

---

### L-4: `_check_json_depth` uses Python recursion

**File:** `api/ingest.py:94-113`

**Summary:**  
The depth check recurses through nested dicts and lists, potentially hitting Python's recursion limit with adversarial input.

---

### L-6: RFC 3161 TSA invoked without certificate pinning

**File:** `api/routers/datasets.py:226-236`

**Summary:**  
The TSA URL is fetched without certificate pinning or HSTS. A MITM with a valid certificate can issue fake timestamp tokens.

---

## INFORMATIONAL

### I-1: Two separate client IP resolution functions use different configuration sources
Already noted in M-4.

### I-2: `generate_commit_id()` uses 160-bit, not 256-bit
**File:** `api/services/hasher.py:64-70`

### I-3: `submit_proof_bundle` does not persist to Postgres
**File:** `api/ingest.py:1460`

### I-4: `_build_poseidon_smt_for_storage_shard` calls private methods
**File:** `api/ingest.py:861-862`

### I-5: `dataset_history` endpoint has no authentication
**File:** `api/routers/datasets.py:727-761`

### I-6: STH router uses mutable global `_storage` with no synchronization
**File:** `api/sth.py:42-50`

### I-7: Poseidon SMT uses Python reference implementation, may diverge from ZK circuit
**Files:** `protocol/poseidon_smt.py`, `protocol/poseidon_bn128.py`

---

## Summary Table

| ID | Severity | Area | Description |
|----|----------|------|-------------|
| C-1 | Critical | Ingest | `_build_poseidon_smt_for_storage_shard` crashes on non-empty shards |
| C-2 | Critical | Documents/Privacy | `embargo_until` stored but never enforced |
| H-1 | High | Witness | Checkpoint observations not signature-verified |
| H-2 | High | Poseidon/ZK | `_value_hash_to_poseidon_field` misses field reduction |
| H-3 | High | Rate Limiting | Dual independent rate-limit systems can desync |
| H-4 | High | STH | Historical STH entries return empty signature/pubkey |
| H-5 | High | Ingest | `proof_id` path param unvalidated, enumeration oracle |
| M-1 | Medium | Datasets | `dataset_history` unbounded query, OOM risk |
| M-2 | Medium | Datasets | Dataset file fetch unbounded, no max files on commit |
| M-3 | Medium | STH | Internal exception leak in HTTP 500 response |
| M-4 | Medium | Auth/Ingest | Duplicate IP resolution implementations can diverge |
| M-5 | Medium | Witness | `origin` field unconstrained, key collision/injection |
| M-6 | Medium | Ingest/Proofs | Proof submission uses caller-supplied values for Poseidon state |
| M-7 | Medium | Storage | Unbounded full tree replay for large shards |
| L-1 | Low | Ingest | `get_ingestion_proof` unauthenticated |
| L-2 | Low | Admin | Admin reload endpoint not rate-limited, leaks config state |
| L-3 | Low | Witness | Multi-worker witness store split silently |
| L-4 | Low | Input Validation | `_check_json_depth` recursive, potential stack issue |
| L-6 | Low | RFC 3161 | No TSA certificate pinning |
| I-1..7 | Info | Various | Architecture/design concerns, code hygiene |
