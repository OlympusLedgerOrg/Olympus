# Olympus Security Audit Report — V2 (Deep Red Team)

**Version:** 2.0  
**Audit Date:** April 3, 2026  
**Report Date:** April 3, 2026  
**Auditors:** Deep Red Team (structural / protocol-level focus)  
**Classification:** Public  
**Scope:** Ledger commitment path, transaction integrity, proof soundness, documentation accuracy

---

## Executive Summary

This report documents findings from a deep structural audit of the Olympus ledger
system, focused on whether the system **actually commits documents to the ledger**
and whether those commitments can be subverted. The audit traces the full code path
from HTTP ingestion through canonicalization, Merkle tree update, and ledger entry
persistence.

**Primary finding: The ledger commitment path is implemented and functional.** Documents
ingested via `POST /ingest/records` are atomically committed to both the CD-HS-ST
(Sparse Merkle Tree) and the append-only ledger within a single `SERIALIZABLE`
PostgreSQL transaction. There is no gap where data is ingested without being committed.

However, the audit identified **5 high-severity**, **4 medium-severity**, and
**3 low-severity** structural issues that could undermine ledger guarantees under
adversarial conditions. Additionally, significant **documentation drift** was found
where docs describe an architecture that does not match the current code.

### Key Findings

| Risk Level | Count | Fixed | Description |
|------------|-------|-------|-------------|
| **High** | 5 | 5 ✅ | All high-severity findings are now closed (RT-H1 through RT-H5) |
| **Medium** | 4 | 4 ✅ | Missing constraints, unverified hashes, documentation drift |
| **Low** | 3 | 0 | Permissive patterns, minor information leaks |
| **Documentation** | 4 | 3 ✅ | Outdated terminology, broken references, misleading architecture claims |

---

## Methodology

### Scope

**In-Scope (ledger commitment path):**
- `api/ingest.py` — Ingestion endpoints, input validation, canonicalization pipeline
- `storage/postgres.py` — `append_record()`, SMT persistence, trigger gates, ledger entries
- `protocol/ssmf.py` — Sparse Merkle Tree, existence/non-existence proofs
- `protocol/ledger.py` — Append-only chain, entry hash computation
- `protocol/hashes.py` — BLAKE3 domain-separated hashing, key derivation
- `api/auth.py` — Authentication gates on ingest path

**Approach:**
- Full code path trace: HTTP request → canonicalize → hash → tree update → ledger insert → commit
- Concurrency analysis under `SERIALIZABLE` isolation
- Proof soundness analysis (existence and non-existence)
- Transaction atomicity verification
- Documentation vs. code comparison

---

## Does It Actually Commit to the Ledger?

**Yes.** The commitment path is:

```
POST /ingest/records
  → ingest_batch() [api/ingest.py]
    → canonicalize_document() [protocol/canonical.py]
    → blake3_hash() [protocol/hashes.py]
    → storage.append_record() [storage/postgres.py]
      → BEGIN SERIALIZABLE TRANSACTION
        → _load_tree_state()           — load global SMT
        → tree.update(key, value_hash) — insert leaf
        → tree.get_root()              — compute new root
        → _persist_tree_nodes()        — write SMT node deltas
        → INSERT INTO shard_headers    — signed header with root
        → INSERT INTO ledger_entries   — chained entry with root in payload
      → COMMIT                         — atomic, all-or-nothing
```

**Verified properties:**
1. **Atomicity:** All tree updates, shard headers, and ledger entries are in one `SERIALIZABLE` transaction. Partial commits are impossible.
2. **Root binding:** The global tree root is included in the ledger entry payload and covered by the entry hash. Changing the tree retroactively would change the entry hash.
3. **Chain linkage:** Each ledger entry includes `prev_entry_hash`, creating a tamper-evident chain. The genesis entry uses empty string for `prev_entry_hash`.
4. **Signature binding:** Shard headers are Ed25519-signed and verified before persistence (post-sign verification at insert time).
5. **Trigger protection:** SMT nodes and leaves are protected by PostgreSQL trigger gates (`olympus.allow_smt_insert`, `olympus.allow_node_rehash`) that prevent direct SQL manipulation.

---

## Findings

### High Severity

#### RT-H1: Deduplication Check Outside Transaction Boundary — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate (requires concurrent requests) |
| **Location** | `api/ingest.py` — `_fetch_by_content_hash()` called before `append_record()` |
| **Status** | ✅ Fixed |
| **Fix Location** | `storage/postgres.py:_append_record_inner()` |

**Description:**
The content-hash deduplication check (`_fetch_by_content_hash()`) executes as a
separate database query **outside** the `SERIALIZABLE` transaction that performs
the actual append. Between the dedup check and the `append_record()` call, a
concurrent request can insert the same content hash.

**Call sequence:**
```
Line ~1050: existing = _fetch_by_content_hash(hash)  # OUTSIDE transaction
Line ~1081: storage.append_record(...)                 # INSIDE transaction
```

**Impact:**
Under concurrent load, two identical documents can both pass the dedup check and
both attempt `append_record()`. The second will fail on the in-memory tree check
(`"Record already exists"`) and fall through to the `except ValueError` handler,
which re-fetches the record. The client receives a successful response, but the
response may reference the *first* transaction's ledger entry rather than a
properly deduplicated result.

**Mitigating factor:** PostgreSQL `SERIALIZABLE` isolation and the `PRIMARY KEY`
constraint on `smt_leaves` prevent actual duplicate *persistence*. The issue is in
the response returned to the second client, not in ledger corruption.

**Recommendation:** Move the dedup check inside the `append_record()` transaction,
or add a `SELECT ... FOR UPDATE` advisory lock on the content hash before the
append attempt.

**Resolution:**
Added an in-transaction `SELECT key FROM smt_leaves WHERE value_hash = %s` check
inside `_append_record_inner()`, before the tree update. This check runs within
the `SERIALIZABLE` transaction, eliminating the TOCTOU race. An index on
`smt_leaves(value_hash)` was added for efficient lookups. The API error handlers
in `api/ingest.py` were updated to recognize the new error message
`"Content hash already committed"` and treat it as a deduplication event.

---

#### RT-H2: No Serialization Failure Retry on Append Path — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate (concurrent writes to same shard) |
| **Location** | `api/ingest.py` — error handling around `storage.append_record()` |
| **Status** | ✅ Fixed |
| **Fix Location** | `storage/postgres.py:append_record()` |

**Description:**
PostgreSQL `SERIALIZABLE` transactions may fail with error code `40001`
(serialization failure) when concurrent transactions conflict. The error handling
in `ingest_batch()` catches `ValueError` (application-level) but does **not**
catch `psycopg` serialization errors. A serialization failure propagates as an
unhandled HTTP 500 error.

**Impact:**
Under concurrent write load to the same shard, legitimate ingest requests will
intermittently fail with 500 errors. Clients have no indication that a retry
would succeed.

**Recommendation:** Add a retry loop (2–3 attempts with exponential backoff) for
PostgreSQL serialization failures (`40001`), or catch and return HTTP 409 Conflict
with a `Retry-After` header.

**Resolution:**
Refactored `append_record()` into an outer method with retry logic and an inner
`_append_record_inner()` method. The outer method catches
`psycopg.errors.SerializationFailure` and retries with exponential backoff
(default 3 retries, using the existing `_retry_base_delay_seconds` and
`_retry_max_delay_seconds` parameters). Retries are logged at WARNING level;
exhausted retries are logged at ERROR level before re-raising.

---

#### RT-H3: Missing UNIQUE Constraint on (shard_id, prev_entry_hash) — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Complex (requires precise timing of concurrent transactions) |
| **Location** | `storage/postgres.py` — `ledger_entries` table definition |
| **Status** | ✅ Fixed |
| **Fix Location** | `storage/postgres.py` — `ledger_entries` CREATE TABLE |

**Description:**
The `ledger_entries` table has `PRIMARY KEY (shard_id, seq)` and
`UNIQUE (entry_hash)`, but **no** `UNIQUE` constraint on
`(shard_id, prev_entry_hash)`. Under `SERIALIZABLE` isolation, two concurrent
transactions that both read the same `latest_seq` could theoretically both insert
entries claiming the same parent hash, creating a chain fork.

**Mitigating factor:** `SERIALIZABLE` isolation should detect this as a
read/write conflict and abort one transaction. Additionally, the `seq` column
appears to be monotonically assigned, making duplicate `seq` values impossible
under the existing primary key constraint. The risk is theoretical but violates
defense-in-depth principles.

**Recommendation:** Add `UNIQUE (shard_id, prev_entry_hash)` constraint as a
belt-and-suspenders defense against chain forking.

**Resolution:**
Added `CONSTRAINT ledger_entries_no_chain_fork UNIQUE (shard_id, prev_entry_hash)`
to the `ledger_entries` CREATE TABLE statement. This provides a database-level
hard guarantee against chain forking, independent of application-level isolation
semantics.

---

#### RT-H4: File Upload Memory Exhaustion Vector — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Trivial (single unauthenticated request if upload endpoint is exposed) |
| **Location** | `api/ingest.py` — `_read_upload_bounded()` |
| **Status** | ✅ Fixed |
| **Fix Location** | `api/ingest.py:_read_upload_bounded()`, `api/ingest.py:submit_proof_bundle()` |

**Description:**
The `_read_upload_bounded()` function reads file uploads in chunks and checks the
total against a maximum **after each chunk is read**. The memory is already
allocated before the limit check fires. Additionally, there is no timeout on
individual `file.read()` calls, allowing a slow-loris style attack where the
attacker sends data byte-by-byte to hold server resources indefinitely.

The final `b"".join(chunks)` call temporarily doubles memory usage during
concatenation.

**Impact:**
An attacker can exhaust server memory by sending a large file upload that
approaches but stays under the limit for many chunks before triggering the check,
or by sending data very slowly to hold connections open.

**Recommendation:** Add a `Content-Length` pre-check before reading, enforce a
per-request timeout, and consider streaming the upload directly to a hash function
rather than accumulating in memory.

**Resolution:**
The upload path now performs the recommended `Content-Length` pre-check before any
body reads in `submit_proof_bundle()`. `_read_upload_bounded()` now wraps each
chunk read in `asyncio.wait_for(...)`, caps the final read to `remaining + 1` bytes
so overflow is detected before unbounded accumulation, and appends into a single
mutable `bytearray` instead of collecting a chunk list plus a final `b"".join(...)`
copy. Timed-out and oversized uploads are closed immediately.

---

#### RT-H5: Poseidon SMT State Stale Under Concurrent Writes — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | High |
| **Exploitability** | Moderate (concurrent writes to same shard) |
| **Location** | `api/ingest.py` — `_build_poseidon_smt_for_storage_shard()` |
| **Status** | ✅ Fixed |
| **Fix Location** | `storage/postgres.py:_append_record_inner()` |

**Description:**
The Poseidon SMT is rebuilt from database state **outside** the `SERIALIZABLE`
transaction that performs the append. Between the Poseidon rebuild and the ledger
commit, another transaction can insert a new leaf, making the Poseidon root stale.

The stale `poseidon_root` is then persisted to the ledger entry. Any subsequent
verification of the Poseidon root against actual tree state will fail.

**Mitigating factor:** The BLAKE3 CD-HS-ST root (the primary commitment) is
computed inside the transaction and is always correct. The Poseidon root is used
only for ZK circuit witness generation and is not the primary integrity guarantee.

**Recommendation:** Compute Poseidon root inside the `SERIALIZABLE` transaction,
or mark it as "advisory" in the ledger entry schema with explicit documentation
that it may lag behind the BLAKE3 root.

**Resolution:**
Poseidon state is now updated inside `_append_record_inner()` during the same
`SERIALIZABLE` transaction that persists the BLAKE3 CD-HS-ST update and ledger
entry. The code loads the authoritative Poseidon sibling path from
`poseidon_smt_nodes`, performs an incremental O(log N) root update, persists the
Poseidon node deltas in-transaction, and binds the resulting authoritative
Poseidon root into the dual-root ledger commitment before commit. This removes the
rebuild-then-append staleness gap.

---

### Medium Severity

#### RT-M1: Ledger Entry Hash Not Re-Verified After Persistence — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Complex (requires subtle serialization bug) |
| **Location** | `storage/postgres.py` — ledger entry insertion |
| **Status** | ✅ Fixed |
| **Fix Location** | `storage/postgres.py:_append_record_inner()` |

**Description:**
Shard headers are verified after signing (post-sign verification before persist),
but ledger entry hashes are computed and persisted without re-verification. If a
subtle bug in `canonical_json_encode()` or `create_dual_root_commitment()` produces
inconsistent output, the stored hash will not match a recomputation, and the chain
will appear corrupted on verification.

**Recommendation:** Add a post-compute verification step for ledger entry hashes,
analogous to the existing shard header verification.

**Remediation:** Post-persist SELECT-and-recompute verification added in
`storage/postgres.py` for both dual-root (Poseidon) and legacy entry hash
paths. After inserting a ledger entry, the code performs a `SELECT` of the
persisted row, re-parses the stored payload, recomputes the hash, and raises
`RuntimeError` on mismatch.

---

#### RT-M2: Tree State Load Unbounded for Historical Replay

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Moderate (attacker inserts many records, then triggers audit) |
| **Location** | `storage/protocol_state.py` — `load_tree_state()` |
| **Status** | ✅ Fixed |

**Description:**
The `load_tree_state()` function loaded **all** SMT leaves into memory for tree
reconstruction. For a shard with millions of leaves, this could exhaust available
memory. The incremental tree reconstruction (ADR-0001) addressed this for the
forward path, but historical replay still loaded all leaves.

**Cross-reference:** This is related to finding M-7 in the
[V1 audit report](SECURITY_AUDIT_REPORT.md), which was marked as verified fixed.
The fix introduced paginated reconstruction for the forward path but did not
address the historical replay case.

**Recommendation:** Extend ADR-0001's incremental approach to historical replays,
or enforce a maximum replay window.

**Fix applied:** `load_tree_state()` now uses `fetchmany(batch_size)` (default
10 000 rows) instead of `fetchall()`, bounding peak memory to O(batch_size)
rows regardless of total leaf count. A `batch_size` parameter is exposed for
caller control.

---

#### RT-M3: Trigger Gate Value Is Deterministic and Discoverable — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Complex (requires DB access + knowledge of gate computation) |
| **Location** | `storage/postgres.py:77` — `_NODE_REHASH_GATE` |
| **Status** | ✅ Fixed |
| **Fix Location** | `storage/gates.py:derive_node_rehash_gate()` |

**Description:**
The session variable gate (`_NODE_REHASH_GATE`) is computed as
`blake3("OLY:NODE-REHASH-GATE:V1").hexdigest()`. This is deterministic and
publicly discoverable from the source code. An attacker with direct database
access (e.g., compromised DB credentials) can set the session variable and
bypass the trigger protection to insert or modify SMT nodes directly.

**Mitigating factor:** An attacker with direct DB access can already do
significant damage regardless of trigger gates. The gates are defense-in-depth
against accidental modification, not against a fully compromised database.
Additionally, `SERIALIZABLE` isolation provides additional detection capability.

**Recommendation:** Consider mixing in a deployment-specific secret (e.g.,
from environment variable) to the gate computation, so the value is not
derivable from source code alone.

**Remediation:** Production deployments now require
`OLYMPUS_NODE_REHASH_GATE_SECRET`. The gate value mixes the secret with the
domain prefix, making it non-derivable from source code. Development
environments retain the deterministic fallback with a logged warning.

---

#### RT-M4: Non-Existence Proof Verification Checks Mathematical Consistency Only — ✅ FIXED

| Attribute | Value |
|-----------|-------|
| **Severity** | Medium |
| **Exploitability** | Complex (attacker needs valid root hash) |
| **Location** | `protocol/ssmf.py` — `verify_nonexistence_proof()` |
| **Status** | ✅ Fixed |
| **Fix Location** | `protocol/ssmf.py`, `tools/verify_cli.py`, `verifiers/cli/verify.py` |

**Description:**
Non-existence proof verification starts from `EMPTY_HASHES[0]` (the empty leaf
sentinel) and reconstructs the root using the provided sibling hashes. It then
checks that the reconstructed root matches the proof's `root_hash`. This proves
mathematical consistency but does not independently verify that the root hash is
an **authentic** root (i.e., signed by an authorized party).

A verifier who accepts a non-existence proof must also verify that `proof.root_hash`
matches a signed shard header. If the verifier skips this step, an attacker can
construct a fake non-existence proof against any fabricated root.

**Mitigating factor:** The verification bundle format (`schemas/verification_bundle.json`)
includes both the proof and the signed shard header. The `tools/verify_cli.py` tool
verifies both. The vulnerability only applies if a caller uses `verify_nonexistence_proof()`
in isolation without checking the root against a signed header.

**Recommendation:** Add a docstring warning to `verify_nonexistence_proof()` that
callers MUST verify the root hash against a signed header. Consider adding an
optional `expected_root` parameter that, when provided, is checked before
proof reconstruction.

**Remediation:** `verify_nonexistence_proof()` and `verify_existence_proof()` now
accept an optional `expected_root` parameter. When provided, the proof root is
checked against the expected value before path reconstruction.
`verify_unified_proof()` passes the parameter through to the underlying function.
`tools/verify_cli.py` extracts the root from signed shard headers in verification
bundles automatically. `verifiers/cli/verify.py` supports `--expected-root` for
standalone verification.

---

### Low Severity

#### RT-L1: Shard ID Pattern Allows Characters That Could Cause Log Injection

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Trivial |
| **Location** | `api/ingest.py` — shard ID validation pattern |

**Description:**
The shard ID validation pattern `^[a-zA-Z0-9_./:@+\-]+$` allows `/` and `:`
characters, which could cause confusion in log parsing, URL construction, or
metric label injection. All database queries use parameterized statements, so
SQL injection is not possible.

**Recommendation:** Document the allowed character set in the API specification.
Consider restricting to `^[a-zA-Z0-9_.\-:]+$` (removing `/`, `@`, `+`).

**Status:** Fixed — shard IDs now use `.` as namespace separator (e.g.
`records.city-a` instead of `records/city-a`). The validation pattern
`^[a-zA-Z0-9_.:\-]+$` already excludes `/`, `@`, and `+`.

---

#### RT-L2: Token Expiration Check Not Constant-Time

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Complex (requires precise timing measurement) |
| **Location** | `api/auth.py` — token expiration check |

**Description:**
The API key lookup uses constant-time comparison, but the subsequent expiration
check (`datetime.now(UTC) >= record.expires_at`) is not constant-time. An
attacker could theoretically distinguish between "valid key, not expired" and
"valid key, expired" by measuring response times.

**Mitigating factor:** The timing difference is on the order of nanoseconds and
is dwarfed by network jitter. Practical exploitation would require thousands
of measurements and local network access.

**Recommendation:** Move expiration check into the constant-time lookup path,
or accept the risk given the impracticality of exploitation.

**Status:** Fixed — expiration check moved into `_constant_time_lookup()` so
that the timing of the response no longer varies based on expiration state.

---

#### RT-L3: Error Responses May Leak Internal State

| Attribute | Value |
|-----------|-------|
| **Severity** | Low |
| **Exploitability** | Trivial |
| **Location** | `api/ingest.py` — error handlers |

**Description:**
Some error paths include internal details in HTTP error responses (e.g., the
specific ValueError message from `append_record()`). While this aids debugging,
it could reveal internal state to an attacker probing the API.

**Cross-reference:** Related to M-3 in the
[V1 audit report](SECURITY_AUDIT_REPORT.md). The fix addressed exception messages
in most paths but some remain in the ingest batch handler.

**Recommendation:** Ensure all error responses on the ingest path use generic
messages, logging detailed errors server-side only.

---

## Documentation Findings

### DOC-1: EXECUTIVE_SUMMARY.md Describes Obsolete Architecture

| Attribute | Value |
|-----------|-------|
| **Severity** | Documentation |
| **Status** | 🟢 Fixed in this report's accompanying commit |

**Description:**
The executive summary described the system as using a "Sharded Sparse Merkle
Forest (SSMF)" with separate per-shard trees and a forest tree. The actual
implementation uses the CD-HS-ST (Constant-Depth Hierarchical Sparse Tree) —
a single global 256-level SMT with shard identity encoded in the key.

**Fix applied:** Rewrote the architecture section to accurately describe the
CD-HS-ST model, including the composite key scheme and the rationale for
replacing the two-tree model.

---

### DOC-2: QUICKSTART.md References Non-Existent Documentation Files

| Attribute | Value |
|-----------|-------|
| **Severity** | Documentation |
| **Status** | 🟢 Fixed in this report's accompanying commit |

**Description:**
QUICKSTART.md referenced `docs/00_overview.md` and `docs/04_ledger_protocol.md`,
neither of which exist. The `docs/` directory contains only
`SECURITY_AUDIT_REPORT.md` and `adr/0001-incremental-tree-reconstruction.md`.

**Fix applied:** Updated references to point to existing files (`README.md`,
`ARCHITECTURE.md`).

---

### DOC-3: README.md Service Layer Diagram Implies Go/Rust Are Primary Path

| Attribute | Value |
|-----------|-------|
| **Severity** | Documentation |
| **Status** | 🟢 Fixed in this report's accompanying commit |

**Description:**
The README.md service layer diagram and the statement "Go never computes Merkle
hashes itself" imply that the Go sequencer and Rust CD-HS-ST service are the
active write path. In reality, the Python API directly manages the SMT and ledger
via `storage/postgres.py`. The Go and Rust services are Phase 1 greenfield work,
not yet integrated into the primary ingestion pipeline.

**Fix applied:** Added a parenthetical clarification noting this describes the
target Phase 1 architecture and directing readers to the "Current Repository
State" section.

---

### DOC-4: docs/ Directory Missing Expected Protocol Specifications

| Attribute | Value |
|-----------|-------|
| **Severity** | Documentation |
| **Status** | 🟡 Noted (no numbered docs were created — they may never have existed) |

**Description:**
Several references in QUICKSTART.md and other documents suggest a numbered
documentation series (`docs/00_overview.md` through `docs/07_*.md`) that does
not exist. The `docs/` directory contains only the security audit report and
one ADR.

Protocol specifications currently live in code docstrings and comments within
`protocol/`, `storage/postgres.py`, and `ARCHITECTURE.md`. This is adequate for
developers but may not meet the needs of external auditors or integrators.

**Recommendation:** Consider creating a `docs/PROTOCOL.md` that consolidates
the protocol specification from code comments into a standalone reference document.

---

## Ledger Commitment Verification Summary

The following table summarizes the verified properties of the ledger commitment path:

| Property | Status | Evidence |
|----------|--------|----------|
| **Documents are actually committed** | ✅ Verified | `append_record()` inserts into both `smt_leaves` and `ledger_entries` |
| **Commits are atomic** | ✅ Verified | Single `SERIALIZABLE` transaction wraps all operations |
| **Tree root is bound to ledger** | ✅ Verified | `shard_root` in ledger payload, covered by `entry_hash` |
| **Chain is tamper-evident** | ✅ Verified | `prev_entry_hash` links entries; genesis uses empty string |
| **Shard headers are signed** | ✅ Verified | Ed25519 signing with post-sign verification before persist |
| **SMT nodes are trigger-protected** | ✅ Verified | `olympus.allow_smt_insert` and `olympus.allow_node_rehash` gates |
| **Canonicalization is deterministic** | ✅ Verified | `canonical_v2` with versioned pipeline stages |
| **Hashing uses domain separation** | ✅ Verified | All BLAKE3 calls use domain-specific prefixes |
| **Proofs are independently verifiable** | ✅ Verified | `verify_cli.py` and verification bundles enable offline verification |
| **Concurrent writes are safe** | ✅ Verified | `append_record()` retries `SerializationFailure` with backoff under `SERIALIZABLE` isolation |
| **Poseidon root is consistent** | ✅ Verified | Poseidon root is updated incrementally and persisted inside the same transaction as the ledger append |
| **Non-existence proofs are sound** | ✅ Verified | Sound; `expected_root` parameter enables root authentication |

---

## Comparison with V1 Audit

| V1 Finding | V2 Status |
|-----------|-----------|
| C-1: Poseidon SMT rebuild crash | ✅ Verified fixed; in-transaction incremental updates also closed RT-H5 |
| C-2: Embargo enforcement | ✅ Verified fixed; not re-examined |
| H-3: Dual rate-limit systems | ✅ Fixed after audit (2026-04-15); not re-examined in V2 |
| H-5: proof_id unvalidated | ✅ Fixed after audit (2026-04-15); not re-examined in V2 |
| M-2: Dataset file commit unbounded | 🔴 Still open; not re-examined (out of scope) |
| M-7: Unbounded tree replay | ✅ Verified fixed for forward path; RT-M2 now also fixed for historical replay |

---

## Appendix: Audit Methodology

### Files Reviewed

| File | Lines | Focus |
|------|-------|-------|
| `api/ingest.py` | ~1500 | Full ingestion pipeline, dedup logic, error handling |
| `storage/postgres.py` | ~2600 | `append_record()`, SMT persistence, triggers, schema |
| `protocol/ssmf.py` | ~500 | SMT operations, proof generation/verification |
| `protocol/ledger.py` | ~300 | Chain integrity, entry hash computation |
| `protocol/hashes.py` | ~300 | BLAKE3 hashing, domain separation, key derivation |
| `protocol/canonical.py` | ~200 | Document canonicalization |
| `api/auth.py` | ~700 | Authentication, rate limiting, token validation |
| `EXECUTIVE_SUMMARY.md` | ~140 | Architecture claims vs. reality |
| `QUICKSTART.md` | ~700 | Reference accuracy |
| `README.md` | ~260 | Architecture claims vs. reality |
| `ARCHITECTURE.md` | ~120 | Structural accuracy (verified accurate) |

### Techniques

- Full code path trace from HTTP entry point to database commit
- Concurrency analysis under PostgreSQL `SERIALIZABLE` isolation semantics
- Proof soundness analysis (existence, non-existence, redaction)
- Documentation cross-referencing against implementation
- Comparison with V1 audit findings for regression analysis
