# Changelog

All notable changes to the Olympus protocol are documented in this file.

## Unreleased

### Breaking Changes

- **`POST /datasets/commit` and `POST /datasets/{id}/lineage` now return
  immediately with `timestamp_status="pending"` (H-5).** The RFC 3161
  timestamp call has been moved out of the request handler into a
  dedicated background worker (`api.workers.tsa_worker`). Clients that
  previously read `rfc3161_tst_hex` synchronously from the commit response
  will now always see `null` until the worker has stored a token —
  typically within a few seconds, but bounded by the configurable grace
  window `TSA_GRACE_SECONDS` (default 300). Operators must run the new
  worker process (`python -m api.workers.tsa_worker` or the
  `olympus-tsa-worker` console script) alongside the API for tokens to
  ever be persisted.
- **`GET /datasets/{id}/verify` adds a new `timestamp_state` field with
  values `verified | pending_within_grace | pending_past_grace | failed`
  (H-5).** The legacy boolean `rfc3161_valid` is preserved for backward
  compatibility but collapses pending-within-grace and pending-past-grace
  into the same `false` value. Witnesses and downstream verifiers should
  read `timestamp_state` to distinguish "still being processed" from
  "permanently failed". A row that previously rendered as
  `rfc3161_valid=false` because the inline TSA call had timed out will
  now report `timestamp_state="pending_within_grace"` (and eventually
  flip to `verified` once the worker lands a token, or `failed` once the
  sweeper or worker exhausts retries).

### Security

- **TSA call hardening (H-5 Tier 0).** `protocol.rfc3161.request_timestamp`
  now passes an explicit `timeout=5.0` to `rfc3161ng.RemoteTimestamper`,
  bounding the TCP round-trip. Previously the default 10-second timeout
  applied; combined with the synchronous inline call this allowed a hung
  TSA to pin FastAPI workers indefinitely.

### Breaking Changes

- **Sequencer endpoint renamed: `/v1/get-consistency-proof` →
  `/v1/get-signed-root-pair`** (`services/sequencer-go/internal/api/sequencer.go`)
  The original name was misleading: the handler returned a pair of signed
  roots for offline comparison, not an RFC-6962 / Trillian consistency
  proof. Anything an external verifier might have built on the old name
  would have overstated the cryptographic guarantee (H-2). The new name
  describes what the endpoint actually returns. The old path is preserved
  for one release as a deprecated alias that returns HTTP `410 Gone` with
  a body pointing to the successor (rather than a silent 301 redirect, to
  avoid masking the semantic change). The deprecated alias will be removed
  in the next release. A real RFC-6962-style consistency proof for the
  CD-HS-ST sparse Merkle tree is tracked as a follow-up; the proof shape
  differs from RFC 6962 and requires its own design.

### Documentation

- **SECURITY.md: Sequencer Token Trust Model** — Documented the v1.0 trust
  assumption that possession of the sequencer's `X-Sequencer-Token`
  bearer token grants append authority for any leaf in any shard, the
  threats this model does not defend against, the operator mitigations
  required to deploy the sequencer safely, and explicit non-goals for
  v1.0 (per-shard authorization, multi-tenant scoping, capability
  tokens) with a forward reference to Guardian replication for
  multi-party trust distribution.

### CI / Supply Chain

- **govulncheck added to `supply-chain` job** (`.github/workflows/ci.yml`)
  The Go modules under `verifiers/go/` and `services/sequencer-go/` are
  now audited on every PR alongside the existing `pip-audit`,
  `cargo audit`, and `npm audit` steps. Suppressions are managed via
  `go-vuln-baseline.txt` (mirrors the format of `pip-audit-baseline.txt`
  and `cargo-audit-baseline.txt`) and applied by
  `scripts/run-govulncheck.sh`, which post-filters `govulncheck -json`
  output by OSV id and aliases (CVE / GHSA). Only call-graph–reachable
  findings cause CI failure.

## canonical_v2 (Round 2) — 2026-03-26

### Breaking Changes

- **Merkle tree: 0x00/0x01 domain separation** (`api/services/merkle.py`)
  Internal node hashes are now computed as `H(0x01 || left || right)` and
  leaf hashes as `H(0x00 || data)`, following RFC 6962 conventions.  This
  prevents a crafted leaf value from colliding with an internal node hash
  and eliminates structural ambiguity in the tree.  All Merkle roots change.
  Pre-launch determination: no stored proofs reference unprefixed roots in
  a way that cannot be regenerated, so no `CANONICAL_VERSION` bump is needed.

### Fixes

- **Unicode homoglyph scrub** (`protocol/canonical.py`)
  `_scrub_homoglyphs()` replaces Unicode characters whose NFKD form is a
  single ASCII printable character with that ASCII character.  This catches
  fullwidth Latin (`Ａ` → `A`), mathematical bold/italic (`𝐔` → `U`), and
  enclosed alphanumerics without touching legitimate non-ASCII (Arabic, CJK,
  accented Latin).  Controlled via `scrub_homoglyphs=True/False` parameter
  on `canonicalize_document()` and `document_to_bytes()`.

- **Schema-annotated list sorting** (`protocol/canonical.py`)
  Added `sorted_list_keys: set[str] | None` parameter to
  `canonicalize_document()` and `document_to_bytes()`.  Fields named in the
  set have their array values sorted deterministically using canonical JSON
  as the sort key.  Default is `None` (preserve order) for backward
  compatibility.

- **Idempotency gate** (`api/ingest.py`)
  `IngestionResult` now includes an `idempotent: bool` field, set `True`
  when a duplicate submission returns the existing record instead of creating
  a new ledger entry.  The existing content-hash dedup check was already
  enforced before any ledger write; this field lets callers distinguish fresh
  inserts from deduplicated returns.

- **Mixed crypto isolation** (`api/ingest.py`, `api/auth.py`)
  `hmac.compare_digest` calls replaced with `_constant_time_equals()` wrapper
  that documents its sole use is timing-safe comparison (not MAC computation).
  Clarifies the crypto boundary: BLAKE3 for hashing, Ed25519 (nacl) for
  signing, `hmac.compare_digest` only for constant-time equality.

- **Proof depth validation** (`api/services/merkle.py`)
  `MerkleProof` now carries `tree_size`; `verify_proof()` validates that
  proof depth matches `ceil(log2(tree_size))` and rejects invalid sibling
  direction values.  `tree_size=0` disables the check for legacy proofs.

- **BLAKE3/Poseidon canonical-hash binding** (`proofs/proof_generator.py`)
  Added `recompute_canonical_hash()` and `_validate_canonical_hash_binding()`
  to the unified circuit validator.  Before witness generation, the Python
  layer independently recomputes the Poseidon chain from `sectionCount`,
  `sectionLengths`, and `sectionHashes`, and rejects inputs where
  `canonicalHash` does not match.  This closes the binding gap between the
  BLAKE3 canonicalization layer and the Poseidon ZK circuit.

## canonical_v2 (Round 1) — 2026-03-26

### Breaking Changes

- **Merkle tree: lone-node self-pair instead of promotion** (`api/services/merkle.py`)
  Lone nodes at any level of the Merkle tree are now duplicated and hashed
  (`H(node || node)`) instead of being promoted without rehashing.  This
  prevents an attacker who controls batching boundaries from producing
  alternate valid roots from the same dataset.  Any tree with an odd leaf
  count will produce a different root than under `canonical_v1`.

### Fixes

- **Numeric canonicalization** (`protocol/canonical.py`)
  `_canonicalize_value()` now normalises numeric types: whole floats are
  converted to `int`, non-whole floats to `Decimal`, and `NaN`/`Inf` are
  rejected with `CanonicalizationError`.  This ensures semantically
  equivalent JSON representations (`100`, `100.0`, `1e2`) produce the same
  canonical bytes.

- **Merkle leaf ordering** (`api/services/merkle.py`)
  `build_tree()` now sorts leaf hashes lexicographically by default so that
  federation nodes ingesting the same dataset in different arrival orders
  produce identical Merkle roots.  A `preserve_order=True` parameter is
  available for append-only log proofs where positional ordering is required.

### Migration

`CANONICAL_VERSION` has been bumped from `canonical_v1` to `canonical_v2`.
`SUPPORTED_VERSIONS` includes both `canonical_v1` and `canonical_v2` so that
the verifier can still accept proofs generated under the old version (with a
deprecation warning).  A full migration layer is planned for a follow-up PR.
