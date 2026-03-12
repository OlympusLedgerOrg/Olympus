# Olympus Architecture

Olympus is an append-only public ledger for government documents.  It provides
cryptographic guarantees about document integrity and provenance via deterministic
canonicalization, Merkle commitments, and verifiable proofs.

## Pipeline Overview

Every document flows through the following stages:

```
Ingest → Canonicalize → Hash → Commit → Prove → [Replicate] → Verify
```

> ⚠️ **Replicate (Guardian multi-node replication) is not implemented in v1.0.**
> It is a Phase 1+ feature.  All other stages are fully implemented.

Each stage is independently verifiable and auditable.

---

## Stage → Module Mapping

### 1. Ingest

Accept raw documents in any supported format (JSON, HTML, DOCX, PDF) and
normalise them into a canonical byte representation.

| File | Key symbols |
|------|-------------|
| `protocol/canonicalizer.py` | `process_artifact()`, `Canonicalizer.json_jcs()`, `Canonicalizer.html_v1()`, `Canonicalizer.docx_v1()`, `Canonicalizer.pdf_normalize()` |
| `api/ingest.py` | FastAPI ingest routes (`/ingest/records`, `/ingest/commit`) |

### 2. Canonicalize

Produce a deterministic, byte-stable representation so that semantically
equivalent documents always hash identically.

| File | Key symbols |
|------|-------------|
| `protocol/canonical.py` | `canonicalize_json()`, `canonicalize_document()`, `canonicalize_text()`, `normalize_whitespace()`, `document_to_bytes()` |
| `protocol/canonical_json.py` | `canonical_json_encode()`, `canonical_json_bytes()` |
| `protocol/timestamps.py` | `current_timestamp()` — ISO 8601 UTC with `Z` suffix |

Canonical JSON follows RFC 8785 / JCS semantics: keys sorted, `ensure_ascii=True`,
compact separators `(",", ":")`.

### 3. Hash

Compute collision-resistant hashes with domain separation prefixes.

| File | Key symbols |
|------|-------------|
| `protocol/hashes.py` | `blake3_hash()`, `hash_bytes()`, `hash_string()`, `hash_hex()`, `leaf_hash()`, `node_hash()`, `record_key()`, `shard_header_hash()` |

All hashes use **BLAKE3**.  Domain separation prefixes (e.g. `OLY:LEAF:V1`,
`OLY:NODE:V1`, `OLY:LEDGER:V1`) are defined as constants in `protocol/hashes.py`
and **must not be changed** — doing so breaks all historical proofs.

Field separator: `HASH_SEPARATOR = "|"` (also in `protocol/hashes.py`).

### 4. Commit

Build Merkle trees over leaf hashes and publish shard headers that commit to the
current tree root.

| File | Key symbols |
|------|-------------|
| `protocol/merkle.py` | `MerkleTree`, `MerkleTree.get_root()`, `MerkleTree.generate_proof()`, `merkle_parent_hash()` |
| `protocol/hashes.py` | `merkle_root()`, `forest_root()` |
| `protocol/shards.py` | `create_shard_header()`, `sign_header()`, `verify_header()` |
| `protocol/ssmf.py` | `SparseMerkleForest` (sparse variant for non-membership proofs) |
| `protocol/ledger.py` | `Ledger`, `LedgerEntry`, `Ledger.append()` |

### 5. Prove

Generate cryptographic proofs (Merkle inclusion, redaction, ZK) that allow a
verifier to confirm claims without trusting the server.

| File | Key symbols |
|------|-------------|
| `protocol/merkle.py` | `MerkleProof`, `MerkleTree.generate_proof()` |
| `protocol/redaction.py` | `RedactionProtocol.commit_document()`, `RedactionProtocol.create_redaction_proof()`, `RedactionProof` |
| `protocol/ssmf.py` | `ExistenceProof`, `NonExistenceProof` |
| `protocol/zkp.py` | ZK proof wrappers |
| `proofs/` | Circom circuits, proving keys, Groth16 verifier (primary); boundary allows optional Halo2 circuits for high-assurance flows |

### 6. Replicate *(Phase 1+ only — not in v1.0)*

> **Not implemented.** Guardian replication distributes ledger state across
> independent nodes so no single institution can rewrite history.  See
> `docs/10_federation_governance.md` and `docs/14_federation_protocol.md` for
> the planned design.

Prototype federation components present in this repo (for local testing only):

| File | Purpose |
|------|---------|
| `protocol/federation.py` | Node identity, static registry, ≥2/3 quorum model |
| `protocol/partition.py` | Partition detection, fork resolution, proof-of-elapsed-rounds validation |
| `protocol/view_change.py` | View-change watermarks, grace-period validation, registry snapshots |
| `examples/federation_registry.json` | Static registry for local dev/tests |
| `docker-compose.federation.yml` | Local three-node simulation |

### 7. Verify

Independently verify any claim (Merkle inclusion, chain integrity, redaction,
or ZK proof) without trusting the original issuer.

| File | Key symbols |
|------|-------------|
| `protocol/merkle.py` | `verify_proof()` |
| `protocol/redaction.py` | `RedactionProtocol.verify_redaction_proof()` |
| `protocol/shards.py` | `verify_header()` |
| `protocol/ledger.py` | `Ledger.verify_chain()` |
| `verifiers/` | Cross-language verifier implementations (Python, Go, JS, Rust) |
| `verifiers/cli/verify.py` | Standalone CLI verifier |
| `tools/verify_cli.py` | Olympus verify CLI |
| `tools/verify_bundle_cli.py` | Verification bundle CLI |
| `tools/chain_verify_cli.py` | Chain integrity CLI |

---

## Dependency Flow

Module imports follow a strict one-way dependency order to avoid cycles:

```
stdlib / third-party
    ↓
protocol/canonical_json.py      (no internal deps)
protocol/timestamps.py          (no internal deps)
    ↓
protocol/hashes.py              (depends on: canonical_json)
protocol/canonical.py           (depends on: canonical_json)
    ↓
protocol/events.py              (depends on: hashes, canonical)
    ↓
protocol/merkle.py              (depends on: events, hashes)
protocol/ledger.py              (depends on: canonical_json, hashes, timestamps)
protocol/shards.py              (depends on: hashes, timestamps)
protocol/redaction.py           (depends on: merkle, hashes)
protocol/ssmf.py                (depends on: hashes)
protocol/federation.py          (depends on: hashes, timestamps) — Phase 1+ only
protocol/partition.py           (depends on: hashes, timestamps) — Phase 1+ only
protocol/view_change.py         (depends on: none, standalone dataclasses) — Phase 1+ only
    ↓
protocol/canonicalizer.py       (depends on: above; also third-party: pikepdf, lxml)
```

The `hashes` module **must not** import from `canonical.py` or `canonicalizer.py`.
Run `make boundary-check` to verify the dependency boundaries are intact.

---

## Directory Map

```
api/            FastAPI application — ingestion routes, auth, rate limiting
app_testonly/   Test-only app wiring used by smoke/integration flows
docs/           Protocol specs, threat model, ADRs (you are here)
examples/       Known-good artifacts: golden vectors, sample documents, notebooks
migrations/     SQL schema migrations
proofs/         Circom circuits, proving assets, JS proof tooling
protocol/       Reference implementations of all pipeline primitives
schemas/        JSON Schema definitions validated by tools/validate_schemas.py
storage/        PostgreSQL persistence layer
tests/          Regression tests (unit, integration, chaos, conformance)
tools/          CLI helpers, schema validation, dev smoke, Makefile fragments
ui/             FastAPI debug console and public verification portal
verifiers/      Cross-language verifier implementations + test vectors
```

---

## Key Developer Commands

| Command | Purpose |
|---------|---------|
| `make help` | List all available make targets with descriptions |
| `make check` | Full quality gate: lint + type-check + bandit + tests |
| `make vectors` | Verify golden test vectors deterministically |
| `make boundary-check` | Verify protocol module import boundaries |
| `make format` | Auto-format code with Ruff |
| `make lint` | Run Ruff + mypy + bandit (no tests) |
| `make smoke` | PostgreSQL-backed integration smoke test |

---

## Cross-Language Conformance

Golden test vectors for canonicalization and hashing live in
`verifiers/test_vectors/` and are exercised by Python, Go, JavaScript, and Rust
conformance tests.  `make vectors` runs the Python verification; see
`verifiers/*/README.md` for instructions on running other language verifiers.
