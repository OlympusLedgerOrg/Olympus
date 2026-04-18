# Copilot Instructions for Olympus

## Project Overview

Olympus is a federated, append-only public ledger for government documents. It provides cryptographic guarantees about document integrity and provenance without being a blockchain, DAO, or token system. This is a civic integrity primitive built around deterministic canonicalization, Merkle commitments, and verifiable proofs.

**Core Purpose:** Make it cryptographically obvious when sensitive records are created, changed, hidden, or over-redacted.

## Architectural Principles

1. **Append-Only Ledger**: All operations are additive; no modifications or deletions
2. **Deterministic Canonicalization**: Semantically equivalent documents must produce identical hashes
3. **CD-HS-ST (Constant-Depth Hierarchical Sparse Tree)**: Single global 256-level Sparse Merkle Tree for all record commitments
4. **Verifiable Proofs**: All operations must be independently verifiable
5. **Distributed Replication (Guardian Replication)**: No trust in a single institution required (Phase 1+ only; not in v1.0)

## Core Architecture: CD-HS-ST (DO NOT CHANGE)

### 1. CD-HS-ST Structure

The **Constant-Depth Hierarchical Sparse Tree (CD-HS-ST)** is the core cryptographic data structure:

- A **single global 256-level Sparse Merkle Tree**
- Keys encode both **shard identity** and **record identity**:
  ```
  key = H(GLOBAL_KEY_PREFIX || shard_id || record_key)
  ```
  where:
  - `shard_id` identifies the logical shard (e.g., `watauga:2025:budget`)
  - `record_key` identifies the specific record (type/id/version/etc.)
  - `H` is BLAKE3 with domain separation
- Values are hashes of **canonicalized record content**
- Tree depth is **constant** (256) and **sparse** (only non-default nodes stored)

**CRITICAL:** Copilot MUST:
- Preserve this model
- NOT reintroduce a separate "shard tree" plus "forest tree"
- Assume **one global SMT**, logically sharded by keyspace, not multiple physical trees
- NOT create separate `smt_nodes` vs `forest_nodes` tables
- NOT implement per-shard SMTs with a separate forest aggregator

### 2. Rust: CD-HS-ST + Crypto Hot Path (Service)

Rust maintains and extends the cryptographic core:

**Responsibilities:**
- Canonicalization (canonical JSON, NFC normalization, deterministic key order)
- BLAKE3 hashing with clear domain separation
- CD-HS-ST operations:
  - `insert/update(global_key, leaf_value) -> (delta, new_root)`
  - `prove_inclusion(global_key, root) -> proof`
  - `verify_inclusion(global_key, leaf_value, proof, root) -> bool`
  - Non-inclusion proofs
- Ed25519 signing of roots/checkpoints
- Optional Poseidon support for witness generation (but CD-HS-ST stays BLAKE3-based)

**Adaptation Rule:**
Existing Rust SMT code must be **adapted to the CD-HS-ST model** (single global tree, composite key). It must **not** be re-introduced or extended as per-shard trees plus a forest tree. If existing Rust code assumes separate shard trees, refactor it to use the composite `H(GLOBAL_KEY_PREFIX || shard_id || record_key)` key scheme instead.

**Form Factor:**
- Implement the Rust core as a **standalone binary** exposing a small, stable API over a local socket using **protobuf as the wire format**
- Do **not** use JSON for the Rust↔Go boundary; protobuf is canonical to avoid double-serialization when Go serves gRPC externally
- Do **not** add new FFI from Python↔Rust or Go↔Rust; treat Rust as a separate service

### 3. Go: Log / Sequencer Around CD-HS-ST

Go builds a "Trillian-shaped" log service that **uses CD-HS-ST in Rust**:

**Public API (HTTP/gRPC):**
- `QueueLeaf` (append a record for a given `shard_id`)
- `GetLatestRoot`
- `GetInclusionProof`
- `GetSignedRootPair` (returns two signed roots for offline comparison; **not** an RFC-6962 consistency proof)

**Sequencer:**
- Batches and orders appends
- Calls the Rust CD-HS-ST service (over local socket, protobuf) to:
  - Canonicalize records
  - Compute `global_key` from `(shard_id, record_id, …)`
  - Update the global SMT
  - Sign new roots
- Persists SMT node deltas and `new_root` to storage (Postgres or current DB)

**Constraints:**
- Use the **same protobuf definitions** as the Rust service; do not introduce a separate JSON shim
- **Go must never compute Merkle hashes itself.** All SMT operations—leaf hashing, node updates, root computation, proof generation—are delegated to the Rust service
- Go is a **client** of the Rust service, not a co-implementor of the tree
- Treat the SMT as **one global tree** (CD-HS-ST), not per-shard plus forest
- Do **not** reintroduce separate `smt_nodes` vs `forest_nodes` tables that try to track two trees
- If sharding metadata is needed, keep it in separate tables (e.g., `shard_meta`), not as separate Merkle trees

### 4. Python: API, Policy, and Orchestration

Python (FastAPI and jobs) handles high-level concerns:

**Responsibilities:**
- API endpoints for clients (FOIA, datasets, operators)
- Metadata and policy logic:
  - What is a shard?
  - Retention and redaction rules
- Orchestration:
  - Call Go log service for append/proof queries
  - Call Rust service for ZK witness generation

**Constraints:**
- Python must **not** implement SMT logic
- Python must **not** re-define canonicalization logic; it should treat Rust as the canonical source
- Python should talk to Go/Rust over HTTP/gRPC or sockets, not via FFI
- Existing Python SMT code in `protocol/ssmf.py` is reference implementation only; operational logic migrates to Rust service

### 5. Poseidon / Redaction Circuits

For ZK / redaction:

- CD-HS-ST remains **BLAKE3** in the operational layer
- Poseidon trees and circuits are a **separate layer**:
  - Rust can expose functions/endpoints to:
    - Derive Poseidon leaves from canonicalized records
    - Build Poseidon Merkle paths and roots for a redaction circuit
  - Ledger/log entries can store both:
    - `root_b3` (CD-HS-ST root)
    - `root_poseidon` (redaction tree root)
    - or a dual-root commitment

**Constraints:**
- Keep Poseidon concerns **logically separate** from the CD-HS-ST implementation
- Do not try to change the CD-HS-ST structure to "be Poseidon-native"

### 6. Non-Goals / Guardrails

Copilot MUST NOT:
- Reintroduce the old "two separate SMTs" pattern (per-shard SMT + forest SMT) that led to TOCTOU and consistency issues
- Move canonicalization back into Python or Go
- Add new in-process FFI layers between Python↔Rust or Go↔Rust
- Introduce JSON as the wire format between Go and Rust (use protobuf)
- Attempt backward-compatibility migrations for legacy Python SMT/ledger state (OK to ignore old data)

Copilot SHOULD:
- Generate or refactor code so that:
  - There is a clear Rust service owning the CD-HS-ST
  - Go's log/transport layer talks to Rust as a client over protobuf
  - Python uses Go/Rust as external services, never as libraries

### 7. Phasing and Scope

This architecture describes the **target state**. Not all of it needs to be built before the system is public. Respect the following phasing:

**Phase 0 — Pre-public blockers (do not defer, do not refactor around):**
- Groth16 trusted setup ceremony (external dependency, not code)
- Decomposition of `federation.py` (~2,000 lines / 73 functions) into focused modules
- E2E CI integration test against a real Postgres database

These three items are the only hard blockers for going public. Copilot should not generate refactor work that blocks or replaces them.

**Phase 1 — Greenfield (new code only, no migration):**
- Go sequencer and witness transport layer (new, not a rewrite of existing Python)
- Rust standalone binary with protobuf socket API (extend existing Rust core, no Python SMT migration)
- `.proto` definitions shared between Go and Rust

**Phase 2 — Post-public migration (deferred):**
- Moving existing Python SMT/ledger logic out of FastAPI handlers and into Go/Rust services
- Replacing any remaining Python canonicalization calls with Rust service calls
- Halo2 backend (currently gated behind `OLYMPUS_HALO2_ENABLED`; keep it gated until circuits are stable)

**Current State (Phase 0):**
- Python reference implementation in `protocol/ssmf.py` remains valid for tests and protocol documentation
- New Rust/Go code should be built as greenfield services, not migrations of existing Python code
- Existing Python API and FastAPI endpoints continue to operate during Phase 1 development

## Pipeline Stages

The Olympus system follows this strict pipeline:
**Ingest → Canonicalize → Hash → Commit → Prove → Replicate → Verify**

Each stage must be independently verifiable and auditable.

**Note:** The Replicate stage refers to the Guardian replication protocol, which is a Phase 1+ feature and not implemented in v1.0.

## Repository Structure

- `docs/` — Protocol specifications (read these first for context)
- `protocol/` — Reference implementations of core primitives
- `schemas/` — Canonical data formats
- `proofs/` — Zero-knowledge circuits and notes
- `examples/` — Known-good test artifacts
- `tools/` — CLI utilities for canonicalization and verification

## Code Conventions

### Cryptographic Standards

1. **Hash Functions**: Always use BLAKE3 via the `hashes.py` module
   - Use `hash_bytes()` for raw bytes
   - Use `hash_string()` for UTF-8 strings
   - Use `hash_hex()` for hex-encoded output

2. **Field Separators**: Use `HASH_SEPARATOR` constant from `protocol.hashes` module for structured data field separators in hash computations
   - Example: `entry_data = HASH_SEPARATOR.join([field1, field2, field3])`

3. **Hash Encoding**: Store hashes as hex strings in data structures, raw bytes for internal computation

### Python Style

1. **Type Hints**: Always use type hints for function parameters and return values
2. **Docstrings**: All public functions must have docstrings explaining purpose, args, and returns
3. **Dataclasses**: Use `@dataclass` decorator for data structures (see `LedgerEntry`, `MerkleNode`, `RedactionProof`)
4. **Error Handling**: Raise `ValueError` for invalid inputs with descriptive messages

### Canonicalization Rules

1. **JSON Canonicalization**: Use `json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)`
2. **Whitespace**: Normalize all whitespace to single spaces using `normalize_whitespace()`
3. **Ordering**: Sort all dictionary keys alphabetically
4. **Encoding**: Always use UTF-8 encoding

### Merkle Trees

1. **Parent Hash**: Use `merkle_parent_hash(left, right)` to compute parent nodes
2. **Leaf Handling**: Use CT-style promotion (lone node promoted without hashing) for odd counts
3. **Proofs**: Include sibling hashes and their position (left/right) for verification

### Ledger Protocol

1. **Chain Linkage**: Each entry must include hash of previous entry
2. **Genesis Entry**: First entry has empty string for `previous_hash`
3. **Timestamps**: Use ISO 8601 format with 'Z' suffix via `protocol.timestamps.current_timestamp()` (timezone-aware `datetime.now(UTC)` with `Z` normalization)
4. **Entry Hash**: Compute over all fields joined with `HASH_SEPARATOR`

## Security Considerations

1. **No Secrets in Code**: Never commit cryptographic keys or secrets
2. **Tamper Evidence**: All operations must preserve chain integrity
3. **Determinism**: All hash operations must be deterministic and reproducible
4. **Collision Resistance**: Always use BLAKE3 or stronger
5. **Input Validation**: Validate all external inputs before processing

## Non-Goals

Olympus intentionally does NOT:
- Assert that governments are honest
- Guarantee completeness of records
- Decide what should be redacted
- Require trust in a single institution

These are out of scope and should not be implied in code or documentation.

## Current Status

This repository is in **protocol hardening phase**. APIs, UIs, and deployments are intentionally out of scope until core semantics are finalized.

## Testing and Verification

1. Test artifacts should be placed in `examples/` directory
2. CLI tools should handle errors gracefully with helpful messages
3. All cryptographic operations should be verifiable independently
4. Chain integrity verification must be thorough (see `Ledger.verify_chain()`)

## Common Patterns

### Creating a Ledger Entry
```python
entry = ledger.append(
    document_hash=doc_hash,
    merkle_root=root_hash,
    shard_id=shard,
    source_signature=signature
)
```

### Canonicalizing Documents
```python
canonical = canonicalize_document(doc)
canonical_bytes = document_to_bytes(canonical)
doc_hash = hash_bytes(canonical_bytes)
```

### Building Merkle Trees
```python
leaf_hashes = [hash_bytes(part.encode('utf-8')) for part in parts]
tree = MerkleTree(leaf_hashes)
root = tree.get_root()
```

### Creating Redaction Proofs
```python
tree, root_hash = RedactionProtocol.commit_document(document_parts)
proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)
is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)
```

## Documentation Style

- Be precise and technical; this is an auditable protocol
- Focus on what the code proves cryptographically
- Avoid marketing language or exaggerated claims
- Reference the threat model when discussing security properties
- Document both what the system does and does not guarantee
