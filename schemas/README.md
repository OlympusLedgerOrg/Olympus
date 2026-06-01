# Olympus JSON Schemas

## Purpose

The JSON schemas in this directory serve as **formal specifications** for external interoperability and protocol documentation. They define the canonical structure of Olympus data types for:

1. **Third-party integrators** who need to understand the expected format of API responses
2. **Protocol documentation** as machine-readable specifications
3. **External validators** who want to verify data independently
4. **Cross-language implementations** that need a language-agnostic schema reference

## Why Schemas Are NOT Used for Runtime Validation

These JSON schemas are **specification artifacts**, not the runtime validator.
Validation happens in Rust: the `serde` types in `src-tauri/` (Axum request /
response models) and `crates/olympus-crypto` are the implementation, and they
enforce structure at the type level. The Python FastAPI / Pydantic stack that
originally owned these models was retired in v0.9.0.

### 1. Single Source of Truth
The Rust `serde` types in the code ARE the implementation. These JSON schemas
are derived specifications for external consumption, not the other way around.

### 2. Type Safety and Performance
Rust's type system enforces model definitions at compile time, while runtime
payload conformance is checked during deserialization by serde (i.e., serde
enforces that incoming JSON matches the Rust types at runtime) — far cheaper
than running a JSON Schema validator per request on an append-only ledger.

### 3. Stable External Contract
The schemas give third-party integrators and offline auditors a
language-agnostic reference for the wire format without depending on the Rust
crate.

## Schema Descriptions

### canonical_document.json
Defines the structure of a canonicalized document after ingestion and normalization. Used by external systems to understand how Olympus represents documents internally.

### leaf_record.json
Describes a leaf node record in a Merkle tree, including its hash, index, and inclusion proof structure. Used by auditors to verify Merkle proofs offline.

### shard_commit.json
Specifies the format of a shard commitment, including the Merkle root, timestamp, and cryptographic signature. Used by replicas and auditors to verify shard state.

### source_proof.json
Defines the structure of a source authenticity proof, including agency signatures and metadata. Used by external verifiers to validate document provenance.

### verification_bundle.json
Defines the offline verification bundle. Each bundle contains the SMT proof, shard header, signature, and optional timestamp token so third parties can verify inclusion without database access. Consumed by the offline verifiers in `verifiers/`.

### proof_asset.json
Defines the versioned envelope for a proof asset. It wraps a `verification_bundle` with stable fields (`asset_id`, `canonical_claim`, `merkle_root`, `zk_public_inputs`) so the asset contract can be implemented later without schema churn.

### dataset_asset.json
Defines the versioned envelope for dataset-level assets. It provides dataset descriptors and the same core commitment fields used by proof assets, while preserving the existing verification bundle as a nested primitive.

## Governance Artifacts

### revenue_distribution.json (moved to docs/)
The revenue distribution schema has been moved to `docs/revenue_distribution.json` as it is a governance/transparency document rather than a protocol schema. See that file and `examples/revenue_distribution_v1.json` for the current distribution model.

## Ownership Map

The Rust types in `src-tauri/` (Axum handlers under `src-tauri/src/api/`) and
`crates/olympus-crypto` own the wire format; each schema mirrors one of those
shapes:

- Verification-bundle / proof responses ⇄ `verification_bundle.json`
- Proof / dataset asset envelopes ⇄ `proof_asset.json`, `dataset_asset.json`
- SMT inclusion-proof responses (`src-tauri/src/smt/`, `api/ledger.rs`) ⇄ `leaf_record.json`
- Shard header + federation flows (`api/shards.rs`, federation layer) ⇄ `shard_commit.json`
- Canonicalization pipeline (`crates/olympus-crypto`) ⇄ `canonical_document.json`
- Provenance ingestion (`api/ingest.rs`, `api/redaction.rs`) ⇄ `source_proof.json`

## Maintaining Schema Alignment

These schemas are not used for runtime validation, but they MUST stay aligned
with the Rust `serde` types in the codebase. When a request/response type
changes in `src-tauri/`, update the matching schema in the same change and keep
the offline verifiers (`verifiers/`) in sync.

## For External Integrators

If you are building a client or validator for Olympus:

- **For API consumers**: treat these schemas as a reference, and verify against actual API responses from the desktop binary.
- **For offline validators**: these schemas describe the expected format, but always verify cryptographic proofs independently using `verifiers/`.

These schemas exist as **specification artifacts** to aid understanding and
external integration, not as runtime validation tools.
