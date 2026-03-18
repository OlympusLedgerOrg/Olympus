# Olympus JSON Schemas

## Purpose

The JSON schemas in this directory serve as **formal specifications** for external interoperability and protocol documentation. They define the canonical structure of Olympus data types for:

1. **Third-party integrators** who need to understand the expected format of API responses
2. **Protocol documentation** as machine-readable specifications
3. **External validators** who want to verify data independently
4. **Cross-language implementations** that need a language-agnostic schema reference

## Why Schemas Are NOT Used for Runtime Validation

Olympus uses **Pydantic models** for runtime validation instead of JSON Schema validation for several important reasons:

### 1. Type Safety and Developer Experience
Pydantic provides native Python type hints and IDE autocomplete, making the codebase more maintainable and reducing bugs during development.

### 2. Performance
Pydantic validation is significantly faster than JSON Schema validation, which is critical for a high-throughput append-only ledger.

### 3. Protocol Phase
Olympus is currently in **protocol hardening phase**. The focus is on core cryptographic primitives and correctness, not external API contracts. Runtime validation is internal to the Python implementation.

### 4. Single Source of Truth
Pydantic models in the code ARE the implementation. The JSON schemas are derived specifications for external consumption, not the other way around.

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
Defines the offline verification bundle used by `protocol/verification_bundle.py` and `tools/verify_bundle_cli.py`. Each bundle contains the SMT proof, shard header, signature, and optional timestamp token so third parties can verify inclusion without database access.

### proof_asset.json
Defines the versioned envelope for a proof asset. It wraps a `verification_bundle` with stable fields (`asset_id`, `canonical_claim`, `merkle_root`, `zk_public_inputs`) so the asset contract can be implemented later without schema churn.

### dataset_asset.json
Defines the versioned envelope for dataset-level assets. It provides dataset descriptors and the same core commitment fields used by proof assets, while preserving the existing verification bundle as a nested primitive.

## Governance Artifacts

### revenue_distribution.json (moved to docs/)
The revenue distribution schema has been moved to `docs/revenue_distribution.json` as it is a governance/transparency document rather than a protocol schema. See that file and `examples/revenue_distribution_v1.json` for the current distribution model.

## Ownership Map

- `protocol/verification_bundle.py` ⇄ `verification_bundle.json`
- `assets/model.py` (stub) ⇄ `proof_asset.json`, `dataset_asset.json`
- `protocol/merkle.py` / API proof responses ⇄ `leaf_record.json`
- Shard header and federation flows (`protocol/shards.py`, storage layer) ⇄ `shard_commit.json`
- Canonicalization pipeline (`protocol/canonical_*`, `tools/canonicalize_cli.py`) ⇄ `canonical_document.json`
- Provenance ingestion (`api/ingest.py`, `protocol/redaction.py`) ⇄ `source_proof.json`

## Maintaining Schema Alignment

While the schemas are not used for runtime validation, they MUST remain aligned with the Pydantic models in the codebase. This is enforced by:

1. **Schema validation script** (`tools/validate_schemas.py`) - Ensures schemas are valid JSON Schema documents
2. **CI automation** - The validation script runs on every commit to catch schema errors early
3. **Alignment tests** (`tests/test_schema_alignment.py`) - Verify schema-model compatibility
4. **Manual review** during code changes
5. **Documentation updates** when data structures change

To validate schemas locally:
```bash
python tools/validate_schemas.py
```

## For External Integrators

If you are building a client or validator for Olympus:

- **For API consumers**: Use the Pydantic models as the source of truth for current API response formats
- **For cross-language clients**: Use these JSON schemas as a reference, but verify against actual API responses
- **For offline validators**: These schemas describe the expected format, but always verify cryptographic proofs independently

## Future Considerations

In a post-1.0 release, we may:

- Generate OpenAPI schemas directly from Pydantic models
- Provide JSON Schema validation as an optional external tool
- Create language-specific client libraries with schema validation

For now, these schemas exist as **specification artifacts** to aid understanding and external integration, not as runtime validation tools.
