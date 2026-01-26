# Copilot Instructions for Olympus

## Project Overview

Olympus is a federated, append-only public ledger for government documents. It provides cryptographic guarantees about document integrity and provenance without being a blockchain, DAO, or token system. This is a civic integrity primitive built around deterministic canonicalization, Merkle commitments, and verifiable proofs.

**Core Purpose:** Make it cryptographically obvious when public records are created, changed, hidden, or over-redacted.

## Architectural Principles

1. **Append-Only Ledger**: All operations are additive; no modifications or deletions
2. **Deterministic Canonicalization**: Semantically equivalent documents must produce identical hashes
3. **Merkle Commitments**: Documents use Merkle trees for efficient cryptographic commitments
4. **Verifiable Proofs**: All operations must be independently verifiable
5. **Distributed Replication**: No trust in a single institution required

## Pipeline Stages

The Olympus system follows this strict pipeline:
**Ingest → Canonicalize → Hash → Commit → Prove → Replicate → Verify**

Each stage must be independently verifiable and auditable.

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
2. **Leaf Handling**: Duplicate the last leaf if odd number of leaves
3. **Proofs**: Include sibling hashes and their position (left/right) for verification

### Ledger Protocol

1. **Chain Linkage**: Each entry must include hash of previous entry
2. **Genesis Entry**: First entry has empty string for `previous_hash`
3. **Timestamps**: Use ISO 8601 format with 'Z' suffix: `datetime.utcnow().isoformat() + 'Z'`
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
- Guarantee completeness of public records
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
