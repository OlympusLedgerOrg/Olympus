# Proof Vectors (End-to-End)

This directory contains a **legacy full-stack** vector for older external
consumers. It binds the pre-SMT binary-Merkle pipeline:

1. Canonicalize the input record
2. Hash the canonical bytes
3. Build a Merkle tree and inclusion proof
4. Commit the Merkle root into a legacy ledger entry
5. Verify the resulting proof and ledger chain

## Files

- `end_to_end.json` – single-record vector covering canonicalization → legacy binary Merkle
  → ledger → proof verification.

## Schema (`end_to_end.json`)

```json
{
  "description": "Human-readable summary",
  "input_record": { "...": "raw input used for canonicalization" },
  "canonicalized_bytes_hex": "hex-encoded canonical bytes",
  "record_hash_hex": "legacy record hash (see note below)",
  "merkle": {
    "leaf_hash_hex": "domain-separated leaf hash",
    "root_hex": "Merkle root for the tree",
    "siblings": [
      { "hash": "sibling hash hex", "position": "left|right" }
    ]
  },
  "ledger": {
    "head_entry_hash": "entry hash at the tip of the chain",
    "entries": [ { "ts": "...", "record_hash": "...", ... } ]
  },
  "proof": {
    "leaf_index": 0,
    "siblings": [ { "hash": "...", "position": "..." } ],
    "root_hash_hex": "...",
    "expected_valid": true
  }
}
```

**Legacy-field note.** `record_hash_hex` and the `ledger.*` fields were
produced by the retired Python pipeline (v0.9.0 removed it) and are **not**
reproducible by any current implementation — in particular, `record_hash_hex`
is *not* `BLAKE3(canonicalized_bytes)`, despite what this schema previously
claimed. `canonicalized_bytes_hex`, `merkle.*`, and `proof.*` are recomputed
against the live verifier in `verifiers/rust/tests/vector_conformance.rs`,
and the file as a whole is BLAKE3-pinned there so any edit fails CI.

The vector is retained as a stable fixture for consumers of the legacy binary
Merkle proof format. New integrations should prefer the SMT/snapshot fixtures in
`verifiers/test_vectors/vectors.json`, which are regenerated from the canonical
Rust implementation where applicable.

`siblings` is empty for single-leaf trees (like the published vector) and
contains the ordered sibling list when additional leaves are present.
