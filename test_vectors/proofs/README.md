# Proof Vectors (End-to-End)

This directory contains **full-stack** vectors that bind the entire Olympus
pipeline:

1. Canonicalize the input record
2. Hash the canonical bytes
3. Build a Merkle tree and inclusion proof
4. Commit the Merkle root into a ledger entry
5. Verify the resulting proof and ledger chain

## Files

- `end_to_end.json` – single-record vector covering canonicalization → Merkle
  → ledger → proof verification.

## Schema (`end_to_end.json`)

```json
{
  "description": "Human-readable summary",
  "input_record": { "...": "raw input used for canonicalization" },
  "canonicalized_bytes_hex": "hex-encoded canonical bytes",
  "record_hash_hex": "BLAKE3 hash of the canonical bytes",
  "merkle": {
    "leaf_hash_hex": "domain-separated leaf hash",
    "root_hex": "Merkle root for the tree",
    "path": [
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

The values are produced directly by `protocol.canonicalizer`, `protocol.merkle`,
and `protocol.ledger` in the Python reference implementation with a fixed
timestamp to keep the ledger hash deterministic.
