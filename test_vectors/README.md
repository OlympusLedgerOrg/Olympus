# Olympus Cross-Implementation Test Vectors

This directory contains **golden vectors** for external consumers. The live
stage-specific source of truth is `verifiers/test_vectors/`, regenerated from
the canonical Rust implementation where applicable. The maintained offline
verifiers are Rust and JavaScript; Python/Go verifier paths were retired in
v0.9.0.

## Layout

- `canonicalization/` – pointers to canonicalization-only vectors
- `merkle/` – pointers to Merkle hashing and proof vectors
- `ledger/` – pointers to ledger chaining vectors
- `proofs/` – legacy full-stack vectors that bind canonicalization → binary
  Merkle → ledger → proof verification in one artifact

The existing golden files under `verifiers/test_vectors/` remain the source of
truth for stage-specific vectors. The subdirectories here document where to
find them and provide a single place for cross-language consumers to pick up
end-to-end vectors without needing to depend on the verifier packages
themselves. New ledger-inclusion integrations should start with
`verifiers/test_vectors/vectors.json`, especially the SMT sections that use the
ADR-0005 structured leaf layout.
