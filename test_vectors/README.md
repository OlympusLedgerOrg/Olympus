# Olympus Cross-Implementation Test Vectors

This directory contains **golden vectors** generated from the Python reference
implementation. They are intended to be consumed by verifiers in Go, Rust,
JavaScript, Python, and any other language that wants to validate Olympus
commitments end-to-end.

## Layout

- `canonicalization/` – pointers to canonicalization-only vectors
- `merkle/` – pointers to Merkle hashing and proof vectors
- `ledger/` – pointers to ledger chaining vectors
- `proofs/` – full-stack vectors that bind canonicalization → Merkle →
  ledger → proof verification in one artifact

The existing golden files under `verifiers/test_vectors/` remain the source of
truth for stage-specific vectors. The subdirectories here document where to
find them and provide a single place for cross-language consumers to pick up
end-to-end vectors without needing to depend on the verifier packages
themselves.
