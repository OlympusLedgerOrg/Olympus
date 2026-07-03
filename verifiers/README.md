# Olympus Cross-Language Verifiers

This directory contains verifiers for Olympus commitments in multiple programming languages.

## Why Multiple Verifiers?

Olympus commitments should be verifiable from any language. These verifiers
prove that Olympus doesn't lock you into a single ecosystem. The canonical
implementation now lives in Rust (`crates/olympus-crypto`); the verifiers
re-derive its outputs independently.

## Available Verifiers

- **Rust** (`rust/`) - Maintained reference verifier; conformance is gated in CI.
- **JavaScript/TypeScript** (`javascript/`) - Maintained verifier for web/Node.js; conformance is gated in CI.

> The Go and Python verifier paths were retired in v0.9.0. Rust and JavaScript
> are the offline reference implementations loaded directly against
> `test_vectors/vectors.json` and the per-concern fixtures in
> `verifiers/test_vectors/`.

## What They Verify

Each verifier can:
1. Verify BLAKE3 hashes
2. Verify Merkle tree roots
3. Verify Poseidon commitments
4. Verify inclusion proofs

## Domain Separation Conventions

The verifier corpus covers two related hash families:

- The legacy binary-Merkle helper vectors use the historic
  `OLY:LEAF:V1 | data` and `OLY:NODE:V1 | left | right` forms. These remain
  pinned for compatibility with old proof bundles and vector consumers.
- The live parser-bound SMT leaf hash uses the ADR-0005 structured binary prefix
  from `olympus-crypto::leaf_hash`: `0x01 || "OLY" || type=LEAF || version=V1
  || lp(shard_id)`, followed by a `0x05` count-framed body binding
  `key`, `value_hash`, `parser_id`, `canonical_parser_version`, and
  `model_hash`.

Changing either family breaks historical proof/vector compatibility.

| Constant / layout | Value | Purpose |
|-------------------|-------|---------|
| Legacy Merkle leaf | `OLY:LEAF:V1 \| data` | Binary Merkle helper vectors |
| Legacy Merkle node | `OLY:NODE:V1 \| left \| right` | Binary Merkle helper vectors |
| SMT empty leaf | `BLAKE3("OLY:EMPTY-LEAF:V1")` | Sparse Merkle empty sentinel |
| SMT leaf | ADR-0005 structured prefix + `0x05` body | Live parser-bound SMT vectors |

The legacy binary-Merkle leaf formula is:
```text
leaf_hash(data) = BLAKE3(b"OLY:LEAF:V1" || b"|" || data)
```

The legacy binary-Merkle parent formula is:
```text
parent_hash(left, right) = BLAKE3(b"OLY:NODE:V1" || b"|" || left || b"|" || right)
```

All hash values are output as **lowercase hexadecimal strings**.

## Conformance Test Vectors

The file `test_vectors/vectors.json` contains golden vectors. The SSMF (SMT)
sections are regenerated from the canonical Rust implementation via
`cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt` (the
Python reference was retired in v0.9.0).

These vectors cover:
- BLAKE3 hash of raw bytes
- Legacy binary-Merkle leaf hash (domain-separated)
- Legacy binary-Merkle parent hash (domain-separated)
- Legacy binary-Merkle root/proof cases
- Parser-bound SMT inclusion / non-inclusion cases using ADR-0005 leaves
- Poseidon commitment root
- Canonicalizer JCS regression vectors (`canonicalizer_vectors.tsv`) with 500+
  input/output pairs and pinned BLAKE3 hashes for Unicode/NFC, escaped nulls,
  numeric format variants, and nested ordering stability

Each language's test suite includes conformance tests that verify byte-for-byte
identical outputs against these vectors:

| Language   | Conformance test file                        |
|------------|----------------------------------------------|
| Rust       | inline in `verifiers/rust/src/lib.rs`        |
| JavaScript | `verifiers/javascript/test_conformance.js`   |

A legacy end-to-end pipeline vector (canonicalization -> binary Merkle ->
ledger -> proof) is published in `test_vectors/proofs/end_to_end.json` for
older consumers. New ledger inclusion work should prefer the SMT/snapshot
fixtures in `verifiers/test_vectors/vectors.json`.

## Usage

See individual README files in each subdirectory for language-specific instructions.

## Interoperability Testing

All verifiers produce identical results for the same inputs, demonstrating:
- Cross-platform compatibility
- Cryptographic correctness
- Implementation independence

**Confirmed parity:** Rust and JavaScript (the offline reference implementations)
produce byte-for-byte identical BLAKE3, legacy Merkle, SMT, Pedersen, redaction,
and checkpoint-quorum results for the committed fixtures.

The `ci.yml` workflow runs the verifier conformance suites on every commit and PR.
