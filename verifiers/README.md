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
- **CLI / Python** (`cli/`, `python/`) - Standalone command-line + Python conformance harness used for cross-language determinism checks.

> The Go verifier (`go/`) was retired alongside the Go sequencer in v0.9.0 and
> no longer ships. Rust and JavaScript are the offline reference implementations
> loaded directly against `test_vectors/vectors.json`. Python is not an active
> verifier loaded against vectors but instead serves as a harness/conformance
> runner used for CI parity and verification of outputs.

## What They Verify

Each verifier can:
1. Verify BLAKE3 hashes
2. Verify Merkle tree roots
3. Verify Poseidon commitments
4. Verify inclusion proofs

## Domain Separation Conventions

All verifiers use the same domain-separation prefixes, which are protocol-critical.
Changing any prefix breaks historical proof compatibility.

| Constant       | Value          | Purpose                  |
|----------------|----------------|--------------------------|
| `LEAF_PREFIX`  | `OLY:LEAF:V1`  | Merkle leaf hashing      |
| `NODE_PREFIX`  | `OLY:NODE:V1`  | Merkle parent node hashing |
| `HASH_SEPARATOR` | `\|`         | Field separator in structured hash inputs |

The leaf hash formula is:
```text
leaf_hash(data) = BLAKE3(b"OLY:LEAF:V1" || b"|" || data)
```

The parent hash formula is:
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
- Merkle leaf hash (domain-separated)
- Merkle parent hash (domain-separated)
- Merkle root for 1-, 2-, and 3-leaf trees (including odd-count duplication)
- Merkle proof verification cases (valid and tampered)
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
| Python     | `verifiers/cli/test_conformance.py`          |

In addition to the fixed vectors above, the cross-language determinism harness
(`verifiers/cli/test_cross_language_determinism.py`) generates thousands of
deterministic random records, hashes them in Rust/JavaScript/Python, and
fails on any divergence.

An end-to-end pipeline vector (canonicalization → Merkle → ledger → proof) is
published in `test_vectors/proofs/end_to_end.json` to give other ecosystems a
single, human-readable artifact that can be verified without pulling in the
verifier packages.

## Usage

See individual README files in each subdirectory for language-specific instructions.

## Interoperability Testing

All verifiers produce identical results for the same inputs, demonstrating:
- Cross-platform compatibility
- Cryptographic correctness
- Implementation independence

**Confirmed parity:** Rust and JavaScript (the offline reference implementations)
produce byte-for-byte identical BLAKE3 leaf/node hashes and Merkle roots for
every test vector in `test_vectors/vectors.json`. The Python harness
(`verifiers/cli/test_cross_language_determinism.py`) validates this parity
over thousands of randomly generated records on every CI run.

The `ci.yml` workflow runs the verifier conformance suites plus the random
determinism harness on every commit and PR.
