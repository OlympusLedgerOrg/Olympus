# Olympus Cross-Language Verifiers

This directory contains verifiers for Olympus commitments in multiple programming languages.

## Why Multiple Verifiers?

Olympus commitments should be verifiable from any language, not just Python. These verifiers prove that Olympus doesn't lock you into a single ecosystem.

## Available Verifiers

- **JavaScript/TypeScript** (`javascript/`) - For web applications and Node.js
- **Go** (`go/`) - For infrastructure tools and system services
- **Rust** (`rust/`) - For high-performance auditing and security-critical applications
- **CLI** (`cli/`) - Standalone command-line tool that works everywhere

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
```
leaf_hash(data) = BLAKE3(b"OLY:LEAF:V1" || b"|" || data)
```

The parent hash formula is:
```
parent_hash(left, right) = BLAKE3(b"OLY:NODE:V1" || b"|" || left || b"|" || right)
```

All hash values are output as **lowercase hexadecimal strings**.

## Conformance Test Vectors

The file `test_vectors/vectors.json` contains golden vectors generated directly from
the Python reference implementation (`protocol/hashes.py`, `protocol/merkle.py`).

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
| Python     | `verifiers/cli/test_conformance.py`          |
| Go         | `verifiers/go/conformance_test.go`           |
| Rust       | inline in `verifiers/rust/src/lib.rs`        |
| JavaScript | `verifiers/javascript/test_conformance.js`   |

In addition to the fixed vectors above, the cross-language determinism harness
(`verifiers/cli/test_cross_language_determinism.py`) generates thousands of
deterministic random records, hashes them in Python/Go/Rust/JavaScript, and
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

A dedicated CI workflow (`.github/workflows/verifier-conformance.yml`) runs all
language test suites plus the random determinism harness on every commit and PR.
