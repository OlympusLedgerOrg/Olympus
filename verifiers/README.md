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

## Usage

See individual README files in each subdirectory for language-specific instructions.

## Interoperability Testing

All verifiers produce identical results for the same inputs, demonstrating:
- Cross-platform compatibility
- Cryptographic correctness
- Implementation independence
