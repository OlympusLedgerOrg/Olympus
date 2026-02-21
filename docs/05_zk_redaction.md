# Zero-Knowledge Redaction

This document describes the zero-knowledge redaction protocol in Olympus.

## Overview

Olympus allows documents to be redacted while providing cryptographic proof that the redacted version is a faithful redaction of the original.

## Protocol

1. Original document is canonicalized
2. Document is split into atomic units (leaves)
3. Merkle tree is constructed from leaves
4. Redacted version selects subset of leaves
5. ZK proof demonstrates inclusion of selected leaves
6. Proof is verified against original commitment

## Privacy Properties

- Redacted content remains hidden
- Proof does not reveal structure of redacted portions
- Verification requires only public commitments

## Proof System

- **Recommended (Phase 0.5+)**: Halo2 (no trusted setup; production-proven in Zcash/Scroll). Python bindings exist (`py-halo2`) though less mature than Rust; circuits should be versioned with explicit parameter pins.
- Current reference: circom circuits for Merkle inclusion and structural validity.
- Batch verification is supported at the proof layer.
