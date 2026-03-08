# Overview

This document provides an overview of the Olympus protocol.

Olympus is an append-only public ledger for government documents with planned federation capabilities, designed to provide cryptographic guarantees about the integrity and provenance of public records.

## Core Principles

- Deterministic canonicalization
- Merkle commitments
- Verifiable proofs
- Distributed replication ⚠️ **(Phase 1+ only)**

## Architecture

The Olympus system follows a strict pipeline:

**Ingest → Canonicalize → Hash → Commit → Prove → Replicate → Verify**

Each stage in this pipeline is designed to be independently verifiable and auditable.

We use BLAKE3 for hashing and Merkle commitments; we use Ed25519 for signatures.

**v1.0 Implementation Status:**
- ✅ Ingest, Canonicalize, Hash, Commit, Prove, Verify — **Implemented**
- ✅ Multi-format canonicalization (JSON/HTML/DOCX/PDF) with version pinning — **Implemented**
- ⚠️ Replicate (multi-node Guardian replication) — **Phase 1+ only**

## Pipeline-to-Code Mapping

Each pipeline stage maps to specific modules and functions in the `protocol/` package:

| Stage | Module | Key Functions / Classes |
|-------|--------|------------------------|
| **Ingest** | `protocol/canonicalizer.py` | `process_artifact()`, `Canonicalizer.json_jcs()`, `Canonicalizer.html_v1()`, `Canonicalizer.docx_v1()`, `Canonicalizer.pdf_normalize()` |
| **Canonicalize** | `protocol/canonical.py` | `canonicalize_json()`, `canonicalize_document()`, `canonicalize_text()`, `normalize_whitespace()`, `document_to_bytes()` |
| | `protocol/canonical_json.py` | `canonical_json_encode()`, `canonical_json_bytes()` |
| | `protocol/timestamps.py` | `current_timestamp()` |
| **Hash** | `protocol/hashes.py` | `blake3_hash()`, `hash_bytes()`, `record_key()`, `leaf_hash()`, `node_hash()`, `shard_header_hash()`, `blake3_to_field_element()` |
| **Commit** | `protocol/merkle.py` | `MerkleTree`, `MerkleTree.get_root()`, `MerkleTree.generate_proof()` |
| | `protocol/hashes.py` | `merkle_root()`, `forest_root()` |
| | `protocol/shards.py` | `create_shard_header()`, `sign_header()` |
| **Prove** | `protocol/merkle.py` | `MerkleProof`, `MerkleTree.generate_proof()` |
| | `protocol/redaction.py` | `RedactionProtocol.commit_document()`, `RedactionProtocol.create_redaction_proof()`, `RedactionProof` |
| | `protocol/ssmf.py` | `SparseMerkleForest`, `ExistenceProof`, `NonExistenceProof` |
| **Replicate** | *(Phase 1+ only)* | Guardian replication — not implemented in v1.0 |
| **Verify** | `protocol/merkle.py` | `verify_proof()` |
| | `protocol/redaction.py` | `RedactionProtocol.verify_redaction_proof()` |
| | `protocol/shards.py` | `verify_header()` |
| | `protocol/ledger.py` | `Ledger.verify_chain()` |

The `tests/test_workflow_conformance.py` test suite verifies that all documented pipeline functions remain importable and callable, catching undocumented changes automatically.

## Specification Map

- **Protocol specification**: `docs/09_protocol_spec.md` (normative pipeline, data structures, verification rules)
- **Canonicalization**: `docs/02_canonicalization.md`
- **Merkle commitments**: `docs/03_merkle_forest.md`
- **Ledger and finality**: `docs/04_ledger_protocol.md`
- **ZK redaction**: `docs/05_zk_redaction.md`
- **External anchoring**: `docs/11_external_anchoring.md`
- **Federation governance (Phase 1+)**: `docs/10_federation_governance.md`
- **Protocol vs applications**: `docs/12_protocol_vs_applications.md`
- **Public explorer interface**: `docs/13_public_explorer.md`
- **Threat model**: `docs/01_threat_model.md` and `docs/threat_model_walkthrough.ipynb`

## Protocol vs Applications

Olympus treats the protocol (hashing, canonicalization, Merkle/ledger formats, proofs) as immutable and independently verifiable. Applications (APIs, explorers, ingestion services) consume protocol outputs but must not alter canonical bytes or ledger linkage. See `docs/12_protocol_vs_applications.md` for the boundary contract.

## Public Explorer (Read-Only)

A public explorer surfaces shard headers, ledger entries, proofs, and anchors without authentication. It is a read-only consumer of protocol artifacts and must provide links back to canonical JSON, proofs, and anchors for independent verification (see `docs/13_public_explorer.md`).
