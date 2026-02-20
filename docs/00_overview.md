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
