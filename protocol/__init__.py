"""
Olympus Protocol Reference Implementation

This package provides reference implementations of the core Olympus protocol primitives.

Pipeline stages (Ingest → Canonicalize → Hash → Commit → Prove → [Replicate] → Verify):

  Ingest:       protocol.canonicalizer
  Canonicalize: protocol.canonical, protocol.canonical_json, protocol.timestamps
  Hash:         protocol.hashes
  Commit:       protocol.merkle, protocol.shards, protocol.ledger, protocol.ssmf
  Prove:        protocol.merkle, protocol.redaction, protocol.zkp, protocol.proof_interface
  Replicate:    *** Phase 1+ only — not implemented in v1.0 ***
  Verify:       protocol.merkle, protocol.redaction, protocol.shards, protocol.ledger

Dependency order (imports must flow down, never up):
  canonical_json, timestamps  →  hashes, canonical  →  events  →  merkle, ledger, shards, ...

Phase 1+ modules (Guardian replication; not part of v1.0):
  protocol.federation, protocol.partition
  See scaffolding.view_change for the non-production view-change helper.

Proof System Interface:
  protocol.proof_interface defines the strict protocol boundary for all proof backends.
  protocol.groth16_backend implements the interface for Groth16 proofs.
  protocol.halo2_backend implements the interface for Halo2 proofs (Phase 1+).
"""

__version__ = "1.0.0"

__all__ = [
    # Canonicalize
    "canonical",
    "canonical_json",
    "timestamps",
    # Hash
    "hashes",
    # Ingest (multi-format; depends on hashes + canonical)
    "canonicalizer",
    # Streaming / large-dataset canonicalization
    "streaming",
    "parquet_writer",
    "audit_metadata",
    # Commit
    "epochs",
    "events",
    "ledger",
    "key_rotation",
    "merkle",
    "rebuild",
    "shards",
    "ssmf",
    # Prove
    "redaction",
    "redaction_ledger",
    "zkp",
    "proof_interface",
    "groth16_backend",
    "halo2_backend",
    # Guardian replication (Phase 1+ only; not part of v1.0)
    "federation",
    "partition",
]
