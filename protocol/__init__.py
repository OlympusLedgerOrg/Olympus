"""
Olympus Protocol Reference Implementation

This package provides reference implementations of the core Olympus protocol primitives.

Pipeline stages (Ingest → Canonicalize → Hash → Commit → Prove → [Replicate] → Verify):

  Ingest:       protocol.canonicalizer
  Canonicalize: protocol.canonical, protocol.canonical_json, protocol.timestamps
  Hash:         protocol.hashes
  Commit:       protocol.merkle, protocol.shards, protocol.ledger, protocol.ssmf
  Prove:        protocol.merkle, protocol.redaction, protocol.zkp
  Replicate:    *** Phase 1+ only — not implemented in v1.0 ***
  Verify:       protocol.merkle, protocol.redaction, protocol.shards, protocol.ledger

Dependency order (imports must flow down, never up):
  canonical_json, timestamps  →  hashes, canonical  →  events  →  merkle, ledger, shards, ...

Phase 1+ modules (Guardian replication; not part of v1.0):
  protocol.federation, protocol.partition, protocol.view_change
"""

__version__ = "0.1.0"

__all__ = [
    # Canonicalize
    "canonical",
    "canonical_json",
    "timestamps",
    # Hash
    "hashes",
    # Ingest (multi-format; depends on hashes + canonical)
    "canonicalizer",
    # Commit
    "epochs",
    "events",
    "ledger",
    "merkle",
    "shards",
    "ssmf",
    # Prove
    "redaction",
    "redaction_ledger",
    "zkp",
    # Guardian replication (Phase 1+ only; not part of v1.0)
    "federation",
    "partition",
    "view_change",
]
