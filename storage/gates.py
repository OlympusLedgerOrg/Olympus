"""Shared helpers for storage-layer session gate derivation."""

from __future__ import annotations

import os

import blake3


def derive_node_rehash_gate() -> str:
    """Derive the session gate value for SMT trigger-protected writes."""
    hasher = blake3.blake3()
    hasher.update(b"OLY:NODE-REHASH-GATE:V1")
    gate_secret = os.getenv("OLYMPUS_NODE_REHASH_GATE_SECRET", "")
    if gate_secret:
        hasher.update(b"|")
        hasher.update(gate_secret.encode("utf-8"))
    return hasher.hexdigest()
