"""IPFS packaging helpers for Olympus proof bundles."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any


_CID_VERSION = b"\x01"
_DAG_JSON_CODEC = b"\x01\x29"
_SHA256_CODE = b"\x12"
_SHA256_LENGTH = b"\x20"


def build_ipfs_proof_envelope(proof_bundle: dict[str, Any]) -> bytes:
    """Serialize a proof bundle as deterministic DAG-JSON bytes."""
    return json.dumps(proof_bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def compute_ipfs_cidv1(proof_bundle: dict[str, Any]) -> str:
    """
    Compute a CIDv1 base32 preview for a proof bundle without talking to IPFS.

    This follows the CIDv1 layout using the dag-json codec and a SHA-256
    multihash. It is intended as a deterministic preview for Olympus bundles,
    not as a replacement for pinning via a full IPFS implementation.
    """
    payload = build_ipfs_proof_envelope(proof_bundle)
    digest = hashlib.sha256(payload).digest()
    multihash = _SHA256_CODE + _SHA256_LENGTH + digest
    cid_bytes = _CID_VERSION + _DAG_JSON_CODEC + multihash
    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")
