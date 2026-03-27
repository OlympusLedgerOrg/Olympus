"""IPFS packaging helpers for Olympus proof bundles."""

from __future__ import annotations

import base64
import json
from typing import Any

import blake3


_CID_VERSION = b"\x01"
# DAG-JSON multicodec = 0x0129 (297 decimal).
# Varint encoding: 297 & 0x7F = 0x29, with continuation bit → 0xA9;
# 297 >> 7 = 2, final byte → 0x02.  Result: b"\xa9\x02".
_DAG_JSON_CODEC = b"\xa9\x02"
# BLAKE3-256 multihash code (0x1e) and 32-byte output length (0x20).
_BLAKE3_CODE = b"\x1e"
_BLAKE3_LENGTH = b"\x20"


def build_ipfs_proof_envelope(proof_bundle: dict[str, Any]) -> bytes:
    """Serialize a proof bundle as deterministic DAG-JSON bytes."""
    return json.dumps(
        proof_bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def compute_ipfs_cidv1(proof_bundle: dict[str, Any]) -> str:
    """
    Compute a CIDv1 base32 preview for a proof bundle without talking to IPFS.

    This follows the CIDv1 layout using the dag-json codec and a BLAKE3-256
    multihash. It is intended as a deterministic preview for Olympus bundles,
    not as a replacement for pinning via a full IPFS implementation.
    """
    payload = build_ipfs_proof_envelope(proof_bundle)
    digest = blake3.blake3(payload).digest()
    multihash = _BLAKE3_CODE + _BLAKE3_LENGTH + digest
    cid_bytes = _CID_VERSION + _DAG_JSON_CODEC + multihash
    return "b" + base64.b32encode(cid_bytes).decode("ascii").lower().rstrip("=")
