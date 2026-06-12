"""Relying-party verification of Olympus SMT membership proofs.

Ports ``olympus_crypto::smt::verify_existence_proof`` /
``verify_nonexistence_proof``. A proof dict uses the same field names the Rust
``Proof`` enum serialises (``key``/``value_hash``/``siblings``/``root_hash`` as
byte arrays, provenance fields as strings).
"""

from __future__ import annotations

from typing import Any

from . import hashing


def _to_bytes(v: Any) -> bytes:
    """Accept a JSON byte-array (list[int]) or a hex string.

    Raises ``ValueError``/``TypeError`` on malformed input; the public verifiers
    catch these and return ``False`` so untrusted proofs never crash a caller.
    """
    if isinstance(v, str):
        return bytes.fromhex(v)
    return bytes(v)


def _to_hash32(v: Any) -> bytes:
    """Like :func:`_to_bytes` but requires exactly 32 bytes."""
    b = _to_bytes(v)
    if len(b) != 32:
        raise ValueError("expected 32 bytes")
    return b


def verify_existence(proof: dict, expected_root: bytes | None = None) -> bool:
    """Verify an existence proof, optionally anchored to ``expected_root``.

    Returns ``False`` (never raises) on any malformed or missing field.
    """
    try:
        if not isinstance(proof, dict):
            return False
        siblings = proof.get("siblings", [])
        if not isinstance(siblings, list) or len(siblings) != hashing.SMT_DEPTH:
            return False
        root = _to_hash32(proof["root_hash"])
        if expected_root is not None and root != expected_root:
            return False
        shard_id = proof.get("shard_id", "")
        parser_id = proof.get("parser_id", "")
        cpv = proof.get("canonical_parser_version", "")
        model_hash = proof.get("model_hash", "")
        if not (
            isinstance(shard_id, str)
            and isinstance(parser_id, str)
            and isinstance(cpv, str)
            and isinstance(model_hash, str)
            and shard_id
            and parser_id
            and cpv
            and model_hash
        ):
            return False
        key = _to_hash32(proof["key"])
        if not hashing.shard_id_matches_key(shard_id, key):
            return False
        start = hashing.leaf_hash(
            shard_id.encode("utf-8"),
            key,
            _to_hash32(proof["value_hash"]),
            parser_id.encode("utf-8"),
            cpv.encode("utf-8"),
            model_hash.encode("utf-8"),
        )
        sibs = [_to_hash32(s) for s in siblings]
        return hashing.fold_to_root(key, start, sibs) == root
    except (KeyError, ValueError, TypeError):
        return False


def verify_nonexistence(proof: dict, expected_root: bytes | None = None) -> bool:
    """Verify a non-existence proof, optionally anchored to ``expected_root``.

    Returns ``False`` (never raises) on any malformed or missing field.
    """
    try:
        if not isinstance(proof, dict):
            return False
        siblings = proof.get("siblings", [])
        if not isinstance(siblings, list) or len(siblings) != hashing.SMT_DEPTH:
            return False
        root = _to_hash32(proof["root_hash"])
        if expected_root is not None and root != expected_root:
            return False
        key = _to_hash32(proof["key"])
        sibs = [_to_hash32(s) for s in siblings]
        return hashing.fold_to_root(key, hashing.empty_leaf(), sibs) == root
    except (KeyError, ValueError, TypeError):
        return False
