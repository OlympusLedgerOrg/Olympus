"""Verify Olympus record proof bundles against a manifest root.

Ports ``olympus_manifest::proof::verify``. The bundle's human-readable
``(shard_id, record_id, record_version)`` is re-derived into the tree key and
checked against the proof's key, so a valid proof for one leaf cannot be
relabelled as a different record.
"""

from __future__ import annotations

from enum import Enum

from . import hashing, smt


class Verdict(str, Enum):
    """Outcome of verifying a record proof bundle."""

    VALID = "valid"
    ROOT_MISMATCH = "root_mismatch"
    KEY_MISMATCH = "key_mismatch"
    CONTENT_MISMATCH = "content_mismatch"
    KIND_MISMATCH = "kind_mismatch"
    SMT_INVALID = "smt_invalid"

    @property
    def is_valid(self) -> bool:
        return self is Verdict.VALID


def record_tree_key(shard_id: str, record_id: str, version: int) -> bytes:
    """The SMT tree key for a manifest record (matches the Rust derivation)."""
    rkey = hashing.record_key(hashing.RECORD_TYPE, record_id, version)
    return hashing.shard_record_key(shard_id, rkey)


def verify(bundle: dict, expected_root: bytes) -> Verdict:
    """Verify ``bundle`` against an authenticated ``expected_root`` (32 bytes).

    The caller must establish that ``expected_root`` is the real committed root
    (by hashing the anchored manifest document); this proves the record
    relationship *given* that root.
    """
    claimed_root = bytes.fromhex(bundle["manifest_root"])
    if claimed_root != expected_root:
        return Verdict.ROOT_MISMATCH

    expected_key = record_tree_key(
        bundle["shard_id"], bundle["record_id"], bundle["record_version"]
    )
    kind = bundle["kind"]
    sp = bundle["smt_proof"]
    # The untagged SMT proof carries provenance fields only for existence.
    is_existence = "value_hash" in sp and "shard_id" in sp

    if kind == "inclusion":
        if not is_existence:
            return Verdict.KIND_MISMATCH
        if smt._to_bytes(sp["key"]) != expected_key:
            return Verdict.KEY_MISMATCH
        stated = bytes.fromhex(bundle["content_hash"])
        if smt._to_bytes(sp["value_hash"]) != stated:
            return Verdict.CONTENT_MISMATCH
        return Verdict.VALID if smt.verify_existence(sp, expected_root) else Verdict.SMT_INVALID

    if kind == "exclusion":
        if is_existence:
            return Verdict.KIND_MISMATCH
        if smt._to_bytes(sp["key"]) != expected_key:
            return Verdict.KEY_MISMATCH
        return (
            Verdict.VALID
            if smt.verify_nonexistence(sp, expected_root)
            else Verdict.SMT_INVALID
        )

    return Verdict.KIND_MISMATCH


def verify_against_manifest(bundle: dict, manifest: dict) -> Verdict:
    """Convenience: verify ``bundle`` against ``manifest['manifest_root']``."""
    return verify(bundle, bytes.fromhex(manifest["manifest_root"]))
