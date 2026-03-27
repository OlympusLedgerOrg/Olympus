"""Deterministic Merkle rebuild utilities for ledger journal recovery."""

from typing import Any

from .canonical_json import canonical_json_bytes
from .hashes import HASH_SEPARATOR, LEDGER_PREFIX, SNARK_SCALAR_FIELD, blake3_hash
from .hlc import HLCTimestamp
from .ledger import LedgerEntry
from .merkle import MerkleTree


_SEP = HASH_SEPARATOR.encode("utf-8")


def _verify_entry_chain(entries: list[LedgerEntry]) -> bool:
    """Verify ledger entry hashes and append-only linkage without mutating a Ledger."""
    if not entries:
        return True
    if entries[0].prev_entry_hash != "":
        return False

    prev_hlc: HLCTimestamp | None = None

    for index, entry in enumerate(entries):
        payload: dict[str, Any] = {
            "ts": entry.ts,
            "record_hash": entry.record_hash,
            "shard_id": entry.shard_id,
            "shard_root": entry.shard_root,
            "canonicalization": entry.canonicalization,
            "prev_entry_hash": entry.prev_entry_hash,
            "poseidon_root": entry.poseidon_root,
        }
        normalized_certificate = _canonicalize_quorum_certificate(entry.federation_quorum_certificate)
        if normalized_certificate is not None:
            payload["federation_quorum_certificate"] = normalized_certificate

        if entry.poseidon_root is not None:
            try:
                poseidon_int = int(entry.poseidon_root)
                if not (0 <= poseidon_int < SNARK_SCALAR_FIELD):
                    return False
                poseidon_bytes = poseidon_int.to_bytes(32, byteorder="big")
            except (ValueError, OverflowError):
                return False
        else:
            poseidon_bytes = b""

        # Include HLC bytes in hash if present (new format), otherwise legacy
        if getattr(entry, "hlc_bytes", None) is not None:
            try:
                hlc_raw = bytes.fromhex(entry.hlc_bytes)
                entry_hlc = HLCTimestamp.from_bytes(hlc_raw)
            except (ValueError, TypeError):
                return False

            if prev_hlc is not None and entry_hlc <= prev_hlc:
                return False
            prev_hlc = entry_hlc

            expected_hash = blake3_hash(
                [LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, poseidon_bytes, _SEP, hlc_raw]
            )
        else:
            expected_hash = blake3_hash(
                [LEDGER_PREFIX, canonical_json_bytes(payload), _SEP, poseidon_bytes]
            )

        if entry.entry_hash != expected_hash.hex():
            return False
        if index > 0 and entry.prev_entry_hash != entries[index - 1].entry_hash:
            return False
    return True


def _canonicalize_quorum_certificate(
    certificate: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Normalize quorum certificate metadata for deterministic entry-hash verification."""
    if certificate is None:
        return None
    signatures = certificate.get("signatures")
    if isinstance(signatures, list):
        signature_items = [
            {"node_id": str(item["node_id"]), "signature": str(item["signature"])}
            for item in signatures
            if isinstance(item, dict) and "node_id" in item and "signature" in item
        ]
        sorted_signatures: list[dict[str, str]] = sorted(
            signature_items,
            key=lambda item: (item["node_id"], item["signature"]),
        )
    else:
        sorted_signatures = []
    return {
        "event_id": str(certificate.get("event_id", "")),
        "federation_epoch": int(certificate.get("federation_epoch", 0)),
        "height": int(certificate.get("height", 0)),
        "header_hash": str(certificate.get("header_hash", "")),
        "membership_hash": str(certificate.get("membership_hash", "")),
        "validator_count": int(certificate.get("validator_count", 0)),
        "quorum_threshold": int(certificate.get("quorum_threshold", 0)),
        "round": int(certificate.get("round", 0)),
        "scheme": str(certificate.get("scheme", "")),
        "shard_id": str(certificate.get("shard_id", "")),
        "signatures": sorted_signatures,
        "signer_bitmap": str(certificate.get("signer_bitmap", "")),
        "timestamp": str(certificate.get("timestamp", "")),
        "validator_set_hash": str(certificate.get("validator_set_hash", "")),
    }


def rebuild_merkle_from_journal(entries: list[LedgerEntry]) -> tuple[bytes, MerkleTree]:
    """
    Rebuild a MerkleTree from an ordered list of ledger entries.

    Args:
        entries: Ordered list of LedgerEntry instances in append order.

    Returns:
        Tuple of ``(recomputed_root, tree)``.

    Raises:
        ValueError: If entries are empty or chain linkage is broken.
    """
    if not entries:
        raise ValueError("entries list cannot be empty")
    if entries[0].prev_entry_hash != "":
        raise ValueError("broken chain linkage: genesis prev_entry_hash must be empty")
    for index in range(1, len(entries)):
        if entries[index].prev_entry_hash != entries[index - 1].entry_hash:
            raise ValueError(f"broken chain linkage at index {index}")

    leaf_payloads = [canonical_json_bytes(entry.to_dict()) for entry in entries]
    tree = MerkleTree(leaf_payloads)
    return tree.get_root(), tree


def verify_rebuild(entries: list[LedgerEntry], expected_root: bytes) -> bool:
    """
    Verify deterministic rebuild from journal entries against an expected root.

    Args:
        entries: Ordered ledger entries.
        expected_root: Expected Merkle root.

    Returns:
        ``True`` if chain integrity is valid and rebuilt root matches.
    """
    if not isinstance(expected_root, bytes) or len(expected_root) != 32:
        return False
    if not _verify_entry_chain(entries):
        return False

    try:
        rebuilt_root, _ = rebuild_merkle_from_journal(entries)
    except ValueError:
        return False
    return rebuilt_root == expected_root
