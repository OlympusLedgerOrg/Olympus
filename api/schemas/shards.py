from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ShardInfo(BaseModel):
    """Information about a shard."""

    shard_id: str
    latest_seq: int
    latest_root: str  # Hex-encoded


class ShardHeaderResponse(BaseModel):
    """Shard header with signature for verification."""

    shard_id: str
    seq: int
    root_hash: str  # Hex-encoded 32-byte root
    tree_size: int
    header_hash: str  # Hex-encoded 32-byte header hash
    previous_header_hash: str  # Hex-encoded (empty for genesis)
    timestamp: str  # ISO 8601
    signature: str  # Hex-encoded 64-byte Ed25519 signature
    pubkey: str  # Hex-encoded 32-byte Ed25519 public key
    canonical_header_json: str  # For offline verification


class ExistenceProofResponse(BaseModel):
    """Existence proof with all data for offline verification."""

    shard_id: str
    record_type: str
    record_id: str
    version: int
    key: str  # Hex-encoded 32-byte key
    value_hash: str  # Hex-encoded 32-byte value hash
    siblings: list[str]  # 256 hex-encoded 32-byte sibling hashes
    root_hash: str  # Hex-encoded 32-byte root
    shard_header: ShardHeaderResponse  # Latest header for this shard


class NonExistenceProofResponse(BaseModel):
    """Non-existence proof with all data for offline verification."""

    shard_id: str
    record_type: str
    record_id: str
    version: int
    key: str  # Hex-encoded 32-byte key
    siblings: list[str]  # 256 hex-encoded 32-byte sibling hashes
    root_hash: str  # Hex-encoded 32-byte root
    shard_header: ShardHeaderResponse  # Latest header for this shard


class LedgerEntryResponse(BaseModel):
    """Ledger entry for chain verification."""

    ts: str  # ISO 8601 timestamp
    record_hash: str  # Hex-encoded
    shard_id: str
    shard_root: str  # Hex-encoded
    canonicalization: dict[str, Any]
    prev_entry_hash: str  # Hex-encoded (empty for genesis)
    entry_hash: str  # Hex-encoded


class LedgerTailResponse(BaseModel):
    """Last N ledger entries for a shard."""

    shard_id: str
    entries: list[LedgerEntryResponse]


class TimestampTokenResponse(BaseModel):
    """RFC 3161 timestamp token for a shard header."""

    tsa_url: str  # URL of the issuing Timestamp Authority
    tst_hex: str  # DER-encoded TimeStampToken, hex-encoded
    hash_hex: str  # Hex-encoded BLAKE3 hash that was submitted to the TSA
    timestamp: str  # ISO 8601 timestamp from the TSA response
    tsa_cert_fingerprint: str | None  # SHA-256 fingerprint of TSA cert


class HeaderVerificationResponse(BaseModel):
    """Combined Ed25519 signature and RFC 3161 timestamp verification result."""

    shard_id: str
    header_hash: str  # Hex-encoded 32-byte header hash
    signature_valid: bool
    timestamp_token: TimestampTokenResponse | None  # None if not yet timestamped
    timestamp_valid: bool | None  # None if no token available
    # RFC 6962 §4.6 cursor fields for paginated replay verification
    headers_checked: int | None = None  # Number of headers verified in this call
    next_seq: int | None = None  # Next unverified sequence; None = complete


class ShardHistoryEntryResponse(BaseModel):
    """Historical shard header snapshot."""

    seq: int
    root_hash: str
    header_hash: str
    previous_header_hash: str
    timestamp: str


class ShardHistoryResponse(BaseModel):
    """Recent shard history for a shard."""

    shard_id: str
    headers: list[ShardHistoryEntryResponse]


class StateRootDiffEntryResponse(BaseModel):
    """Leaf-level difference between two sparse Merkle roots."""

    key: str
    before_value_hash: str | None
    after_value_hash: str | None


class StateRootDiffResponse(BaseModel):
    """Comparison between two shard state roots."""

    shard_id: str
    from_seq: int
    to_seq: int
    from_root_hash: str
    to_root_hash: str
    added: list[StateRootDiffEntryResponse]
    changed: list[StateRootDiffEntryResponse]
    removed: list[StateRootDiffEntryResponse]
    summary: dict[str, int]


class RekorAnchorResponse(BaseModel):
    """Rekor transparency log anchor for a shard header."""

    shard_id: str
    shard_seq: int
    root_hash: str  # Hex-encoded 32-byte root
    rekor_uuid: str | None  # Rekor entry UUID
    rekor_index: int | None  # Rekor log index
    anchored_at: str  # ISO 8601 timestamp
    status: str  # pending | anchored | failed
    verification_url: str | None  # URL to verify the Rekor entry
