"""
Tests for protocol.anchors — AnchorCommitment.

Covers:
- AnchorCommitment.create() determinism and validation
- verify() with correct and tampered data
- to_dict() / from_dict() round-trip
- Input normalization (hex strings, byte arrays, timestamps)
"""

from __future__ import annotations

import pytest

from protocol.anchors import AnchorCommitment, _normalize_hash, _normalize_timestamp
from protocol.hashes import hash_bytes


def _fake_hash(label: str) -> bytes:
    """Return a deterministic 32-byte BLAKE3 hash for testing."""
    return hash_bytes(label.encode())


# ------------------------------------------------------------------ #
# _normalize_hash
# ------------------------------------------------------------------ #


class TestNormalizeHash:
    """Tests for the _normalize_hash helper."""

    def test_bytes_passthrough(self) -> None:
        h = _fake_hash("test")
        assert _normalize_hash(h) == h

    def test_hex_string_conversion(self) -> None:
        h = _fake_hash("test")
        assert _normalize_hash(h.hex()) == h

    def test_wrong_length_rejected(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            _normalize_hash(b"\x00" * 16)

    def test_invalid_hex_rejected(self) -> None:
        with pytest.raises(ValueError):
            _normalize_hash("not-valid-hex")

    def test_empty_bytes_rejected(self) -> None:
        with pytest.raises(ValueError, match="32 bytes"):
            _normalize_hash(b"")


# ------------------------------------------------------------------ #
# _normalize_timestamp
# ------------------------------------------------------------------ #


class TestNormalizeTimestamp:
    """Tests for the _normalize_timestamp helper."""

    def test_none_returns_current(self) -> None:
        ts = _normalize_timestamp(None)
        assert ts.endswith("Z")

    def test_z_suffix_preserved(self) -> None:
        ts = _normalize_timestamp("2024-06-01T12:00:00Z")
        assert ts.endswith("Z")
        assert "2024-06-01" in ts

    def test_offset_normalized_to_z(self) -> None:
        ts = _normalize_timestamp("2024-06-01T12:00:00+00:00")
        assert ts.endswith("Z")


# ------------------------------------------------------------------ #
# AnchorCommitment.create
# ------------------------------------------------------------------ #


class TestAnchorCommitmentCreate:
    """Tests for AnchorCommitment.create() factory."""

    def test_basic_creation(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:abc123",
        )
        assert ac.anchor_chain == "bitcoin"
        assert ac.merkle_root == root.hex()
        assert ac.anchor_reference == "txid:abc123"
        assert len(ac.commitment_hash) == 64

    def test_deterministic_hash(self) -> None:
        root = _fake_hash("root")
        ts = "2024-01-01T00:00:00Z"
        ac1 = AnchorCommitment.create(
            anchor_chain="eth",
            merkle_root=root,
            anchor_reference="0xabc",
            anchored_at=ts,
        )
        ac2 = AnchorCommitment.create(
            anchor_chain="eth",
            merkle_root=root,
            anchor_reference="0xabc",
            anchored_at=ts,
        )
        assert ac1.commitment_hash == ac2.commitment_hash

    def test_hex_string_root(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root.hex(),
            anchor_reference="txid:123",
            anchored_at="2024-01-01T00:00:00Z",
        )
        assert ac.merkle_root == root.hex()

    def test_with_metadata(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:abc",
            metadata={"block_height": 800000},
        )
        assert ac.metadata == {"block_height": 800000}

    def test_empty_metadata_default(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(anchor_chain="test", merkle_root=root, anchor_reference="ref1")
        assert ac.metadata == {}

    def test_different_chains_different_hashes(self) -> None:
        root = _fake_hash("root")
        ts = "2024-01-01T00:00:00Z"
        ac1 = AnchorCommitment.create(
            anchor_chain="bitcoin", merkle_root=root, anchor_reference="ref", anchored_at=ts
        )
        ac2 = AnchorCommitment.create(
            anchor_chain="ethereum", merkle_root=root, anchor_reference="ref", anchored_at=ts
        )
        assert ac1.commitment_hash != ac2.commitment_hash


# ------------------------------------------------------------------ #
# AnchorCommitment.verify
# ------------------------------------------------------------------ #


class TestAnchorCommitmentVerify:
    """Tests for AnchorCommitment.verify()."""

    def test_valid_commitment_verifies(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:abc",
            anchored_at="2024-01-01T00:00:00Z",
        )
        assert ac.verify()

    def test_verify_with_expected_root(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:abc",
            anchored_at="2024-01-01T00:00:00Z",
        )
        assert ac.verify(expected_root=root)
        assert ac.verify(expected_root=root.hex())

    def test_verify_wrong_expected_root_fails(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:abc",
            anchored_at="2024-01-01T00:00:00Z",
        )
        wrong_root = _fake_hash("wrong")
        assert not ac.verify(expected_root=wrong_root)

    def test_tampered_commitment_hash_fails(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:abc",
            anchored_at="2024-01-01T00:00:00Z",
        )
        tampered = AnchorCommitment(
            anchor_chain=ac.anchor_chain,
            merkle_root=ac.merkle_root,
            anchor_reference=ac.anchor_reference,
            anchored_at=ac.anchored_at,
            commitment_hash="00" * 32,
            metadata=ac.metadata,
        )
        assert not tampered.verify()


# ------------------------------------------------------------------ #
# Serialization round-trip
# ------------------------------------------------------------------ #


class TestAnchorCommitmentSerialization:
    """Tests for to_dict() / from_dict()."""

    def test_round_trip(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(
            anchor_chain="bitcoin",
            merkle_root=root,
            anchor_reference="txid:xyz",
            anchored_at="2024-06-01T00:00:00Z",
            metadata={"block": 1},
        )
        d = ac.to_dict()
        ac2 = AnchorCommitment.from_dict(d)
        assert ac2.anchor_chain == ac.anchor_chain
        assert ac2.merkle_root == ac.merkle_root
        assert ac2.commitment_hash == ac.commitment_hash
        assert ac2.metadata == ac.metadata

    def test_to_dict_keys(self) -> None:
        root = _fake_hash("root")
        ac = AnchorCommitment.create(anchor_chain="test", merkle_root=root, anchor_reference="ref1")
        d = ac.to_dict()
        expected_keys = {
            "anchor_chain",
            "merkle_root",
            "anchor_reference",
            "anchored_at",
            "commitment_hash",
            "metadata",
        }
        assert set(d.keys()) == expected_keys
