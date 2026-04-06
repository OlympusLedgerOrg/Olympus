"""
Tests for protocol.epochs — Epoch chaining, EpochRecord, and SignedTreeHead.

Covers:
- compute_epoch_head() determinism and input validation
- EpochRecord.create() and round-trip serialization
- SignedTreeHead.create(), verify(), and round-trip serialization
- signed_tree_head_hash() determinism
- verify_sth_consistency() and advance_epoch() protocol guarantees
"""

from __future__ import annotations

import nacl.signing
import pytest

from protocol.consistency import generate_consistency_proof
from protocol.epochs import (
    EpochRecord,
    SignedTreeHead,
    advance_epoch,
    compute_epoch_head,
    signed_tree_head_hash,
    verify_sth_consistency,
)
from protocol.hashes import hash_bytes
from protocol.merkle import MerkleTree


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _fake_hash(label: str) -> bytes:
    """Return a deterministic 32-byte hash for testing."""
    return hash_bytes(label.encode())


def _make_tree(n: int) -> MerkleTree:
    """Build a MerkleTree with *n* deterministic leaves."""
    leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(n)]
    return MerkleTree(leaves)


# ------------------------------------------------------------------ #
# compute_epoch_head
# ------------------------------------------------------------------ #


class TestComputeEpochHead:
    """Tests for compute_epoch_head()."""

    def test_deterministic(self) -> None:
        root = _fake_hash("root")
        meta = _fake_hash("meta")
        h1 = compute_epoch_head(None, root, meta)
        h2 = compute_epoch_head(None, root, meta)
        assert h1 == h2

    def test_genesis_empty_string_matches_none(self) -> None:
        root = _fake_hash("root")
        meta = _fake_hash("meta")
        assert compute_epoch_head(None, root, meta) == compute_epoch_head("", root, meta)

    def test_different_previous_head_changes_result(self) -> None:
        root = _fake_hash("root")
        meta = _fake_hash("meta")
        prev = _fake_hash("prev")
        h1 = compute_epoch_head(None, root, meta)
        h2 = compute_epoch_head(prev, root, meta)
        assert h1 != h2

    def test_accepts_hex_strings(self) -> None:
        root_hex = _fake_hash("root").hex()
        meta_hex = _fake_hash("meta").hex()
        h = compute_epoch_head(None, root_hex, meta_hex)
        assert len(h) == 32

    def test_returns_32_bytes(self) -> None:
        result = compute_epoch_head(None, _fake_hash("r"), _fake_hash("m"))
        assert isinstance(result, bytes)
        assert len(result) == 32


# ------------------------------------------------------------------ #
# EpochRecord
# ------------------------------------------------------------------ #


class TestEpochRecord:
    """Tests for EpochRecord creation and serialization."""

    def test_genesis_record(self) -> None:
        root = _fake_hash("root")
        meta = _fake_hash("meta")
        rec = EpochRecord.create(epoch_index=0, merkle_root=root, metadata_hash=meta)
        assert rec.epoch_index == 0
        assert rec.previous_epoch_head == ""
        assert len(rec.epoch_head) == 64

    def test_chained_record(self) -> None:
        root1 = _fake_hash("root1")
        meta1 = _fake_hash("meta1")
        rec1 = EpochRecord.create(epoch_index=0, merkle_root=root1, metadata_hash=meta1)

        root2 = _fake_hash("root2")
        meta2 = _fake_hash("meta2")
        rec2 = EpochRecord.create(
            epoch_index=1,
            merkle_root=root2,
            metadata_hash=meta2,
            previous_epoch_head=rec1.epoch_head,
        )
        assert rec2.epoch_index == 1
        assert rec2.previous_epoch_head == rec1.epoch_head
        assert rec2.epoch_head != rec1.epoch_head

    def test_negative_epoch_index_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            EpochRecord.create(
                epoch_index=-1, merkle_root=_fake_hash("r"), metadata_hash=_fake_hash("m")
            )

    def test_non_genesis_without_previous_rejected(self) -> None:
        with pytest.raises(ValueError, match="genesis epoch"):
            EpochRecord.create(
                epoch_index=1, merkle_root=_fake_hash("r"), metadata_hash=_fake_hash("m")
            )

    def test_to_dict_round_trip(self) -> None:
        rec = EpochRecord.create(
            epoch_index=0, merkle_root=_fake_hash("r"), metadata_hash=_fake_hash("m")
        )
        d = rec.to_dict()
        rec2 = EpochRecord.from_dict(d)
        assert rec2.epoch_index == rec.epoch_index
        assert rec2.epoch_head == rec.epoch_head
        assert rec2.merkle_root == rec.merkle_root


# ------------------------------------------------------------------ #
# signed_tree_head_hash
# ------------------------------------------------------------------ #


class TestSignedTreeHeadHash:
    """Tests for signed_tree_head_hash()."""

    def test_deterministic(self) -> None:
        root = _fake_hash("root")
        h1 = signed_tree_head_hash(
            epoch_id=0, tree_size=5, merkle_root=root, timestamp="2024-01-01T00:00:00Z"
        )
        h2 = signed_tree_head_hash(
            epoch_id=0, tree_size=5, merkle_root=root, timestamp="2024-01-01T00:00:00Z"
        )
        assert h1 == h2

    def test_different_epoch_different_hash(self) -> None:
        root = _fake_hash("root")
        ts = "2024-01-01T00:00:00Z"
        h1 = signed_tree_head_hash(epoch_id=0, tree_size=5, merkle_root=root, timestamp=ts)
        h2 = signed_tree_head_hash(epoch_id=1, tree_size=5, merkle_root=root, timestamp=ts)
        assert h1 != h2

    def test_negative_epoch_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            signed_tree_head_hash(
                epoch_id=-1,
                tree_size=5,
                merkle_root=_fake_hash("r"),
                timestamp="2024-01-01T00:00:00Z",
            )

    def test_negative_tree_size_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            signed_tree_head_hash(
                epoch_id=0,
                tree_size=-1,
                merkle_root=_fake_hash("r"),
                timestamp="2024-01-01T00:00:00Z",
            )

    def test_empty_timestamp_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            signed_tree_head_hash(
                epoch_id=0,
                tree_size=5,
                merkle_root=_fake_hash("r"),
                timestamp="",
            )


# ------------------------------------------------------------------ #
# SignedTreeHead
# ------------------------------------------------------------------ #


class TestSignedTreeHead:
    """Tests for SignedTreeHead creation and verification."""

    def test_create_and_verify(self) -> None:
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        sth = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=tree.get_root(), signing_key=key
        )
        assert sth.verify()

    def test_tampered_signature_fails(self) -> None:
        key = nacl.signing.SigningKey.generate()
        sth = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=_fake_hash("root"), signing_key=key
        )
        # Tamper with signature
        tampered = SignedTreeHead(
            epoch_id=sth.epoch_id,
            tree_size=sth.tree_size,
            merkle_root=sth.merkle_root,
            timestamp=sth.timestamp,
            signature="00" * 64,
            signer_pubkey=sth.signer_pubkey,
        )
        assert not tampered.verify()

    def test_wrong_key_fails(self) -> None:
        key1 = nacl.signing.SigningKey.generate()
        key2 = nacl.signing.SigningKey.generate()
        sth = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=_fake_hash("root"), signing_key=key1
        )
        tampered = SignedTreeHead(
            epoch_id=sth.epoch_id,
            tree_size=sth.tree_size,
            merkle_root=sth.merkle_root,
            timestamp=sth.timestamp,
            signature=sth.signature,
            signer_pubkey=key2.verify_key.encode().hex(),
        )
        assert not tampered.verify()

    def test_payload_hash_deterministic(self) -> None:
        key = nacl.signing.SigningKey.generate()
        sth = SignedTreeHead.create(
            epoch_id=0,
            tree_size=10,
            merkle_root=_fake_hash("root"),
            signing_key=key,
            timestamp="2024-06-01T00:00:00Z",
        )
        assert sth.payload_hash() == sth.payload_hash()

    def test_to_dict_from_dict_round_trip(self) -> None:
        key = nacl.signing.SigningKey.generate()
        sth = SignedTreeHead.create(
            epoch_id=3, tree_size=20, merkle_root=_fake_hash("root"), signing_key=key
        )
        d = sth.to_dict()
        sth2 = SignedTreeHead.from_dict(d)
        assert sth2.epoch_id == sth.epoch_id
        assert sth2.merkle_root == sth.merkle_root
        assert sth2.signature == sth.signature
        assert sth2.verify()

    def test_custom_timestamp(self) -> None:
        key = nacl.signing.SigningKey.generate()
        ts = "2024-12-25T12:00:00Z"
        sth = SignedTreeHead.create(
            epoch_id=0, tree_size=1, merkle_root=_fake_hash("r"), signing_key=key, timestamp=ts
        )
        assert sth.timestamp == ts


# ------------------------------------------------------------------ #
# verify_sth_consistency
# ------------------------------------------------------------------ #


class TestVerifySTHConsistency:
    """Tests for verify_sth_consistency()."""

    def test_valid_consistency(self) -> None:
        key = nacl.signing.SigningKey.generate()
        leaves = [hash_bytes(f"l-{i}".encode()) for i in range(10)]
        old_tree = MerkleTree(leaves[:5])
        new_tree = MerkleTree(leaves[:10])

        old_sth = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=old_tree.get_root(), signing_key=key
        )
        new_sth = SignedTreeHead.create(
            epoch_id=2, tree_size=10, merkle_root=new_tree.get_root(), signing_key=key
        )
        proof = generate_consistency_proof(5, 10, new_tree)
        assert verify_sth_consistency(old_sth, new_sth, proof)

    def test_tree_size_regression_fails(self) -> None:
        key = nacl.signing.SigningKey.generate()
        old_sth = SignedTreeHead.create(
            epoch_id=1, tree_size=10, merkle_root=_fake_hash("old"), signing_key=key
        )
        new_sth = SignedTreeHead.create(
            epoch_id=2, tree_size=5, merkle_root=_fake_hash("new"), signing_key=key
        )
        # Use a dummy proof; verify_sth_consistency should reject before checking it
        dummy_tree = _make_tree(1)
        proof = generate_consistency_proof(1, 1, dummy_tree)
        assert not verify_sth_consistency(old_sth, new_sth, proof)

    def test_invalid_old_signature_fails(self) -> None:
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        old_sth = SignedTreeHead.create(
            epoch_id=1, tree_size=5, merkle_root=tree.get_root(), signing_key=key
        )
        # Tamper old STH
        tampered_old = SignedTreeHead(
            epoch_id=old_sth.epoch_id,
            tree_size=old_sth.tree_size,
            merkle_root=old_sth.merkle_root,
            timestamp=old_sth.timestamp,
            signature="00" * 64,
            signer_pubkey=old_sth.signer_pubkey,
        )
        new_sth = SignedTreeHead.create(
            epoch_id=2, tree_size=5, merkle_root=tree.get_root(), signing_key=key
        )
        proof = generate_consistency_proof(5, 5, tree)
        assert not verify_sth_consistency(tampered_old, new_sth, proof)


# ------------------------------------------------------------------ #
# advance_epoch
# ------------------------------------------------------------------ #


class TestAdvanceEpoch:
    """Tests for the advance_epoch() protocol entry point."""

    def test_genesis_epoch(self) -> None:
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        sth, proof = advance_epoch(previous_sth=None, new_tree=tree, epoch_id=1, signing_key=key)
        assert proof is None
        assert sth.verify()
        assert sth.epoch_id == 1
        assert sth.tree_size == 5

    def test_subsequent_epoch_with_proof(self) -> None:
        key = nacl.signing.SigningKey.generate()
        leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
        tree1 = MerkleTree(leaves[:5])
        sth1, _ = advance_epoch(previous_sth=None, new_tree=tree1, epoch_id=1, signing_key=key)

        tree2 = MerkleTree(leaves[:10])
        sth2, proof = advance_epoch(previous_sth=sth1, new_tree=tree2, epoch_id=2, signing_key=key)
        assert proof is not None
        assert sth2.verify()
        assert verify_sth_consistency(sth1, sth2, proof)

    def test_epoch_id_not_increasing_rejected(self) -> None:
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        sth1, _ = advance_epoch(previous_sth=None, new_tree=tree, epoch_id=5, signing_key=key)
        with pytest.raises(ValueError, match="must be greater"):
            advance_epoch(previous_sth=sth1, new_tree=tree, epoch_id=5, signing_key=key)

    def test_tree_shrink_rejected(self) -> None:
        key = nacl.signing.SigningKey.generate()
        tree1 = _make_tree(10)
        sth1, _ = advance_epoch(previous_sth=None, new_tree=tree1, epoch_id=1, signing_key=key)
        tree2 = _make_tree(5)
        with pytest.raises(ValueError, match="append-only"):
            advance_epoch(previous_sth=sth1, new_tree=tree2, epoch_id=2, signing_key=key)

    def test_same_size_epoch_allowed(self) -> None:
        """Advancing with the same tree (no new leaves) should succeed."""
        key = nacl.signing.SigningKey.generate()
        tree = _make_tree(5)
        sth1, _ = advance_epoch(previous_sth=None, new_tree=tree, epoch_id=1, signing_key=key)
        sth2, proof = advance_epoch(previous_sth=sth1, new_tree=tree, epoch_id=2, signing_key=key)
        assert sth2.tree_size == sth1.tree_size
        assert proof is not None
