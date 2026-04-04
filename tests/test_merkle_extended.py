"""Extended tests for protocol/merkle.py targeting uncovered lines."""

import pytest

from protocol.merkle import (
    EMPTY_TREE_HASH,
    MAX_PROOF_DEPTH,
    PROOF_VERSION,
    MerkleProof,
    MerkleTree,
    _largest_power_of_two_less_than,
    _subtree_root,
    ct_merkle_root,
    deserialize_merkle_proof,
    generate_consistency_proof,
    merkle_leaf_hash,
    verify_consistency_proof,
    verify_proof,
)


# ── MerkleProof __post_init__ (line 97) ──


class TestMerkleProofNormalization:
    def test_boolean_positions_normalized(self):
        """Boolean positions are normalized to 'left'/'right' strings."""
        proof = MerkleProof(
            leaf_hash=b"\x00" * 32,
            leaf_index=0,
            siblings=[(b"\x01" * 32, True), (b"\x02" * 32, False)],
            root_hash=b"\x03" * 32,
        )
        assert proof.siblings[0][1] == "right"
        assert proof.siblings[1][1] == "left"

    def test_invalid_position_raises(self):
        with pytest.raises(ValueError, match="left.*right"):
            MerkleProof(
                leaf_hash=b"\x00" * 32,
                leaf_index=0,
                siblings=[(b"\x01" * 32, "up")],
                root_hash=b"\x03" * 32,
            )


# ── MerkleTree edge cases (lines 127, 140, 143) ──


class TestMerkleTreeEdgeCases:
    def test_empty_leaves_raises(self):
        with pytest.raises(ValueError, match="empty"):
            MerkleTree([])

    def test_single_leaf(self):
        tree = MerkleTree([b"leaf1"])
        root = tree.get_root()
        assert root == tree.root()
        assert len(root) == 32

    def test_non_bytes_leaf_raises(self):
        with pytest.raises(ValueError, match="bytes"):
            MerkleTree([123])

    def test_power_of_two_leaves(self):
        tree = MerkleTree([b"a", b"b", b"c", b"d"])
        proof = tree.generate_proof(0)
        assert verify_proof(proof)

    def test_odd_number_leaves_ct_promotion(self):
        tree = MerkleTree([b"a", b"b", b"c"])
        proof = tree.generate_proof(2)  # last leaf promoted
        assert verify_proof(proof)


# ── generate_proof (line 195) ──


class TestGenerateProof:
    def test_negative_index_raises(self):
        tree = MerkleTree([b"a", b"b"])
        with pytest.raises(ValueError, match="Invalid"):
            tree.generate_proof(-1)

    def test_out_of_range_index_raises(self):
        tree = MerkleTree([b"a", b"b"])
        with pytest.raises(ValueError, match="Invalid"):
            tree.generate_proof(5)

    def test_proof_with_epoch(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.generate_proof(0, epoch=42)
        assert proof.epoch == 42
        assert verify_proof(proof)


# ── verify_proof (line 270) ──


class TestVerifyProof:
    def test_unknown_proof_version(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.generate_proof(0)
        bad_proof = MerkleProof(
            leaf_hash=proof.leaf_hash,
            leaf_index=proof.leaf_index,
            siblings=proof.siblings,
            root_hash=proof.root_hash,
            proof_version="unknown_v99",
        )
        with pytest.raises(ValueError, match="Unknown proof_version"):
            verify_proof(bad_proof)

    def test_single_leaf_proof(self):
        tree = MerkleTree([b"only"])
        proof = tree.generate_proof(0)
        assert verify_proof(proof)
        assert proof.tree_size == 1
        assert len(proof.siblings) == 0


# ── _largest_power_of_two_less_than (lines 355-357) ──


class TestLargestPowerOfTwo:
    def test_n_zero(self):
        assert _largest_power_of_two_less_than(0) == 1

    def test_n_one(self):
        assert _largest_power_of_two_less_than(1) == 1

    def test_n_five(self):
        assert _largest_power_of_two_less_than(5) == 4

    def test_n_eight(self):
        assert _largest_power_of_two_less_than(8) == 4


# ── _subtree_root (lines 362-367) ──


class TestSubtreeRoot:
    def test_size_zero_raises(self):
        with pytest.raises(ValueError, match="positive"):
            _subtree_root([b"\x00" * 32], 0, 0)

    def test_range_exceeds_raises(self):
        with pytest.raises(ValueError, match="exceeds"):
            _subtree_root([b"\x00" * 32], 0, 5)

    def test_valid_subtree(self):
        leaves = [merkle_leaf_hash(b"a"), merkle_leaf_hash(b"b")]
        root = _subtree_root(leaves, 0, 2)
        assert len(root) == 32


# ── ct_merkle_root (lines 381) ──


class TestCtMerkleRoot:
    def test_empty_raises(self):
        with pytest.raises(ValueError, match="empty"):
            ct_merkle_root([])

    def test_single_leaf(self):
        h = merkle_leaf_hash(b"x")
        assert ct_merkle_root([h]) == h

    def test_three_leaves(self):
        leaves = [merkle_leaf_hash(b"a"), merkle_leaf_hash(b"b"), merkle_leaf_hash(b"c")]
        root = ct_merkle_root(leaves)
        assert len(root) == 32


# ── generate_consistency_proof (lines 419, 421, 423) ──


class TestGenerateConsistencyProof:
    def test_negative_sizes(self):
        with pytest.raises(ValueError, match="non-negative"):
            generate_consistency_proof([], -1, 0)

    def test_old_exceeds_new(self):
        with pytest.raises(ValueError, match="cannot exceed"):
            generate_consistency_proof([], 5, 3)

    def test_not_enough_leaves(self):
        with pytest.raises(ValueError, match="Not enough"):
            generate_consistency_proof([b"\x00" * 32], 1, 5)

    def test_trivial_old_zero(self):
        assert generate_consistency_proof([b"\x00" * 32], 0, 1) == []

    def test_trivial_same_size(self):
        h = merkle_leaf_hash(b"a")
        assert generate_consistency_proof([h], 1, 1) == []

    def test_nontrivial_proof(self):
        leaves = [merkle_leaf_hash(f"leaf-{i}".encode()) for i in range(4)]
        proof = generate_consistency_proof(leaves, 2, 4)
        assert len(proof) > 0


# ── verify_consistency_proof (lines 510-520, 532, 564, 566) ──


class TestVerifyConsistencyProof:
    def test_invalid_sizes(self):
        assert verify_consistency_proof(b"\x00" * 32, b"\x00" * 32, [], -1, 5) is False
        assert verify_consistency_proof(b"\x00" * 32, b"\x00" * 32, [], 5, 3) is False

    def test_old_zero_wrong_root(self):
        """old_size=0 with wrong old_root fails."""
        assert verify_consistency_proof(b"\x00" * 32, b"\x01" * 32, [], 0, 1) is False
        assert (
            verify_consistency_proof(
                b"\x00" * 32,
                b"\x01" * 32,
                [],
                0,
                1,
                trust_new_root_on_empty=True,
            )
            is False
        )

    def test_old_zero_requires_trusted_new_root(self):
        """old_size=0 with EMPTY_TREE_HASH requires explicit trust."""
        with pytest.raises(ValueError, match="old_size=0 cannot cryptographically"):
            verify_consistency_proof(EMPTY_TREE_HASH, b"\x01" * 32, [], 0, 1)

    def test_old_zero_trusted_new_root(self):
        """old_size=0 with EMPTY_TREE_HASH succeeds when trust is explicit."""
        assert (
            verify_consistency_proof(
                EMPTY_TREE_HASH,
                b"\x01" * 32,
                [],
                0,
                1,
                trust_new_root_on_empty=True,
            )
            is True
        )

    def test_same_size_same_root(self):
        root = b"\xaa" * 32
        assert verify_consistency_proof(root, root, [], 5, 5) is True

    def test_same_size_different_root(self):
        assert verify_consistency_proof(b"\xaa" * 32, b"\xbb" * 32, [], 5, 5) is False

    def test_roundtrip_verification(self):
        leaves = [merkle_leaf_hash(f"leaf-{i}".encode()) for i in range(8)]
        old_root = ct_merkle_root(leaves[:3])
        new_root = ct_merkle_root(leaves[:8])
        proof = generate_consistency_proof(leaves, 3, 8)
        assert verify_consistency_proof(old_root, new_root, proof, 3, 8) is True

    def test_unconsumed_proof_nodes(self):
        """Extra proof nodes cause verification failure."""
        leaves = [merkle_leaf_hash(f"leaf-{i}".encode()) for i in range(4)]
        old_root = ct_merkle_root(leaves[:2])
        new_root = ct_merkle_root(leaves[:4])
        proof = generate_consistency_proof(leaves, 2, 4)
        bad_proof = proof + [b"\x00" * 32]
        assert verify_consistency_proof(old_root, new_root, bad_proof, 2, 4) is False


# ── deserialize_merkle_proof (lines 661, 689-690, 695-696) ──


class TestDeserializeMerkleProof:
    def test_unknown_proof_version(self):
        with pytest.raises(ValueError, match="Unknown proof_version"):
            deserialize_merkle_proof({"proof_version": "bad_v99"})

    def test_depth_dos_check(self):
        data = {
            "proof_version": PROOF_VERSION,
            "leaf_hash": "aa" * 32,
            "leaf_index": 0,
            "siblings": [("bb" * 32, "right")] * (MAX_PROOF_DEPTH + 1),
            "root_hash": "cc" * 32,
        }
        with pytest.raises(ValueError, match="exceeds maximum"):
            deserialize_merkle_proof(data)

    def test_bad_epoch_value(self):
        data = {
            "proof_version": PROOF_VERSION,
            "leaf_hash": "aa" * 32,
            "leaf_index": 0,
            "siblings": [],
            "root_hash": "cc" * 32,
            "epoch": "not-a-number",
        }
        with pytest.raises(ValueError, match="epoch"):
            deserialize_merkle_proof(data)

    def test_bad_tree_size_value(self):
        data = {
            "proof_version": PROOF_VERSION,
            "leaf_hash": "aa" * 32,
            "leaf_index": 0,
            "siblings": [],
            "root_hash": "cc" * 32,
            "tree_size": "not-a-number",
        }
        with pytest.raises(ValueError, match="tree_size"):
            deserialize_merkle_proof(data)

    def test_roundtrip(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.generate_proof(0)
        data = {
            "proof_version": proof.proof_version,
            "tree_version": proof.tree_version,
            "leaf_hash": proof.leaf_hash.hex(),
            "leaf_index": proof.leaf_index,
            "siblings": [(h.hex(), pos) for h, pos in proof.siblings],
            "root_hash": proof.root_hash.hex(),
            "epoch": proof.epoch,
            "tree_size": proof.tree_size,
        }
        deserialized = deserialize_merkle_proof(data)
        assert deserialized.leaf_hash == proof.leaf_hash
        assert verify_proof(deserialized)

    def test_legacy_boolean_siblings(self):
        tree = MerkleTree([b"a", b"b"])
        proof = tree.generate_proof(0)
        data = {
            "leaf_hash": proof.leaf_hash.hex(),
            "leaf_index": proof.leaf_index,
            "siblings": [(h.hex(), True) for h, _ in proof.siblings],
            "root_hash": proof.root_hash.hex(),
        }
        deserialized = deserialize_merkle_proof(data)
        assert all(pos in ("left", "right") for _, pos in deserialized.siblings)


# ── merkle_leaf_hash (lines 722-723) ──


class TestMerkleLeafHash:
    def test_non_bytes_raises(self):
        with pytest.raises(ValueError, match="bytes"):
            merkle_leaf_hash("not bytes")

    def test_valid(self):
        result = merkle_leaf_hash(b"test")
        assert len(result) == 32
