"""
Tests for ZK hardening improvements.

Covers:
  1. Domain-separated Poseidon hashing
  2. Proper SMT non-membership with default hash chain
  3. Range checks (index bounds)
  4. Structured canonicalization (sectionCount, sectionLength, sectionHash)
  5. Redaction correctness proof (binding original + redacted commitments)
  6. Index bounds (leafIndex < treeSize)
"""

import pytest

from protocol.hashes import SNARK_SCALAR_FIELD, hash_bytes
from protocol.poseidon_bn128 import poseidon_hash_bn128
from protocol.poseidon_tree import (
    POSEIDON_DOMAIN_COMMITMENT,
    POSEIDON_DOMAIN_LEAF,
    POSEIDON_DOMAIN_NODE,
    PoseidonMerkleTree,
    build_poseidon_witness_inputs,
    poseidon_hash_with_domain,
)
from protocol.redaction import (
    RedactionCorrectnessProof,
    RedactionProtocol,
    SectionMetadata,
)
from protocol.ssmf import (
    EMPTY_HASHES,
    NonExistenceProof,
    SparseMerkleTree,
    verify_nonexistence_proof,
)


# ====================================================================
# 1. Domain-separated Poseidon
# ====================================================================


class TestDomainSeparatedPoseidon:
    """Test that domain tags prevent cross-context hash collisions."""

    def test_different_domains_produce_different_hashes(self):
        """Poseidon(left, right) with different domain tags must differ."""
        left, right = 42, 99
        h_leaf = poseidon_hash_with_domain(left, right, POSEIDON_DOMAIN_LEAF)
        h_node = poseidon_hash_with_domain(left, right, POSEIDON_DOMAIN_NODE)
        h_commit = poseidon_hash_with_domain(left, right, POSEIDON_DOMAIN_COMMITMENT)

        assert h_leaf != h_node, "LEAF and NODE domains must produce different hashes"
        assert h_leaf != h_commit, "LEAF and COMMITMENT domains must produce different hashes"
        assert h_node != h_commit, "NODE and COMMITMENT domains must produce different hashes"

    def test_domain_hash_is_deterministic(self):
        """Same inputs + same domain must always produce the same hash."""
        left, right, domain = 123, 456, POSEIDON_DOMAIN_NODE
        h1 = poseidon_hash_with_domain(left, right, domain)
        h2 = poseidon_hash_with_domain(left, right, domain)
        assert h1 == h2

    def test_domain_hash_in_field(self):
        """Domain-separated hash must be within the BN128 field."""
        h = poseidon_hash_with_domain(1, 2, POSEIDON_DOMAIN_NODE)
        assert 0 <= h < SNARK_SCALAR_FIELD

    def test_domain_hash_differs_from_raw_poseidon(self):
        """Domain-separated hash must differ from raw Poseidon(left, right)."""
        left, right = 42, 99
        raw = poseidon_hash_bn128(left, right)
        domain_tagged = poseidon_hash_with_domain(left, right, POSEIDON_DOMAIN_NODE)
        assert raw != domain_tagged, "Domain-separated hash must differ from raw Poseidon"

    def test_merkle_tree_uses_plain_poseidon(self):
        """PoseidonMerkleTree must use plain Poseidon(2) for internal nodes (matching circuit)."""
        leaves = [10, 20]
        tree = PoseidonMerkleTree(leaves)
        root = int(tree.get_root())

        # Manually compute with plain Poseidon (matching merkleProof.circom)
        left = 10 % SNARK_SCALAR_FIELD
        right = 20 % SNARK_SCALAR_FIELD
        expected = poseidon_hash_bn128(left, right)
        assert root == expected % SNARK_SCALAR_FIELD

    def test_domain_constants_are_distinct(self):
        """Domain tag constants must be distinct."""
        tags = {POSEIDON_DOMAIN_LEAF, POSEIDON_DOMAIN_NODE, POSEIDON_DOMAIN_COMMITMENT}
        assert len(tags) == 3, "All domain tags must be distinct"


# ====================================================================
# 2. Proper SMT non-membership with default hash chain
# ====================================================================


class TestSMTNonMembership:
    """Test SMT non-existence proofs use the default hash chain correctly."""

    def test_empty_tree_nonexistence_proof(self):
        """Non-existence proof in empty tree should verify."""
        tree = SparseMerkleTree()
        key = b"\x00" * 32
        proof = tree.prove_nonexistence(key)

        assert isinstance(proof, NonExistenceProof)
        assert verify_nonexistence_proof(proof) is True

    def test_nonempty_tree_nonexistence_proof(self):
        """Non-existence proof for missing key in non-empty tree should verify."""
        tree = SparseMerkleTree()
        key_exists = b"\x01" * 32
        key_missing = b"\x02" * 32
        tree.update(key_exists, hash_bytes(b"value"))

        proof = tree.prove_nonexistence(key_missing)
        assert verify_nonexistence_proof(proof) is True

    def test_nonexistence_starts_with_empty_leaf_sentinel(self):
        """Non-existence uses EMPTY_HASHES[0] as the leaf sentinel."""
        from protocol.ssmf import EMPTY_LEAF

        # EMPTY_HASHES[0] should be the domain-separated empty leaf hash
        assert EMPTY_HASHES[0] == EMPTY_LEAF
        assert len(EMPTY_HASHES[0]) == 32

    def test_nonexistence_default_hash_chain_structure(self):
        """Precomputed empty hashes form a valid default hash chain."""
        from protocol.hashes import node_hash

        for level in range(1, 257):
            expected = node_hash(EMPTY_HASHES[level - 1], EMPTY_HASHES[level - 1])
            assert EMPTY_HASHES[level] == expected, (
                f"EMPTY_HASHES[{level}] does not match "
                f"node_hash(EMPTY_HASHES[{level - 1}], EMPTY_HASHES[{level - 1}])"
            )

    def test_tampered_nonexistence_proof_fails(self):
        """Tampered non-existence proof must fail verification."""
        tree = SparseMerkleTree()
        key = b"\x00" * 32
        proof = tree.prove_nonexistence(key)

        # Tamper with a sibling
        tampered_siblings = list(proof.siblings)
        tampered_siblings[0] = b"\xff" * 32
        tampered = NonExistenceProof(
            key=proof.key,
            siblings=tampered_siblings,
            root_hash=proof.root_hash,
        )
        assert verify_nonexistence_proof(tampered) is False


# ====================================================================
# 3. Range checks / Index bounds (leafIndex < treeSize)
# ====================================================================


class TestIndexBounds:
    """Test that index bounds are enforced in the Python protocol layer."""

    def test_build_witness_rejects_out_of_bounds_index(self):
        """build_poseidon_witness_inputs must reject out-of-bounds target_index."""
        leaves = [b"a", b"b"]
        with pytest.raises(ValueError, match="out of bounds"):
            build_poseidon_witness_inputs(leaves, target_index=5)

    def test_build_witness_rejects_negative_index(self):
        """build_poseidon_witness_inputs must reject negative target_index."""
        leaves = [b"a", b"b"]
        with pytest.raises(ValueError, match="out of bounds"):
            build_poseidon_witness_inputs(leaves, target_index=-1)

    def test_build_witness_includes_tree_size(self):
        """build_poseidon_witness_inputs must include tree_size in the proof."""
        leaves = [b"a", b"b", b"c", b"d"]
        proof = build_poseidon_witness_inputs(leaves, target_index=0)
        assert proof.tree_size == 4

    def test_tree_size_with_depth_padding(self):
        """tree_size includes padded leaves when depth is specified."""
        leaves = [b"a", b"b"]
        proof = build_poseidon_witness_inputs(leaves, target_index=0, depth=3)
        assert proof.tree_size == 8  # 2^3 = 8

    def test_poseidon_tree_tree_size_property(self):
        """PoseidonMerkleTree.tree_size returns the number of leaves."""
        tree = PoseidonMerkleTree([1, 2, 3, 4])
        assert tree.tree_size == 4

    def test_poseidon_tree_proof_rejects_out_of_bounds(self):
        """PoseidonMerkleTree.get_proof must reject out-of-bounds index."""
        tree = PoseidonMerkleTree([1, 2])
        with pytest.raises(ValueError, match="Invalid leaf index"):
            tree.get_proof(2)

    def test_boundary_index_is_valid(self):
        """Last valid index (tree_size - 1) must be accepted."""
        leaves = [b"a", b"b", b"c"]
        tree = PoseidonMerkleTree(leaves)
        # Should not raise
        tree.get_proof(len(leaves) - 1)


# ====================================================================
# 4. Structured canonicalization (sectionCount, sectionLength, sectionHash)
# ====================================================================


class TestStructuredCanonicalization:
    """Test structured canonicalization metadata."""

    def test_build_section_metadata_structure(self):
        """build_section_metadata returns correct metadata for each section."""
        parts = ["Hello world", "Second section"]
        metadata = RedactionProtocol.build_section_metadata(parts)

        assert len(metadata) == 2
        for i, meta in enumerate(metadata):
            assert isinstance(meta, SectionMetadata)
            assert meta.section_index == i
            assert meta.section_count == 2
            assert meta.section_length > 0
            assert len(meta.section_hash) == 64  # hex string of 32 bytes

    def test_section_metadata_lengths_match_canonical_bytes(self):
        """Section lengths must match the canonical byte representation."""
        parts = ["Hello world", "Second"]
        metadata = RedactionProtocol.build_section_metadata(parts)
        canonical_bytes = RedactionProtocol.canonical_section_bytes_list(parts)

        for meta, section_bytes in zip(metadata, canonical_bytes):
            assert meta.section_length == len(section_bytes)

    def test_section_metadata_hashes_match(self):
        """Section hashes must match BLAKE3 of canonical bytes."""
        parts = ["Test section"]
        metadata = RedactionProtocol.build_section_metadata(parts)
        canonical_bytes = RedactionProtocol.canonical_section_bytes_list(parts)

        expected_hash = hash_bytes(canonical_bytes[0]).hex()
        assert metadata[0].section_hash == expected_hash

    def test_structured_commitment_is_deterministic(self):
        """Same document parts must produce the same structured commitment."""
        parts = ["Part A", "Part B", "Part C"]
        c1 = RedactionProtocol.structured_canonical_commitment(parts)
        c2 = RedactionProtocol.structured_canonical_commitment(parts)
        assert c1 == c2

    def test_different_documents_produce_different_commitments(self):
        """Different document parts must produce different commitments."""
        parts1 = ["Part A", "Part B"]
        parts2 = ["Part A", "Part C"]
        c1 = RedactionProtocol.structured_canonical_commitment(parts1)
        c2 = RedactionProtocol.structured_canonical_commitment(parts2)
        assert c1 != c2

    def test_different_section_counts_produce_different_commitments(self):
        """Different section counts must produce different commitments."""
        parts1 = ["Part A", "Part B"]
        parts2 = ["Part A"]
        c1 = RedactionProtocol.structured_canonical_commitment(parts1)
        c2 = RedactionProtocol.structured_canonical_commitment(parts2)
        assert c1 != c2

    def test_reordered_sections_produce_different_commitments(self):
        """Reordered sections must produce different commitments."""
        parts1 = ["Alpha", "Beta"]
        parts2 = ["Beta", "Alpha"]
        c1 = RedactionProtocol.structured_canonical_commitment(parts1)
        c2 = RedactionProtocol.structured_canonical_commitment(parts2)
        assert c1 != c2

    def test_structured_commitment_is_field_element(self):
        """Structured commitment must be a valid BN128 field element."""
        parts = ["A section"]
        c = RedactionProtocol.structured_canonical_commitment(parts)
        assert 0 <= int(c) < SNARK_SCALAR_FIELD


# ====================================================================
# 5. Redaction correctness proof
# ====================================================================


class TestRedactionCorrectnessProof:
    """Test binding of original + redacted commitments."""

    def test_create_correctness_proof(self):
        """create_redaction_correctness_proof must return a valid proof."""
        parts = ["Section 1", "Section 2", "Section 3"]
        proof = RedactionProtocol.create_redaction_correctness_proof(parts, [0, 2])

        assert isinstance(proof, RedactionCorrectnessProof)
        assert len(proof.original_blake3_root) == 64
        assert len(proof.redacted_blake3_root) == 64
        assert proof.original_blake3_root != proof.redacted_blake3_root
        assert proof.revealed_indices == [0, 2]
        assert len(proof.binding_hash) == 64

    def test_verify_correctness_proof(self):
        """verify_redaction_correctness_proof must accept valid proof."""
        parts = ["Section 1", "Section 2", "Section 3"]
        proof = RedactionProtocol.create_redaction_correctness_proof(parts, [0, 2])
        assert RedactionProtocol.verify_redaction_correctness_proof(proof) is True

    def test_tampered_correctness_proof_fails(self):
        """Tampered correctness proof must fail verification."""
        parts = ["Section 1", "Section 2"]
        proof = RedactionProtocol.create_redaction_correctness_proof(parts, [0])

        tampered = RedactionCorrectnessProof(
            original_blake3_root=proof.original_blake3_root,
            redacted_blake3_root="ff" * 32,  # tampered
            original_poseidon_root=proof.original_poseidon_root,
            redacted_poseidon_root=proof.redacted_poseidon_root,
            revealed_indices=proof.revealed_indices,
            binding_hash=proof.binding_hash,
        )
        assert RedactionProtocol.verify_redaction_correctness_proof(tampered) is False

    def test_correctness_proof_binds_both_hash_types(self):
        """Proof must bind both BLAKE3 and Poseidon roots."""
        parts = ["Alpha", "Beta"]
        proof = RedactionProtocol.create_redaction_correctness_proof(parts, [0])

        assert proof.original_poseidon_root != proof.redacted_poseidon_root
        # Poseidon roots should be valid decimal strings
        int(proof.original_poseidon_root)
        int(proof.redacted_poseidon_root)

    def test_correctness_proof_rejects_invalid_indices(self):
        """Out-of-bounds revealed indices must raise ValueError."""
        parts = ["A", "B"]
        with pytest.raises(ValueError, match="within the document length"):
            RedactionProtocol.create_redaction_correctness_proof(parts, [5])

    def test_correctness_proof_all_revealed(self):
        """Proof with all sections revealed is valid."""
        parts = ["Section 1", "Section 2"]
        proof = RedactionProtocol.create_redaction_correctness_proof(parts, [0, 1])
        assert RedactionProtocol.verify_redaction_correctness_proof(proof) is True

    def test_correctness_proof_none_revealed(self):
        """Proof with no sections revealed is valid."""
        parts = ["Section 1", "Section 2"]
        proof = RedactionProtocol.create_redaction_correctness_proof(parts, [])
        assert RedactionProtocol.verify_redaction_correctness_proof(proof) is True


# ====================================================================
# 6. Integration: domain separation + tree operations
# ====================================================================


class TestDomainSeparationIntegration:
    """Integration tests verifying Poseidon tree operations."""

    def test_proof_roundtrip_with_plain_poseidon(self):
        """Full proof roundtrip using plain Poseidon (matching circuit)."""
        leaves = [b"doc_part_1", b"doc_part_2", b"doc_part_3", b"doc_part_4"]
        proof = build_poseidon_witness_inputs(leaves, target_index=2)

        # Verify proof by reconstructing root using plain Poseidon (matching circuit)
        current = int(proof.leaf) % SNARK_SCALAR_FIELD
        for sibling, idx in zip(proof.path_elements, proof.path_indices):
            sib = int(sibling) % SNARK_SCALAR_FIELD
            if idx == 0:
                current = poseidon_hash_bn128(current, sib)
            else:
                current = poseidon_hash_bn128(sib, current)
            current %= SNARK_SCALAR_FIELD

        assert str(current % SNARK_SCALAR_FIELD) == proof.root

    def test_poseidon_tree_root_deterministic(self):
        """Same leaves always produce the same root."""
        leaves = [b"a", b"b", b"c"]
        t1 = PoseidonMerkleTree(leaves)
        t2 = PoseidonMerkleTree(leaves)
        assert t1.get_root() == t2.get_root()

    def test_different_leaves_different_roots(self):
        """Different leaves must produce different roots."""
        t1 = PoseidonMerkleTree([b"a", b"b"])
        t2 = PoseidonMerkleTree([b"c", b"d"])
        assert t1.get_root() != t2.get_root()
