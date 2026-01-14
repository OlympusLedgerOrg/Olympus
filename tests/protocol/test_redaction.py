"""
Comprehensive tests for protocol.redaction module.

Tests cover:
- Basic redaction operations
- Input immutability
- Edge cases (empty fields, non-existent paths, etc.)
- Merkle tree-based redaction proofs
- Redaction protocol verification
"""

import pytest

from protocol.redaction import (
    RedactionProof,
    RedactionProtocol,
    apply_redaction,
)


class TestApplyRedaction:
    """Tests for apply_redaction function."""

    @pytest.mark.parametrize(
        "original,mask,replacement,expected",
        [
            # Basic redaction
            ("ABCDE", [0, 1, 0, 1, 0], "█", "A█C█E"),
            # No redaction
            ("OLYMPUS", [0, 0, 0, 0, 0, 0, 0], "█", "OLYMPUS"),
            # Full redaction
            ("SECRET", [1, 1, 1, 1, 1, 1], "█", "██████"),
            # Custom replacement
            ("HELLO", [0, 1, 1, 1, 0], "*", "H***O"),
            # Single character
            ("A", [0], "█", "A"),
            ("A", [1], "█", "█"),
            # Empty string
            ("", [], "█", ""),
            # Multi-character replacement
            ("ABC", [0, 1, 0], "XXX", "AXXXC"),
        ],
    )
    def test_apply_redaction_basic(self, original, mask, replacement, expected):
        """Test basic redaction with various inputs."""
        result = apply_redaction(original, mask, replacement)
        assert result == expected

    def test_apply_redaction_immutable_input(self):
        """Test that original input is not modified."""
        original = "SECRET"
        mask = [1, 1, 1, 1, 1, 1]
        original_copy = original

        result = apply_redaction(original, mask, replacement="█")

        # Original should be unchanged
        assert original == original_copy
        assert original == "SECRET"
        # Result should be redacted
        assert result == "██████"

    def test_apply_redaction_mask_length_mismatch(self):
        """Test that mask length must match original length."""
        original = "HELLO"
        mask = [0, 1, 0]  # Too short

        with pytest.raises(ValueError, match="Mask length must equal original text length"):
            apply_redaction(original, mask)

    def test_apply_redaction_mask_too_long(self):
        """Test that mask cannot be longer than original."""
        original = "HI"
        mask = [0, 1, 0, 1, 0]  # Too long

        with pytest.raises(ValueError, match="Mask length must equal original text length"):
            apply_redaction(original, mask)

    def test_apply_redaction_invalid_mask_values(self):
        """Test that mask with values other than 0/1 still works (per implementation)."""
        # The current implementation only checks for == 1, so other values act like 0
        original = "ABC"
        mask = [0, 2, 0]  # 2 is not 1, so it won't redact

        result = apply_redaction(original, mask, replacement="█")
        assert result == "ABC"  # Nothing redacted because mask[1] != 1

    def test_apply_redaction_unicode(self):
        """Test redaction with unicode characters."""
        original = "Hello 世界"
        mask = [0, 0, 0, 0, 0, 0, 1, 1]
        result = apply_redaction(original, mask, replacement="█")
        assert result == "Hello ██"


class TestRedactionProtocol:
    """Tests for RedactionProtocol class."""

    def test_create_leaf_hashes(self):
        """Test creating leaf hashes from document parts."""
        parts = ["Part 1", "Part 2", "Part 3"]
        hashes = RedactionProtocol.create_leaf_hashes(parts)

        assert len(hashes) == 3
        assert all(isinstance(h, bytes) for h in hashes)
        assert all(len(h) == 32 for h in hashes)  # SHA-256 produces 32 bytes

    def test_create_leaf_hashes_empty(self):
        """Test creating leaf hashes with empty list."""
        parts: list[str] = []
        hashes = RedactionProtocol.create_leaf_hashes(parts)
        assert hashes == []

    def test_create_leaf_hashes_deterministic(self):
        """Test that same parts produce same hashes."""
        parts = ["Part 1", "Part 2"]
        hashes1 = RedactionProtocol.create_leaf_hashes(parts)
        hashes2 = RedactionProtocol.create_leaf_hashes(parts)

        assert hashes1 == hashes2

    def test_commit_document(self):
        """Test document commitment."""
        parts = ["Paragraph 1", "Paragraph 2", "Paragraph 3"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        assert tree is not None
        assert isinstance(root_hash, str)
        assert len(root_hash) == 64  # Hex-encoded SHA-256

    def test_commit_document_deterministic(self):
        """Test that same document produces same commitment."""
        parts = ["Para 1", "Para 2"]
        tree1, root1 = RedactionProtocol.commit_document(parts)
        tree2, root2 = RedactionProtocol.commit_document(parts)

        assert root1 == root2

    def test_create_redaction_proof(self):
        """Test creating redaction proof."""
        parts = ["Public info", "Secret data", "More public info"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        # Reveal only indices 0 and 2 (hide index 1)
        revealed_indices = [0, 2]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        assert isinstance(proof, RedactionProof)
        assert proof.original_root == root_hash
        assert proof.revealed_indices == revealed_indices
        assert len(proof.revealed_hashes) == 2
        assert len(proof.merkle_proofs) == 2

    def test_create_redaction_proof_all_revealed(self):
        """Test proof when all parts are revealed."""
        parts = ["Part 1", "Part 2"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        revealed_indices = [0, 1]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        assert len(proof.revealed_indices) == 2
        assert len(proof.revealed_hashes) == 2

    def test_create_redaction_proof_none_revealed(self):
        """Test proof when no parts are revealed."""
        parts = ["Part 1", "Part 2"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        revealed_indices: list[int] = []
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        assert len(proof.revealed_indices) == 0
        assert len(proof.revealed_hashes) == 0
        assert len(proof.merkle_proofs) == 0

    def test_verify_redaction_proof_valid(self):
        """Test verifying a valid redaction proof."""
        parts = ["Public", "Secret", "Data"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        revealed_indices = [0, 2]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        revealed_content = ["Public", "Data"]
        is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)

        assert is_valid is True

    def test_verify_redaction_proof_wrong_content(self):
        """Test that proof fails with wrong content."""
        parts = ["Public", "Secret", "Data"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        revealed_indices = [0, 2]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        # Wrong content
        revealed_content = ["Wrong", "Content"]
        is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)

        assert is_valid is False

    def test_verify_redaction_proof_length_mismatch(self):
        """Test that proof fails when revealed content length doesn't match."""
        parts = ["A", "B", "C"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        revealed_indices = [0, 2]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        # Too few items
        revealed_content = ["A"]
        is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)
        assert is_valid is False

        # Too many items
        revealed_content = ["A", "B", "C"]
        is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)
        assert is_valid is False

    def test_reconstruct_redacted_document(self):
        """Test reconstructing document with redaction markers."""
        revealed_content = ["Public", "Info"]
        revealed_indices = [0, 2]
        total_parts = 4

        result = RedactionProtocol.reconstruct_redacted_document(
            revealed_content, revealed_indices, total_parts, redaction_marker="[REDACTED]"
        )

        assert result == ["Public", "[REDACTED]", "Info", "[REDACTED]"]

    def test_reconstruct_redacted_document_all_revealed(self):
        """Test reconstruction when all parts revealed."""
        revealed_content = ["A", "B", "C"]
        revealed_indices = [0, 1, 2]
        total_parts = 3

        result = RedactionProtocol.reconstruct_redacted_document(
            revealed_content, revealed_indices, total_parts
        )

        assert result == ["A", "B", "C"]

    def test_reconstruct_redacted_document_none_revealed(self):
        """Test reconstruction when no parts revealed."""
        revealed_content: list[str] = []
        revealed_indices: list[int] = []
        total_parts = 3

        result = RedactionProtocol.reconstruct_redacted_document(
            revealed_content, revealed_indices, total_parts
        )

        assert result == ["[REDACTED]", "[REDACTED]", "[REDACTED]"]

    def test_reconstruct_redacted_document_custom_marker(self):
        """Test reconstruction with custom marker."""
        revealed_content = ["X"]
        revealed_indices = [1]
        total_parts = 3

        result = RedactionProtocol.reconstruct_redacted_document(
            revealed_content, revealed_indices, total_parts, redaction_marker="***"
        )

        assert result == ["***", "X", "***"]


class TestRedactionProofDataclass:
    """Tests for RedactionProof dataclass."""

    def test_redaction_proof_creation(self):
        """Test creating RedactionProof instance."""
        proof = RedactionProof(
            original_root="abc123",
            revealed_indices=[0, 2],
            revealed_hashes=["hash1", "hash2"],
            merkle_proofs=[],
        )

        assert proof.original_root == "abc123"
        assert proof.revealed_indices == [0, 2]
        assert proof.revealed_hashes == ["hash1", "hash2"]
        assert proof.merkle_proofs == []


class TestEndToEndRedactionScenario:
    """End-to-end tests for complete redaction scenarios."""

    def test_complete_redaction_workflow(self):
        """Test complete workflow: commit -> redact -> prove -> verify."""
        # 1. Original document
        document_parts = [
            "This is public information.",
            "CLASSIFIED: Secret operation details.",
            "This is also public.",
            "CLASSIFIED: More secrets.",
            "Public conclusion.",
        ]

        # 2. Commit to document
        tree, root_hash = RedactionProtocol.commit_document(document_parts)

        # 3. Create redaction (reveal only public parts: indices 0, 2, 4)
        revealed_indices = [0, 2, 4]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        # 4. Prepare revealed content
        revealed_content = [
            "This is public information.",
            "This is also public.",
            "Public conclusion.",
        ]

        # 5. Verify proof
        is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)
        assert is_valid is True

        # 6. Reconstruct redacted document
        redacted_doc = RedactionProtocol.reconstruct_redacted_document(
            revealed_content, revealed_indices, len(document_parts)
        )

        expected = [
            "This is public information.",
            "[REDACTED]",
            "This is also public.",
            "[REDACTED]",
            "Public conclusion.",
        ]
        assert redacted_doc == expected

    def test_tampered_proof_fails(self):
        """Test that tampering with proof causes verification to fail."""
        parts = ["A", "B", "C"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        revealed_indices = [0, 2]
        proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

        # Tamper with the proof by changing the root
        proof.original_root = "0" * 64

        revealed_content = ["A", "C"]
        is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)

        assert is_valid is False

    def test_single_part_document(self):
        """Test redaction with single-part document."""
        parts = ["Only one part"]
        tree, root_hash = RedactionProtocol.commit_document(parts)

        # Reveal it
        proof = RedactionProtocol.create_redaction_proof(tree, [0])
        is_valid = RedactionProtocol.verify_redaction_proof(proof, ["Only one part"])
        assert is_valid is True

        # Hide it
        proof_hidden = RedactionProtocol.create_redaction_proof(tree, [])
        redacted = RedactionProtocol.reconstruct_redacted_document([], [], 1)
        assert redacted == ["[REDACTED]"]
