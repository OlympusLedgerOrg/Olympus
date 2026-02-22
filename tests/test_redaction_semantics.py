"""
Tests for redaction protocol.

Validates:
- Redaction mask semantics
- Merkle-based redaction proof creation
- Independent proof verification
- Edge cases and error handling
"""

import pytest

from protocol.hashes import hash_bytes
from protocol.merkle import MerkleProof
from protocol.redaction import RedactionProof, RedactionProtocol, apply_redaction


def test_redaction_mask_semantics():
    original = "ABCDE"
    mask = [0, 1, 0, 1, 0]  # redact B and D

    redacted = apply_redaction(original, mask, replacement="█")

    assert redacted == "A█C█E"


def test_redaction_does_not_modify_kept_text():
    original = "OLYMPUS"
    mask = [0] * len(original)

    redacted = apply_redaction(original, mask, replacement="█")

    assert redacted == original


def test_redaction_mask_length_mismatch():
    """Test that mask must match text length."""
    original = "OLYMPUS"
    mask = [0, 1, 0]  # Too short

    with pytest.raises(ValueError, match="Mask length must equal original text length"):
        apply_redaction(original, mask)


def test_redaction_protocol_commit_document():
    """Test creating a cryptographic commitment to a document."""
    document_parts = ["Section A", "Section B", "Section C"]

    tree, root_hash = RedactionProtocol.commit_document(document_parts)

    # Root hash should be deterministic
    assert isinstance(root_hash, str)
    assert len(root_hash) == 64  # BLAKE3 hex is 64 chars
    assert root_hash == tree.get_root().hex()


def test_redaction_protocol_commit_does_not_mutate_parts():
    """Test that committing does not mutate the input parts list."""
    document_parts = ["Alpha", "Beta", "Gamma"]
    original_parts = list(document_parts)

    RedactionProtocol.commit_document(document_parts)

    assert document_parts == original_parts


def test_redaction_protocol_proof_deterministic():
    """Test that redaction proofs are deterministic for the same inputs."""
    document_parts = ["Red", "Green", "Blue"]
    revealed_indices = [0, 2]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof1 = RedactionProtocol.create_redaction_proof(tree, revealed_indices)
    proof2 = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    assert proof1 == proof2


def test_redaction_protocol_create_proof():
    """Test creating a redaction proof for partial document reveal."""
    document_parts = ["Secret A", "Public B", "Secret C", "Public D"]
    revealed_indices = [1, 3]  # Reveal only parts 1 and 3

    tree, root_hash = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Verify proof structure
    assert proof.original_root == root_hash
    assert proof.revealed_indices == revealed_indices
    assert len(proof.revealed_hashes) == len(revealed_indices)
    assert len(proof.merkle_proofs) == len(revealed_indices)

    # Verify revealed hashes match the content
    for i, idx in enumerate(revealed_indices):
        expected_hash = hash_bytes(document_parts[idx].encode("utf-8")).hex()
        assert proof.revealed_hashes[i] == expected_hash


def test_redaction_protocol_verify_valid_proof():
    """Test verification of a valid redaction proof."""
    document_parts = ["Sensitive", "Public", "Classified", "Unclassified"]
    revealed_indices = [1, 3]
    revealed_content = ["Public", "Unclassified"]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Proof should verify successfully
    is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)
    assert is_valid is True


def test_redaction_protocol_verify_tampered_content():
    """Test that verification fails if revealed content is tampered."""
    document_parts = ["Sensitive", "Public", "Classified", "Unclassified"]
    revealed_indices = [1, 3]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Tamper with revealed content
    tampered_content = ["Modified", "Unclassified"]

    is_valid = RedactionProtocol.verify_redaction_proof(proof, tampered_content)
    assert is_valid is False


def test_redaction_protocol_verify_wrong_content_count():
    """Test that verification fails if content count doesn't match."""
    document_parts = ["Sensitive", "Public", "Classified"]
    revealed_indices = [1]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Try to verify with wrong number of revealed items
    wrong_content = ["Public", "Extra"]

    is_valid = RedactionProtocol.verify_redaction_proof(proof, wrong_content)
    assert is_valid is False


def test_redaction_protocol_verify_all_revealed():
    """Test proof when entire document is revealed."""
    document_parts = ["Part 1", "Part 2", "Part 3"]
    revealed_indices = [0, 1, 2]  # Reveal everything

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    is_valid = RedactionProtocol.verify_redaction_proof(proof, document_parts)
    assert is_valid is True


def test_redaction_protocol_verify_none_revealed():
    """Test proof when nothing is revealed."""
    document_parts = ["Secret 1", "Secret 2", "Secret 3"]
    revealed_indices = []  # Reveal nothing

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    is_valid = RedactionProtocol.verify_redaction_proof(proof, [])
    assert is_valid is True


def test_redaction_protocol_reconstruct_redacted_document():
    """Test reconstructing a document with redaction markers."""
    document_parts = ["Part A", "Part B", "Part C", "Part D"]
    revealed_indices = [0, 2]  # Reveal parts 0 and 2
    revealed_content = ["Part A", "Part C"]

    result = RedactionProtocol.reconstruct_redacted_document(
        revealed_content, revealed_indices, len(document_parts), redaction_marker="[REDACTED]"
    )

    assert result == ["Part A", "[REDACTED]", "Part C", "[REDACTED]"]


def test_redaction_protocol_reconstruct_with_missing_revealed_content():
    """Test reconstruction when revealed content is missing indices."""
    revealed_content = ["Visible"]
    revealed_indices = [0, 2]

    result = RedactionProtocol.reconstruct_redacted_document(
        revealed_content, revealed_indices, total_parts=3, redaction_marker="[REDACTED]"
    )

    assert result == ["Visible", "[REDACTED]", "[REDACTED]"]


def test_redaction_protocol_reconstruct_with_custom_marker():
    """Test reconstruction with custom redaction marker."""
    revealed_content = ["Visible"]
    revealed_indices = [1]
    total_parts = 3

    result = RedactionProtocol.reconstruct_redacted_document(
        revealed_content, revealed_indices, total_parts, redaction_marker="█████"
    )

    assert result == ["█████", "Visible", "█████"]


def test_redaction_protocol_single_part_document():
    """Test redaction with single-part document."""
    document_parts = ["Only Part"]

    tree, root_hash = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, [0])

    is_valid = RedactionProtocol.verify_redaction_proof(proof, document_parts)
    assert is_valid is True


def test_redaction_protocol_deterministic_commitment():
    """Test that commitments are deterministic."""
    document_parts = ["A", "B", "C"]

    tree1, root1 = RedactionProtocol.commit_document(document_parts)
    tree2, root2 = RedactionProtocol.commit_document(document_parts)

    assert root1 == root2


def test_redaction_protocol_different_documents_different_roots():
    """Test that different documents produce different roots."""
    doc1 = ["A", "B", "C"]
    doc2 = ["A", "B", "D"]  # Only last part differs

    _, root1 = RedactionProtocol.commit_document(doc1)
    _, root2 = RedactionProtocol.commit_document(doc2)

    assert root1 != root2


def test_redaction_proof_independence():
    """Test that proofs can be verified independently without original tree."""
    document_parts = ["Sensitive Info", "Public Info"]
    revealed_indices = [1]
    revealed_content = ["Public Info"]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Verification should work with just the proof and revealed content
    # No access to original tree needed
    is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)
    assert is_valid is True


def test_redaction_proof_verification_mismatched_revealed_count():
    """Test that proof verification fails when revealed_content count mismatches."""
    document_parts = ["Part A", "Part B", "Part C"]
    revealed_indices = [0, 2]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Try to verify with wrong number of revealed items
    wrong_revealed = ["Part A"]  # Should be 2 items, not 1
    is_valid = RedactionProtocol.verify_redaction_proof(proof, wrong_revealed)
    assert is_valid is False


def test_redaction_proof_verification_wrong_content():
    """Test that proof verification fails with wrong revealed content."""
    document_parts = ["Correct A", "Correct B"]
    revealed_indices = [0, 1]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Try to verify with wrong content
    wrong_content = ["Wrong A", "Wrong B"]
    is_valid = RedactionProtocol.verify_redaction_proof(proof, wrong_content)
    assert is_valid is False


def test_redaction_proof_tampered_revealed_hashes_length():
    """Test that verification fails when revealed_hashes length is inconsistent with indices."""
    document_parts = ["Part A", "Part B", "Part C"]
    revealed_indices = [0, 2]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Tamper the proof: keep indices at length 2 but truncate revealed_hashes to length 1
    tampered_proof = RedactionProof(
        original_root=proof.original_root,
        revealed_indices=proof.revealed_indices,
        revealed_hashes=proof.revealed_hashes[:1],  # shorter than indices
        merkle_proofs=proof.merkle_proofs,
    )

    # revealed_content has 2 items matching indices, but revealed_hashes only has 1
    is_valid = RedactionProtocol.verify_redaction_proof(tampered_proof, ["Part A", "Part C"])
    assert is_valid is False


def test_redaction_proof_tampered_merkle_proofs_length():
    """Test that verification fails when merkle_proofs length is inconsistent."""
    document_parts = ["Part A", "Part B", "Part C"]
    revealed_indices = [0, 2]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Tamper the proof: keep indices and hashes at length 2 but truncate merkle_proofs to length 1
    tampered_proof = RedactionProof(
        original_root=proof.original_root,
        revealed_indices=proof.revealed_indices,
        revealed_hashes=proof.revealed_hashes,
        merkle_proofs=proof.merkle_proofs[:1],  # shorter than indices
    )

    # revealed_content has 2 items, but merkle_proofs only has 1
    is_valid = RedactionProtocol.verify_redaction_proof(tampered_proof, ["Part A", "Part C"])
    assert is_valid is False


def test_redaction_proof_tampered_merkle_proof_siblings():
    """Test that verification fails when Merkle proof siblings are tampered."""
    document_parts = ["Part A", "Part B", "Part C"]
    revealed_indices = [0]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Tamper the Merkle proof by corrupting its sibling hash
    original_mp = proof.merkle_proofs[0]
    fake_sibling = b"\x00" * 32
    tampered_siblings = [(fake_sibling, is_right) for _, is_right in original_mp.siblings]
    tampered_mp = MerkleProof(
        leaf_hash=original_mp.leaf_hash,
        leaf_index=original_mp.leaf_index,
        siblings=tampered_siblings,
        root_hash=original_mp.root_hash,
    )
    tampered_proof = RedactionProof(
        original_root=proof.original_root,
        revealed_indices=proof.revealed_indices,
        revealed_hashes=proof.revealed_hashes,
        merkle_proofs=[tampered_mp],
    )

    is_valid = RedactionProtocol.verify_redaction_proof(tampered_proof, ["Part A"])
    assert is_valid is False


def test_redaction_proof_mismatched_root_hash():
    """Test that verification fails when Merkle proof root hash differs from claimed root."""
    document_parts = ["Part A", "Part B"]
    revealed_indices = [0]

    tree, _ = RedactionProtocol.commit_document(document_parts)
    proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)

    # Build a proof where original_root claims a different root than the Merkle proof contains
    tampered_proof = RedactionProof(
        original_root="a" * 64,  # wrong root
        revealed_indices=proof.revealed_indices,
        revealed_hashes=proof.revealed_hashes,
        merkle_proofs=proof.merkle_proofs,
    )

    is_valid = RedactionProtocol.verify_redaction_proof(tampered_proof, ["Part A"])
    assert is_valid is False


def test_apply_redaction_fully_redacted():
    """Test apply_redaction when all characters are redacted."""
    original = "SECRET"
    mask = [1] * len(original)

    redacted = apply_redaction(original, mask, replacement="█")

    assert redacted == "██████"


def test_apply_redaction_empty_string():
    """Test apply_redaction with an empty string."""
    original = ""
    mask = []

    redacted = apply_redaction(original, mask, replacement="█")

    assert redacted == ""


def test_create_leaf_hashes_deterministic():
    """Test that create_leaf_hashes produces consistent, deterministic results."""
    parts = ["alpha", "beta", "gamma"]
    hashes1 = RedactionProtocol.create_leaf_hashes(parts)
    hashes2 = RedactionProtocol.create_leaf_hashes(parts)

    assert hashes1 == hashes2
    assert all(isinstance(h, bytes) for h in hashes1)
    assert len(hashes1) == len(parts)


def test_create_leaf_hashes_unique_per_part():
    """Test that distinct document parts produce distinct leaf hashes."""
    parts = ["apple", "orange", "banana"]
    hashes = RedactionProtocol.create_leaf_hashes(parts)

    assert len(set(hashes)) == len(parts)
