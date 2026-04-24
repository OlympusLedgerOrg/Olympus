"""
Tests for cross-root validation (protocol/cross_root_validation.py).

Coverage:
- extract_blake3_root: valid extraction, type/value errors
- extract_poseidon_root: valid extraction, field-element validation
- verify_against_dual_commitment: matching, mismatched, malformed inputs
- _verify_poseidon_proof: valid proofs, tampered proofs, malformed inputs
- validate_proof_consistency: all pass, various failure modes
- check_proof_consistency: detailed diagnostic results for every error type
- Edge cases: empty proofs, corrupted data, wrong-document mixing
"""

import pytest

from protocol import cross_root_validation as cross_root_validation_module
from protocol.cross_root_validation import (
    ConsistencyError,
    ConsistencyResult,
    _verify_poseidon_proof,
    check_proof_consistency,
    extract_blake3_root,
    extract_poseidon_root,
    validate_proof_consistency,
    verify_against_dual_commitment,
)
from protocol.hashes import SNARK_SCALAR_FIELD, blake3_to_field_element, hash_bytes
from protocol.merkle import MerkleProof, MerkleTree
from protocol.poseidon_tree import PoseidonMerkleTree, PoseidonProof
from protocol.redaction import RedactionProtocol
from protocol.redaction_ledger import DualHashCommitment


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_blake3_proof(parts: list[str], leaf_index: int = 0) -> tuple[MerkleProof, bytes]:
    """Return (MerkleProof, blake3_root_bytes) for the given document parts."""
    canonical = RedactionProtocol.canonical_section_bytes_list(parts)
    leaf_hashes = [hash_bytes(c) for c in canonical]
    tree = MerkleTree(leaf_hashes)
    proof = tree.generate_proof(leaf_index)
    return proof, tree.get_root()


def _make_poseidon_proof(parts: list[str], leaf_index: int = 0) -> tuple[PoseidonProof, str]:
    """Return (PoseidonProof, poseidon_root_decimal) for the given document parts."""
    canonical = RedactionProtocol.canonical_section_bytes_list(parts)
    leaves = [int(blake3_to_field_element(c)) for c in canonical]
    tree = PoseidonMerkleTree(leaves, depth=4)
    path_elements, path_indices = tree.get_proof(leaf_index)
    proof = PoseidonProof(
        root=tree.get_root(),
        leaf=str(leaves[leaf_index]),
        leaf_index=leaf_index,
        path_elements=path_elements,
        path_indices=path_indices,
        tree_size=tree.tree_size,
    )
    return proof, tree.get_root()


def _make_dual_commitment(parts: list[str]) -> DualHashCommitment:
    """Build a real DualHashCommitment for the given document parts."""
    canonical = RedactionProtocol.canonical_section_bytes_list(parts)
    leaf_hashes = [hash_bytes(c) for c in canonical]
    tree = MerkleTree(leaf_hashes)
    blake3_root = tree.get_root().hex()

    leaves = [int(blake3_to_field_element(c)) for c in canonical]
    poseidon_root = PoseidonMerkleTree(leaves, depth=4).get_root()
    return DualHashCommitment(blake3_root=blake3_root, poseidon_root=poseidon_root)


PARTS_A = ["alpha", "beta", "gamma"]
PARTS_B = ["delta", "epsilon", "zeta"]


# ---------------------------------------------------------------------------
# extract_blake3_root
# ---------------------------------------------------------------------------


def test_extract_blake3_root_returns_root_hash():
    proof, root = _make_blake3_proof(PARTS_A)
    assert extract_blake3_root(proof) == root


def test_extract_blake3_root_is_32_bytes():
    proof, _ = _make_blake3_proof(PARTS_A)
    result = extract_blake3_root(proof)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_extract_blake3_root_rejects_non_proof():
    with pytest.raises(TypeError, match="Expected MerkleProof"):
        extract_blake3_root("not a proof")  # type: ignore[arg-type]


def test_extract_blake3_root_rejects_none():
    with pytest.raises(TypeError, match="Expected MerkleProof"):
        extract_blake3_root(None)  # type: ignore[arg-type]


def test_extract_blake3_root_rejects_wrong_root_hash_length():
    proof, _ = _make_blake3_proof(PARTS_A)
    bad_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=proof.siblings,
        root_hash=b"\x00" * 16,  # 16 bytes instead of 32
    )
    with pytest.raises(ValueError, match="32 bytes"):
        extract_blake3_root(bad_proof)


def test_extract_blake3_root_rejects_non_bytes_root_hash():
    proof, _ = _make_blake3_proof(PARTS_A)
    bad_proof = MerkleProof(
        leaf_hash=proof.leaf_hash,
        leaf_index=proof.leaf_index,
        siblings=proof.siblings,
        root_hash="not bytes",  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError):
        extract_blake3_root(bad_proof)


# ---------------------------------------------------------------------------
# extract_poseidon_root
# ---------------------------------------------------------------------------


def test_extract_poseidon_root_returns_bytes():
    proof, _ = _make_poseidon_proof(PARTS_A)
    result = extract_poseidon_root(proof)
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_extract_poseidon_root_round_trips_root():
    proof, root_decimal = _make_poseidon_proof(PARTS_A)
    result = extract_poseidon_root(proof)
    expected = int(root_decimal).to_bytes(32, byteorder="big")
    assert result == expected


def test_extract_poseidon_root_rejects_non_proof():
    with pytest.raises(TypeError, match="Expected PoseidonProof"):
        extract_poseidon_root(42)  # type: ignore[arg-type]


def test_extract_poseidon_root_rejects_none():
    with pytest.raises(TypeError, match="Expected PoseidonProof"):
        extract_poseidon_root(None)  # type: ignore[arg-type]


def test_extract_poseidon_root_rejects_non_integer_root():
    bad_proof = PoseidonProof(
        root="not_an_integer",
        leaf="0",
        leaf_index=0,
        path_elements=[],
        path_indices=[],
    )
    with pytest.raises(ValueError, match="decimal integer"):
        extract_poseidon_root(bad_proof)


def test_extract_poseidon_root_rejects_negative_root():
    bad_proof = PoseidonProof(
        root="-1",
        leaf="0",
        leaf_index=0,
        path_elements=[],
        path_indices=[],
    )
    with pytest.raises(ValueError, match="outside the BN128 scalar field"):
        extract_poseidon_root(bad_proof)


def test_extract_poseidon_root_rejects_root_exceeding_field():
    bad_proof = PoseidonProof(
        root=str(SNARK_SCALAR_FIELD),  # exactly one over the limit
        leaf="0",
        leaf_index=0,
        path_elements=[],
        path_indices=[],
    )
    with pytest.raises(ValueError, match="outside the BN128 scalar field"):
        extract_poseidon_root(bad_proof)


# ---------------------------------------------------------------------------
# verify_against_dual_commitment
# ---------------------------------------------------------------------------


def test_verify_against_dual_commitment_matching_roots():
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    b3_root = extract_blake3_root(blake3_proof)
    p_root = extract_poseidon_root(poseidon_proof)
    assert verify_against_dual_commitment(b3_root, p_root, commitment) is True


def test_verify_against_dual_commitment_mismatched_blake3_root():
    commitment = _make_dual_commitment(PARTS_A)
    # Use a BLAKE3 root from a different document
    blake3_proof_b, _ = _make_blake3_proof(PARTS_B)
    poseidon_proof_a, _ = _make_poseidon_proof(PARTS_A)
    b3_root = extract_blake3_root(blake3_proof_b)
    p_root = extract_poseidon_root(poseidon_proof_a)
    assert verify_against_dual_commitment(b3_root, p_root, commitment) is False


def test_verify_against_dual_commitment_mismatched_poseidon_root():
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof_a, _ = _make_blake3_proof(PARTS_A)
    # Use a Poseidon root from a different document
    poseidon_proof_b, _ = _make_poseidon_proof(PARTS_B)
    b3_root = extract_blake3_root(blake3_proof_a)
    p_root = extract_poseidon_root(poseidon_proof_b)
    assert verify_against_dual_commitment(b3_root, p_root, commitment) is False


def test_verify_against_dual_commitment_rejects_wrong_blake3_root_length():
    commitment = _make_dual_commitment(PARTS_A)
    _, p_root_dec = _make_poseidon_proof(PARTS_A)
    p_root = int(p_root_dec).to_bytes(32, byteorder="big")
    assert verify_against_dual_commitment(b"\x00" * 16, p_root, commitment) is False


def test_verify_against_dual_commitment_rejects_wrong_poseidon_root_length():
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    b3_root = extract_blake3_root(blake3_proof)
    assert verify_against_dual_commitment(b3_root, b"\x00" * 16, commitment) is False


def test_verify_against_dual_commitment_rejects_malformed_blake3_hex():
    # 64 non-hex characters – same length as a valid BLAKE3 root hex string but not valid hex
    commitment = DualHashCommitment(blake3_root="z" * 64, poseidon_root="12345")
    assert verify_against_dual_commitment(b"\x00" * 32, b"\x00" * 32, commitment) is False


def test_verify_against_dual_commitment_rejects_malformed_poseidon_decimal():
    _, b3_root = _make_blake3_proof(PARTS_A)
    commitment = DualHashCommitment(
        blake3_root=b3_root.hex(),
        poseidon_root="not_a_number",
    )
    assert verify_against_dual_commitment(b"\x00" * 32, b"\x00" * 32, commitment) is False


def test_verify_against_dual_commitment_rejects_non_commitment():
    assert verify_against_dual_commitment(b"\x00" * 32, b"\x00" * 32, None) is False  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _verify_poseidon_proof (internal helper)
# ---------------------------------------------------------------------------


def test_verify_poseidon_proof_valid():
    proof, _ = _make_poseidon_proof(PARTS_A)
    assert _verify_poseidon_proof(proof) is True


def test_verify_poseidon_proof_valid_all_indices():
    """All leaves in the tree should produce verifiable proofs."""
    for i in range(len(PARTS_A)):
        proof, _ = _make_poseidon_proof(PARTS_A, leaf_index=i)
        assert _verify_poseidon_proof(proof) is True, f"Proof for leaf {i} failed"


def test_verify_poseidon_proof_tampered_root():
    proof, _ = _make_poseidon_proof(PARTS_A)
    bad_proof = PoseidonProof(
        root="0",  # wrong root
        leaf=proof.leaf,
        leaf_index=proof.leaf_index,
        path_elements=proof.path_elements,
        path_indices=proof.path_indices,
    )
    assert _verify_poseidon_proof(bad_proof) is False


def test_verify_poseidon_proof_tampered_leaf():
    proof, _ = _make_poseidon_proof(PARTS_A)
    bad_proof = PoseidonProof(
        root=proof.root,
        leaf="9999999999999",  # wrong leaf
        leaf_index=proof.leaf_index,
        path_elements=proof.path_elements,
        path_indices=proof.path_indices,
    )
    assert _verify_poseidon_proof(bad_proof) is False


def test_verify_poseidon_proof_tampered_path_element():
    proof, _ = _make_poseidon_proof(PARTS_A)
    tampered_elements = list(proof.path_elements)
    tampered_elements[0] = "0"
    bad_proof = PoseidonProof(
        root=proof.root,
        leaf=proof.leaf,
        leaf_index=proof.leaf_index,
        path_elements=tampered_elements,
        path_indices=proof.path_indices,
    )
    assert _verify_poseidon_proof(bad_proof) is False


def test_verify_poseidon_proof_rejects_truncated_palindrome_path():
    """
    Palindromic trees must satisfy two independent properties:

    1. Cryptographic: position-binding via _to_field_int ensures that a tree
       built from raw bytes [A, B, A] has a different root than [A, B, A] with
       leaves passed as pre-normalized integers (bypassing position context),
       and that non-palindromic trees like [A, B, C] differ from reversed [C, B, A]
       at the root level due to position-binding.

    2. Structural: a truncated proof path must be rejected by _verify_poseidon_proof
       even when the root and leaf are genuine.
    """
    from protocol.poseidon_tree import PoseidonMerkleTree

    leaves_bytes = [b"A", b"B", b"A"]

    # --- Property 1: position-binding produces distinct roots for reversal ---
    # Use non-palindromic data to demonstrate position-binding creates order-sensitivity
    tree_forward = PoseidonMerkleTree([b"A", b"B", b"C"], depth=2)
    tree_reversed = PoseidonMerkleTree(list(reversed([b"A", b"B", b"C"])), depth=2)
    assert tree_forward.get_root() != tree_reversed.get_root(), (
        "Position-binding ensures [A, B, C] != [C, B, A] even though "
        "they contain the same bytes, because position affects field element values"
    )

    # --- Property 2: truncated path is rejected by the verifier ---
    # Build tree using raw bytes so position-binding is exercised end-to-end
    tree = PoseidonMerkleTree(leaves_bytes, depth=2)
    path_elements, path_indices = tree.get_proof(0)
    truncated = PoseidonProof(
        root=tree.get_root(),
        leaf=str(tree._leaves[0]),
        leaf_index=0,
        path_elements=path_elements[:-1],
        path_indices=path_indices[:-1],
        tree_size=tree.tree_size,
    )
    assert _verify_poseidon_proof(truncated) is False, (
        "Truncated proof path must be rejected even for a palindrome tree"
    )


def test_verify_poseidon_proof_malformed_leaf():
    proof, _ = _make_poseidon_proof(PARTS_A)
    bad_proof = PoseidonProof(
        root=proof.root,
        leaf="not_a_number",
        leaf_index=proof.leaf_index,
        path_elements=proof.path_elements,
        path_indices=proof.path_indices,
    )
    assert _verify_poseidon_proof(bad_proof) is False


def test_verify_poseidon_proof_rejects_missing_or_wrong_tree_size():
    proof, _ = _make_poseidon_proof(PARTS_A)
    missing_size = PoseidonProof(
        root=proof.root,
        leaf=proof.leaf,
        leaf_index=proof.leaf_index,
        path_elements=proof.path_elements,
        path_indices=proof.path_indices,
        tree_size=0,
    )
    wrong_size = PoseidonProof(
        root=proof.root,
        leaf=proof.leaf,
        leaf_index=proof.leaf_index,
        path_elements=proof.path_elements,
        path_indices=proof.path_indices,
        tree_size=1,  # inconsistent with path depth
    )
    assert _verify_poseidon_proof(missing_size) is False
    assert _verify_poseidon_proof(wrong_size) is False


# ---------------------------------------------------------------------------
# validate_proof_consistency – primary API
# ---------------------------------------------------------------------------


def test_validate_proof_consistency_valid_consistent_proofs():
    """Both proofs reference the same document and match the dual commitment."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    assert validate_proof_consistency(blake3_proof, poseidon_proof, commitment) is True


def test_validate_proof_consistency_different_leaf_indices():
    """Proofs for different leaves of the same document are still consistent."""
    commitment = _make_dual_commitment(PARTS_A)
    for i in range(len(PARTS_A)):
        blake3_proof, _ = _make_blake3_proof(PARTS_A, leaf_index=i)
        poseidon_proof, _ = _make_poseidon_proof(PARTS_A, leaf_index=i)
        assert validate_proof_consistency(blake3_proof, poseidon_proof, commitment) is True


def test_validate_proof_consistency_mixed_documents_returns_false():
    """BLAKE3 proof from doc A + Poseidon proof from doc B must not be accepted."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof_a, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof_b, _ = _make_poseidon_proof(PARTS_B)
    assert validate_proof_consistency(blake3_proof_a, poseidon_proof_b, commitment) is False


def test_validate_proof_consistency_swapped_blake3_proof_returns_false():
    """BLAKE3 proof from doc B + Poseidon proof from doc A must not be accepted."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof_b, _ = _make_blake3_proof(PARTS_B)
    poseidon_proof_a, _ = _make_poseidon_proof(PARTS_A)
    assert validate_proof_consistency(blake3_proof_b, poseidon_proof_a, commitment) is False


def test_validate_proof_consistency_both_wrong_document_returns_false():
    """Both proofs from doc B against doc A commitment must not pass."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof_b, _ = _make_blake3_proof(PARTS_B)
    poseidon_proof_b, _ = _make_poseidon_proof(PARTS_B)
    assert validate_proof_consistency(blake3_proof_b, poseidon_proof_b, commitment) is False


def test_validate_proof_consistency_invalid_blake3_proof():
    """A cryptographically invalid BLAKE3 proof must be rejected."""
    commitment = _make_dual_commitment(PARTS_A)
    valid_proof, _ = _make_blake3_proof(PARTS_A)
    # Corrupt the leaf hash to invalidate the proof
    bad_blake3 = MerkleProof(
        leaf_hash=b"\xff" * 32,
        leaf_index=valid_proof.leaf_index,
        siblings=valid_proof.siblings,
        root_hash=valid_proof.root_hash,
    )
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    assert validate_proof_consistency(bad_blake3, poseidon_proof, commitment) is False


def test_validate_proof_consistency_invalid_poseidon_proof():
    """A cryptographically invalid Poseidon proof must be rejected."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    valid_poseidon, _ = _make_poseidon_proof(PARTS_A)
    # Corrupt the leaf value to invalidate the proof
    bad_poseidon = PoseidonProof(
        root=valid_poseidon.root,
        leaf="9999999999999",  # wrong leaf
        leaf_index=valid_poseidon.leaf_index,
        path_elements=valid_poseidon.path_elements,
        path_indices=valid_poseidon.path_indices,
    )
    assert validate_proof_consistency(blake3_proof, bad_poseidon, commitment) is False


def test_validate_proof_consistency_rejects_empty_path_for_multi_leaf_tree():
    """Poseidon proofs with empty siblings for non-trivial trees must be rejected."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)

    tampered_poseidon = PoseidonProof(
        root=poseidon_proof.root,
        leaf=poseidon_proof.leaf,
        leaf_index=poseidon_proof.leaf_index,
        path_elements=[],  # stripped siblings
        path_indices=[],
        tree_size=poseidon_proof.tree_size,
    )
    assert validate_proof_consistency(blake3_proof, tampered_poseidon, commitment) is False


def test_validate_proof_consistency_none_inputs_return_false():
    """None inputs must return False, not raise."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)

    assert validate_proof_consistency(None, poseidon_proof, commitment) is False  # type: ignore[arg-type]
    assert validate_proof_consistency(blake3_proof, None, commitment) is False  # type: ignore[arg-type]
    assert validate_proof_consistency(blake3_proof, poseidon_proof, None) is False  # type: ignore[arg-type]


def test_validate_batch_consistency_reports_failures():
    """Batch consistency must surface any failing proof."""
    commitment_ok = _make_dual_commitment(PARTS_A)
    good_b3, _ = _make_blake3_proof(PARTS_A)
    good_poseidon, _ = _make_poseidon_proof(PARTS_A)

    commitment_bad = _make_dual_commitment(PARTS_B)
    bad_poseidon = PoseidonProof(
        root="1",
        leaf="0",
        leaf_index=0,
        path_elements=[],
        path_indices=[],
        tree_size=1,
    )

    from protocol.cross_root_validation import validate_batch_consistency

    report = validate_batch_consistency(
        [
            (good_b3, good_poseidon, commitment_ok),
            (good_b3, bad_poseidon, commitment_bad),
        ]
    )

    assert report.is_consistent is False
    assert len(report.failures) == 1


# ---------------------------------------------------------------------------
# check_proof_consistency – detailed diagnostics
# ---------------------------------------------------------------------------


def test_check_proof_consistency_success():
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    result = check_proof_consistency(blake3_proof, poseidon_proof, commitment)
    assert result.is_consistent is True
    assert result.error is None
    assert result.error_message is None
    assert bool(result) is True


def test_check_proof_consistency_malformed_dual_commitment():
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    bad_commitment = DualHashCommitment(
        blake3_root="not_hex",
        poseidon_root="12345",
    )
    result = check_proof_consistency(blake3_proof, poseidon_proof, bad_commitment)
    assert result.is_consistent is False
    assert result.error is ConsistencyError.MALFORMED_DUAL_COMMITMENT
    assert bool(result) is False


def test_check_proof_consistency_malformed_dual_commitment_poseidon_out_of_field():
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    _, b3_root = _make_blake3_proof(PARTS_A)
    bad_commitment = DualHashCommitment(
        blake3_root=b3_root.hex(),
        poseidon_root=str(SNARK_SCALAR_FIELD),  # out of field
    )
    result = check_proof_consistency(blake3_proof, poseidon_proof, bad_commitment)
    assert result.is_consistent is False
    assert result.error is ConsistencyError.MALFORMED_DUAL_COMMITMENT


def test_check_proof_consistency_none_dual_commitment():
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    result = check_proof_consistency(blake3_proof, poseidon_proof, None)  # type: ignore[arg-type]
    assert result.is_consistent is False
    assert result.error is ConsistencyError.MALFORMED_DUAL_COMMITMENT


def test_check_proof_consistency_malformed_blake3_proof():
    commitment = _make_dual_commitment(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    result = check_proof_consistency("not a proof", poseidon_proof, commitment)  # type: ignore[arg-type]
    assert result.is_consistent is False
    assert result.error is ConsistencyError.MALFORMED_BLAKE3_PROOF
    assert result.error_message is not None


def test_check_proof_consistency_malformed_poseidon_proof():
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    result = check_proof_consistency(blake3_proof, "not a proof", commitment)  # type: ignore[arg-type]
    assert result.is_consistent is False
    assert result.error is ConsistencyError.MALFORMED_POSEIDON_PROOF
    assert result.error_message is not None


def test_check_proof_consistency_invalid_blake3_proof():
    commitment = _make_dual_commitment(PARTS_A)
    valid_proof, _ = _make_blake3_proof(PARTS_A)
    bad_blake3 = MerkleProof(
        leaf_hash=b"\xff" * 32,  # corrupt leaf breaks cryptographic verification
        leaf_index=valid_proof.leaf_index,
        siblings=valid_proof.siblings,
        root_hash=valid_proof.root_hash,
    )
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    result = check_proof_consistency(bad_blake3, poseidon_proof, commitment)
    assert result.is_consistent is False
    assert result.error is ConsistencyError.INVALID_BLAKE3_PROOF


def test_check_proof_consistency_invalid_poseidon_proof():
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    valid_poseidon, _ = _make_poseidon_proof(PARTS_A)
    bad_poseidon = PoseidonProof(
        root=valid_poseidon.root,
        leaf="1",  # wrong leaf
        leaf_index=valid_poseidon.leaf_index,
        path_elements=valid_poseidon.path_elements,
        path_indices=valid_poseidon.path_indices,
    )
    result = check_proof_consistency(blake3_proof, bad_poseidon, commitment)
    assert result.is_consistent is False
    assert result.error is ConsistencyError.INVALID_POSEIDON_PROOF


def test_check_proof_consistency_blake3_root_mismatch():
    """BLAKE3 proof is valid but refers to a different document."""
    commitment = _make_dual_commitment(PARTS_A)
    # Valid proof for doc B, valid poseidon proof for doc B, against doc A commitment
    blake3_proof_b, _ = _make_blake3_proof(PARTS_B)
    poseidon_proof_b, _ = _make_poseidon_proof(PARTS_B)
    result = check_proof_consistency(blake3_proof_b, poseidon_proof_b, commitment)
    assert result.is_consistent is False
    # The BLAKE3 root from doc B won't match doc A commitment, so BLAKE3_ROOT_MISMATCH
    assert result.error is ConsistencyError.BLAKE3_ROOT_MISMATCH


def test_check_proof_consistency_poseidon_root_mismatch():
    """BLAKE3 proof matches commitment but Poseidon proof doesn't."""
    commitment = _make_dual_commitment(PARTS_A)
    blake3_proof_a, _ = _make_blake3_proof(PARTS_A)
    # Poseidon proof from different document
    poseidon_proof_b, _ = _make_poseidon_proof(PARTS_B)
    result = check_proof_consistency(blake3_proof_a, poseidon_proof_b, commitment)
    assert result.is_consistent is False
    assert result.error is ConsistencyError.POSEIDON_ROOT_MISMATCH


# ---------------------------------------------------------------------------
# ConsistencyResult bool behavior
# ---------------------------------------------------------------------------


def test_consistency_result_bool_true():
    assert bool(ConsistencyResult(is_consistent=True)) is True


def test_consistency_result_bool_false():
    assert bool(ConsistencyResult(is_consistent=False)) is False


def test_consistency_result_bool_false_with_error():
    result = ConsistencyResult(
        is_consistent=False,
        error=ConsistencyError.INVALID_BLAKE3_PROOF,
        error_message="proof failed",
    )
    assert bool(result) is False
    assert result.error is ConsistencyError.INVALID_BLAKE3_PROOF
    assert result.error_message == "proof failed"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_validate_proof_consistency_single_section_document():
    """Single-section documents are supported."""
    parts = ["only one section"]
    commitment = _make_dual_commitment(parts)
    blake3_proof, _ = _make_blake3_proof(parts)
    poseidon_proof, _ = _make_poseidon_proof(parts)
    assert validate_proof_consistency(blake3_proof, poseidon_proof, commitment) is True


def test_validate_proof_consistency_large_document():
    """Documents with the maximum number of Poseidon-supported sections (16)."""
    parts = [f"section {i}" for i in range(16)]
    commitment = _make_dual_commitment(parts)
    blake3_proof, _ = _make_blake3_proof(parts)
    poseidon_proof, _ = _make_poseidon_proof(parts)
    assert validate_proof_consistency(blake3_proof, poseidon_proof, commitment) is True


def test_validate_proof_consistency_corrupted_siblings():
    """Corrupting a sibling in the BLAKE3 proof must trigger INVALID_BLAKE3_PROOF."""
    commitment = _make_dual_commitment(PARTS_A)
    valid_proof, _ = _make_blake3_proof(PARTS_A)
    if valid_proof.siblings:
        corrupted_siblings = [(b"\x00" * 32, pos) for _, pos in valid_proof.siblings]
        bad_blake3 = MerkleProof(
            leaf_hash=valid_proof.leaf_hash,
            leaf_index=valid_proof.leaf_index,
            siblings=corrupted_siblings,
            root_hash=valid_proof.root_hash,
        )
        poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
        result = check_proof_consistency(bad_blake3, poseidon_proof, commitment)
        assert result.is_consistent is False
        assert result.error is ConsistencyError.INVALID_BLAKE3_PROOF


def test_validate_proof_consistency_does_not_raise_on_garbage():
    """Completely invalid inputs must return False, never raise."""
    assert validate_proof_consistency(object(), object(), object()) is False  # type: ignore[arg-type]
    assert validate_proof_consistency(1, 2, 3) is False  # type: ignore[arg-type]
    assert validate_proof_consistency([], {}, ()) is False  # type: ignore[arg-type]


def test_validate_proof_consistency_propagates_unexpected_internal_errors(
    monkeypatch: pytest.MonkeyPatch,
):
    """Unexpected verifier bugs should surface instead of being silently mapped to False."""
    blake3_proof, _ = _make_blake3_proof(PARTS_A)
    poseidon_proof, _ = _make_poseidon_proof(PARTS_A)
    commitment = _make_dual_commitment(PARTS_A)

    def _boom(*_args: object, **_kwargs: object) -> bool:
        raise RuntimeError("unexpected internal failure")

    monkeypatch.setattr(cross_root_validation_module, "_verify_blake3_proof", _boom)

    with pytest.raises(RuntimeError, match="unexpected internal failure"):
        validate_proof_consistency(blake3_proof, poseidon_proof, commitment)


# ---------------------------------------------------------------------------
# validate_batch_consistency – extended coverage
# ---------------------------------------------------------------------------


def test_validate_batch_consistency_all_pass():
    """All-pass batch must report is_consistent=True with no failures."""
    from protocol.cross_root_validation import validate_batch_consistency

    commitment_a = _make_dual_commitment(PARTS_A)
    b3_a, _ = _make_blake3_proof(PARTS_A)
    pos_a, _ = _make_poseidon_proof(PARTS_A)

    commitment_b = _make_dual_commitment(PARTS_B)
    b3_b, _ = _make_blake3_proof(PARTS_B)
    pos_b, _ = _make_poseidon_proof(PARTS_B)

    report = validate_batch_consistency(
        [
            (b3_a, pos_a, commitment_a),
            (b3_b, pos_b, commitment_b),
        ]
    )

    assert report.is_consistent is True
    assert len(report.failures) == 0


def test_validate_batch_consistency_empty_input():
    """Empty input list must report is_consistent=True with no failures."""
    from protocol.cross_root_validation import validate_batch_consistency

    report = validate_batch_consistency([])

    assert report.is_consistent is True
    assert len(report.failures) == 0


def test_validate_batch_consistency_mixed_results():
    """Mixed batch with one good and one bad proof must report the failure."""
    from protocol.cross_root_validation import validate_batch_consistency

    commitment_ok = _make_dual_commitment(PARTS_A)
    good_b3, _ = _make_blake3_proof(PARTS_A)
    good_poseidon, _ = _make_poseidon_proof(PARTS_A)

    # Second triplet: valid proofs but against wrong commitment → should fail
    commitment_wrong = _make_dual_commitment(PARTS_B)

    report = validate_batch_consistency(
        [
            (good_b3, good_poseidon, commitment_ok),
            (good_b3, good_poseidon, commitment_wrong),
        ]
    )

    assert report.is_consistent is False
    assert len(report.failures) == 1
    assert report.failures[0].is_consistent is False


def test_validate_batch_consistency_single_pass():
    """Single passing triplet must report is_consistent=True."""
    from protocol.cross_root_validation import validate_batch_consistency

    commitment = _make_dual_commitment(PARTS_A)
    b3, _ = _make_blake3_proof(PARTS_A)
    pos, _ = _make_poseidon_proof(PARTS_A)

    report = validate_batch_consistency([(b3, pos, commitment)])

    assert report.is_consistent is True
    assert len(report.failures) == 0
