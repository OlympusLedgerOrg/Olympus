"""
Cross-root validation for dual-anchor commitment consistency.

This module implements validation logic to ensure BLAKE3 and Poseidon proofs
reference the same document, preventing attacks where valid proofs from
different documents could be mixed.

The dual-anchor strategy in Olympus uses two independent hash trees:

1. **BLAKE3** Merkle tree – ledger commitments, verified via ``MerkleProof``.
2. **Poseidon** Merkle tree – ZK circuit root, verified via ``PoseidonProof``.

A ``DualHashCommitment`` binds both roots together.  This module checks that
a presented BLAKE3 proof and Poseidon proof both reconstruct to roots that
match the same dual commitment, ensuring they refer to the identical document.

Usage::

    from protocol.cross_root_validation import validate_proof_consistency

    consistent = validate_proof_consistency(
        blake3_proof=merkle_proof,
        poseidon_proof=poseidon_proof,
        dual_commitment=commitment,
    )
    if not consistent:
        result = check_proof_consistency(merkle_proof, poseidon_proof, commitment)
        print(result.error_message)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .hashes import SNARK_SCALAR_FIELD
from .merkle import MerkleProof, verify_proof as _verify_blake3_proof
from .poseidon_tree import POSEIDON_DOMAIN_NODE, PoseidonProof, poseidon_hash_with_domain
from .redaction_ledger import POSEIDON_ROOT_VALUE_SIZE, DualHashCommitment


class ConsistencyError(Enum):
    """Classification of proof consistency failures."""

    MALFORMED_DUAL_COMMITMENT = "malformed_dual_commitment"
    MALFORMED_BLAKE3_PROOF = "malformed_blake3_proof"
    MALFORMED_POSEIDON_PROOF = "malformed_poseidon_proof"
    INVALID_BLAKE3_PROOF = "invalid_blake3_proof"
    INVALID_POSEIDON_PROOF = "invalid_poseidon_proof"
    BLAKE3_ROOT_MISMATCH = "blake3_root_mismatch"
    POSEIDON_ROOT_MISMATCH = "poseidon_root_mismatch"


@dataclass
class ConsistencyResult:
    """Detailed outcome of a proof consistency check.

    Attributes:
        is_consistent: ``True`` if both proofs are valid and reference the same
            document as recorded in the dual commitment.
        error: Classification of the failure, or ``None`` on success.
        error_message: Human-readable description of the failure, or ``None``
            on success.
    """

    is_consistent: bool
    error: ConsistencyError | None = None
    error_message: str | None = None

    def __bool__(self) -> bool:
        return self.is_consistent


def extract_blake3_root(blake3_proof: MerkleProof) -> bytes:
    """Extract the BLAKE3 Merkle root from a BLAKE3 inclusion proof.

    Args:
        blake3_proof: A BLAKE3 Merkle inclusion proof produced by
            :meth:`~protocol.merkle.MerkleTree.generate_proof`.

    Returns:
        The 32-byte BLAKE3 Merkle root encoded in the proof.

    Raises:
        ValueError: If *blake3_proof* is not a :class:`~protocol.merkle.MerkleProof`
            or its ``root_hash`` is not exactly 32 bytes.
        TypeError: If *blake3_proof* is ``None`` or not the expected type.
    """
    if not isinstance(blake3_proof, MerkleProof):
        raise TypeError(f"Expected MerkleProof, got {type(blake3_proof)!r}")
    root = blake3_proof.root_hash
    if not isinstance(root, bytes) or len(root) != 32:
        raise ValueError(
            f"MerkleProof.root_hash must be exactly 32 bytes, "
            f"got {len(root) if isinstance(root, bytes) else type(root)!r}"
        )
    return root


def extract_poseidon_root(poseidon_proof: PoseidonProof) -> bytes:
    """Extract the Poseidon Merkle root from a Poseidon inclusion proof.

    The root is stored as a decimal string in :class:`~protocol.poseidon_tree.PoseidonProof`
    and is converted here to a 32-byte big-endian representation so it can be
    compared byte-for-byte with a :class:`~protocol.redaction_ledger.DualHashCommitment`.

    Args:
        poseidon_proof: A Poseidon Merkle inclusion proof produced by
            :func:`~protocol.poseidon_tree.build_poseidon_witness_inputs` or
            :meth:`~protocol.poseidon_tree.PoseidonMerkleTree.get_proof`.

    Returns:
        32-byte big-endian serialization of the Poseidon root field element.

    Raises:
        ValueError: If the proof root is not a valid decimal integer or falls
            outside the BN128 scalar field.
        TypeError: If *poseidon_proof* is not a :class:`~protocol.poseidon_tree.PoseidonProof`.
    """
    if not isinstance(poseidon_proof, PoseidonProof):
        raise TypeError(f"Expected PoseidonProof, got {type(poseidon_proof)!r}")
    try:
        root_int = int(poseidon_proof.root)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"PoseidonProof.root must be a decimal integer string, got: {poseidon_proof.root!r}"
        ) from exc
    if root_int < 0 or root_int >= SNARK_SCALAR_FIELD:
        raise ValueError(
            f"PoseidonProof root {root_int} is outside the BN128 scalar field range "
            f"[0, {SNARK_SCALAR_FIELD})"
        )
    return root_int.to_bytes(POSEIDON_ROOT_VALUE_SIZE, byteorder="big")


def verify_against_dual_commitment(
    blake3_root: bytes,
    poseidon_root: bytes,
    dual_commitment: DualHashCommitment,
) -> bool:
    """Verify that both roots match the dual commitment.

    Compares *blake3_root* against ``dual_commitment.blake3_root`` (hex) and
    *poseidon_root* (32-byte big-endian) against ``dual_commitment.poseidon_root``
    (decimal string).  Returns ``False`` for any malformed input rather than
    raising an exception.

    Args:
        blake3_root: 32-byte BLAKE3 Merkle root extracted from a BLAKE3 proof.
        poseidon_root: 32-byte big-endian Poseidon root extracted from a Poseidon
            proof (as produced by :func:`extract_poseidon_root`).
        dual_commitment: The binding dual commitment to validate against.

    Returns:
        ``True`` if both roots match their respective fields in the dual
        commitment; ``False`` for any mismatch or malformed input.
    """
    if not isinstance(blake3_root, bytes) or len(blake3_root) != 32:
        return False
    if not isinstance(poseidon_root, bytes) or len(poseidon_root) != POSEIDON_ROOT_VALUE_SIZE:
        return False
    if not isinstance(dual_commitment, DualHashCommitment):
        return False

    try:
        expected_blake3 = bytes.fromhex(dual_commitment.blake3_root)
    except (ValueError, AttributeError):
        return False

    try:
        expected_poseidon_int = int(dual_commitment.poseidon_root)
        if expected_poseidon_int < 0 or expected_poseidon_int >= SNARK_SCALAR_FIELD:
            return False
        expected_poseidon = expected_poseidon_int.to_bytes(
            POSEIDON_ROOT_VALUE_SIZE, byteorder="big"
        )
    except (ValueError, TypeError, OverflowError):
        return False

    return blake3_root == expected_blake3 and poseidon_root == expected_poseidon


def _reconstruct_poseidon_root(poseidon_proof: PoseidonProof) -> int | None:
    """Reconstruct the Poseidon root by traversing the proof path.

    Follows the circom convention: ``path_indices[i] == 0`` means the current
    node is the **left** child; ``path_indices[i] == 1`` means it is the
    **right** child.

    Args:
        poseidon_proof: Poseidon inclusion proof to reconstruct.

    Returns:
        The reconstructed root as an integer reduced modulo the BN128 field,
        or ``None`` if any value is malformed.
    """
    try:
        current = int(poseidon_proof.leaf) % SNARK_SCALAR_FIELD
        for sibling_str, is_right in zip(poseidon_proof.path_elements, poseidon_proof.path_indices):
            sibling = int(sibling_str) % SNARK_SCALAR_FIELD
            if is_right == 0:
                current = poseidon_hash_with_domain(current, sibling, POSEIDON_DOMAIN_NODE)
            else:
                current = poseidon_hash_with_domain(sibling, current, POSEIDON_DOMAIN_NODE)
        return current % SNARK_SCALAR_FIELD
    except (ValueError, TypeError, AttributeError):
        return None


def _verify_poseidon_proof(poseidon_proof: PoseidonProof) -> bool:
    """Verify a Poseidon Merkle inclusion proof by reconstructing the root.

    Args:
        poseidon_proof: The Poseidon proof to verify.

    Returns:
        ``True`` if the reconstructed root matches the proof's claimed root;
        ``False`` otherwise (including malformed inputs).
    """
    reconstructed = _reconstruct_poseidon_root(poseidon_proof)
    if reconstructed is None:
        return False
    try:
        expected = int(poseidon_proof.root) % SNARK_SCALAR_FIELD
    except (ValueError, TypeError):
        return False
    return reconstructed == expected


def check_proof_consistency(
    blake3_proof: MerkleProof,
    poseidon_proof: PoseidonProof,
    dual_commitment: DualHashCommitment,
) -> ConsistencyResult:
    """Check proof consistency and return a detailed diagnostic result.

    Performs the following checks in order:

    1. Validate the structure of *dual_commitment*.
    2. Validate the structure of *blake3_proof* (``root_hash`` is 32 bytes).
    3. Validate the structure of *poseidon_proof* (``root`` is a valid field element).
    4. Verify the BLAKE3 proof cryptographically.
    5. Verify the Poseidon proof cryptographically by reconstructing the root.
    6. Check the BLAKE3 root against the dual commitment.
    7. Check the Poseidon root against the dual commitment.

    Args:
        blake3_proof: BLAKE3 Merkle inclusion proof.
        poseidon_proof: Poseidon Merkle inclusion proof.
        dual_commitment: The dual commitment that binds both roots.

    Returns:
        :class:`ConsistencyResult` describing the outcome.  On success,
        ``is_consistent`` is ``True`` and ``error`` / ``error_message`` are
        ``None``.  On failure, ``error`` identifies the failure type and
        ``error_message`` provides a human-readable description.
    """
    # 1. Validate dual commitment structure.
    if not isinstance(dual_commitment, DualHashCommitment):
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.MALFORMED_DUAL_COMMITMENT,
            error_message="dual_commitment must be a DualHashCommitment instance",
        )
    try:
        dc_blake3_bytes = bytes.fromhex(dual_commitment.blake3_root)
        if len(dc_blake3_bytes) != 32:
            raise ValueError("blake3_root must decode to exactly 32 bytes")
        dc_poseidon_int = int(dual_commitment.poseidon_root)
        if dc_poseidon_int < 0 or dc_poseidon_int >= SNARK_SCALAR_FIELD:
            raise ValueError("poseidon_root is outside the BN128 scalar field")
    except (ValueError, AttributeError, TypeError) as exc:
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.MALFORMED_DUAL_COMMITMENT,
            error_message=f"Dual commitment is malformed: {exc}",
        )

    # 2. Validate BLAKE3 proof structure.
    try:
        blake3_root = extract_blake3_root(blake3_proof)
    except (TypeError, ValueError) as exc:
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.MALFORMED_BLAKE3_PROOF,
            error_message=f"BLAKE3 proof is malformed: {exc}",
        )

    # 3. Validate Poseidon proof structure.
    try:
        poseidon_root = extract_poseidon_root(poseidon_proof)
    except (TypeError, ValueError) as exc:
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.MALFORMED_POSEIDON_PROOF,
            error_message=f"Poseidon proof is malformed: {exc}",
        )

    # 4. Verify BLAKE3 proof cryptographically.
    try:
        blake3_valid = _verify_blake3_proof(blake3_proof)
    except Exception:
        blake3_valid = False
    if not blake3_valid:
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.INVALID_BLAKE3_PROOF,
            error_message="BLAKE3 proof failed cryptographic verification",
        )

    # 5. Verify Poseidon proof cryptographically.
    if not _verify_poseidon_proof(poseidon_proof):
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.INVALID_POSEIDON_PROOF,
            error_message="Poseidon proof failed cryptographic verification",
        )

    # 6. Check BLAKE3 root against dual commitment.
    if blake3_root != dc_blake3_bytes:
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.BLAKE3_ROOT_MISMATCH,
            error_message=(
                f"BLAKE3 proof root {blake3_root.hex()!r} does not match "
                f"dual commitment blake3_root {dual_commitment.blake3_root!r}"
            ),
        )

    # 7. Check Poseidon root against dual commitment.
    dc_poseidon_bytes = dc_poseidon_int.to_bytes(POSEIDON_ROOT_VALUE_SIZE, byteorder="big")
    if poseidon_root != dc_poseidon_bytes:
        return ConsistencyResult(
            is_consistent=False,
            error=ConsistencyError.POSEIDON_ROOT_MISMATCH,
            error_message=(
                f"Poseidon proof root does not match dual commitment poseidon_root "
                f"{dual_commitment.poseidon_root!r}"
            ),
        )

    return ConsistencyResult(is_consistent=True)


def validate_proof_consistency(
    blake3_proof: MerkleProof,
    poseidon_proof: PoseidonProof,
    dual_commitment: DualHashCommitment,
) -> bool:
    """Validate that BLAKE3 and Poseidon proofs reference the same document.

    This is the primary entry point for cross-root validation.  It prevents
    mix-and-match attacks where a valid BLAKE3 proof from document A and a
    valid Poseidon proof from document B could be combined to impersonate a
    consistent dual-anchor commitment.

    Both proofs are verified independently first, then their reconstructed
    roots are checked against *dual_commitment* to confirm they refer to the
    same document.

    For detailed diagnostics on failure use :func:`check_proof_consistency`.

    Args:
        blake3_proof: BLAKE3 Merkle inclusion proof for the document.
        poseidon_proof: Poseidon Merkle inclusion proof for the document.
        dual_commitment: The dual commitment that binds the BLAKE3 and Poseidon
            roots together.

    Returns:
        ``True`` if both proofs are cryptographically valid and their roots are
        consistent with *dual_commitment*; ``False`` for any failure or
        malformed input.
    """
    try:
        return check_proof_consistency(blake3_proof, poseidon_proof, dual_commitment).is_consistent
    except Exception:
        return False
