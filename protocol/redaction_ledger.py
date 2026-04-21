"""
Dual-anchor redaction protocol for Olympus.

This module bridges the BLAKE3-based Sparse Merkle Tree (SMT) used for
ledger/state commitments with the Poseidon-based Merkle tree required by
the Groth16 ZK redaction circuit.

Dual-anchor strategy
--------------------
Olympus uses two independent hash functions for two distinct purposes:

1. **BLAKE3** – ledger and SMT commitments (efficient, collision-resistant,
   post-quantum candidate).  Every document record is stored in the 256-height
   Sparse Merkle Tree under a deterministic key derived from
   ``record_key("document", doc_id, version)``.

2. **Poseidon** – ZK circuit root (the ``originalRoot`` public signal in
   ``proofs/circuits/redaction_validity.circom``).  Poseidon is an
   arithmetic-hash that maps naturally into the BN128 scalar field, making
   it cheap to verify inside a Groth16 proof.

Rather than building a BLAKE3→Poseidon bridge circuit (which would be large
and maintenance-heavy), the Poseidon Merkle root is *anchored* in the same
SMT under a dedicated key namespace (``"redaction_root_poseidon"``).  A
verifier can therefore:

  a) Look up the Poseidon root in the SMT and check its SMT membership proof.
  b) Independently verify the ZK proof against the public inputs that include
     the same Poseidon root.

No hash-bridge circuit is needed; the two proofs are checked separately.

Usage
-----
Building and verifying the anchor::

    from protocol.redaction_ledger import (
        RedactionProofWithLedger,
        ZKPublicInputs,
        poseidon_root_record_key,
        poseidon_root_to_bytes,
    )
    from protocol.ssmf import SparseMerkleTree

    smt = SparseMerkleTree()
    poseidon_root_str = poseidon_tree.get_root()   # decimal string
    key = poseidon_root_record_key(document_id, version)
    value = poseidon_root_to_bytes(poseidon_root_str)
    smt.update(key, value, "docling@2.3.1", "v1")

    smt_proof = smt.prove_existence(key)
    public_inputs = ZKPublicInputs(
        original_root=poseidon_root_str,
        redacted_commitment="...",
        revealed_count=3,
    )
    wrapped = RedactionProofWithLedger(
        smt_proof=smt_proof,
        zk_proof={},          # opaque Groth16 proof blob
        zk_public_inputs=public_inputs,
    )
    assert wrapped.verify_smt_anchor(smt.get_root())
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .hashes import SNARK_SCALAR_FIELD, record_key
from .ssmf import ExistenceProof, verify_proof
from .zkp import Groth16Prover, ZKProof


# Record-type namespace used to key Poseidon roots in the SMT.
# This must remain distinct from all other record types so that
# Poseidon root records never collide with BLAKE3 document records.
POSEIDON_ROOT_RECORD_TYPE = "redaction_root_poseidon"

# Size of the serialized Poseidon root value stored in the SMT (bytes).
POSEIDON_ROOT_VALUE_SIZE = 32


def poseidon_root_to_bytes(root: str) -> bytes:
    """
    Serialize a Poseidon Merkle root field element to 32 bytes (big-endian).

    The root is expressed as a decimal string representing an integer in the
    BN128 scalar field (0 <= root < SNARK_SCALAR_FIELD).  It is serialized as
    a 32-byte big-endian unsigned integer, which is the canonical SMT value
    format.

    Args:
        root: Decimal string representation of the Poseidon root field element.

    Returns:
        32-byte big-endian serialization of the field element.

    Raises:
        ValueError: If *root* is not a valid non-negative integer string, or if
                    it falls outside the BN128 scalar field range.
    """
    try:
        value = int(root)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Poseidon root must be a decimal integer string, got: {root!r}") from exc

    if value < 0 or value >= SNARK_SCALAR_FIELD:
        raise ValueError(
            f"Poseidon root {value} is outside the BN128 scalar field range "
            f"[0, {SNARK_SCALAR_FIELD})"
        )

    return value.to_bytes(POSEIDON_ROOT_VALUE_SIZE, byteorder="big")


def poseidon_root_from_bytes(data: bytes) -> str:
    """
    Deserialize a 32-byte big-endian Poseidon root back to a decimal string.

    Args:
        data: Exactly 32 bytes produced by :func:`poseidon_root_to_bytes`.

    Returns:
        Decimal string representation of the field element.

    Raises:
        ValueError: If *data* is not exactly 32 bytes or the decoded integer
                    falls outside the BN128 scalar field range.
    """
    if len(data) != POSEIDON_ROOT_VALUE_SIZE:
        raise ValueError(
            f"Poseidon root bytes must be exactly {POSEIDON_ROOT_VALUE_SIZE} bytes, got {len(data)}"
        )

    value = int.from_bytes(data, byteorder="big")

    if value >= SNARK_SCALAR_FIELD:
        raise ValueError(f"Decoded Poseidon root {value} is outside the BN128 scalar field range")

    return str(value)


def poseidon_root_record_key(document_id: str, version: int) -> bytes:
    """
    Derive the deterministic 32-byte SMT key for a Poseidon root record.

    Keys are in the ``"redaction_root_poseidon"`` namespace, which keeps them
    distinct from BLAKE3 document records (``"document"`` namespace).
    Append-only semantics are preserved because each *version* produces a
    different key.

    Args:
        document_id: Unique identifier for the source document.
        version: Version number of the redaction commitment.

    Returns:
        32-byte BLAKE3-derived SMT key.
    """
    return record_key(POSEIDON_ROOT_RECORD_TYPE, document_id, version)


@dataclass
class ZKPublicInputs:
    """
    Public inputs for the Groth16 redaction validity proof.

    These map directly to the three public signals declared in
    ``proofs/circuits/redaction_validity.circom``:
    ``originalRoot``, ``redactedCommitment``, and ``revealedCount``.

    Attributes:
        original_root: Decimal string of the Poseidon Merkle root for the
                       original (un-redacted) document.
        redacted_commitment: Decimal string of the Poseidon commitment over
                             the revealed-leaf vector.
        revealed_count: Number of leaves that were revealed (integer).
    """

    original_root: str
    redacted_commitment: str
    revealed_count: int


class VerificationResult(Enum):
    """Three-valued verification outcome."""

    VALID = "valid"
    INVALID = "invalid"
    UNABLE_TO_VERIFY = "unable_to_verify"

    def __bool__(self) -> bool:  # pragma: no cover - convenience for legacy callers
        return self is VerificationResult.VALID


def verify_zk_redaction(
    proof_blob: dict[str, Any], public_inputs: ZKPublicInputs
) -> VerificationResult:
    """
    Verify a Groth16 redaction proof against the redaction_validity verification key.

    Args:
        proof_blob: Parsed Groth16 proof JSON (snarkjs-style ``pi_a/pi_b/pi_c``).
        public_inputs: Public signals for the redaction circuit.

    Returns:
        VerificationResult.VALID when snarkjs verifies the proof.
        VerificationResult.INVALID when verification cryptographically fails.
        VerificationResult.UNABLE_TO_VERIFY when verifier inputs are malformed
        or the verification artifacts are unavailable (e.g., missing vkey).
    """
    try:
        public_signals = [
            str(int(public_inputs.original_root)),
            str(int(public_inputs.redacted_commitment)),
            str(int(public_inputs.revealed_count)),
        ]
    except (TypeError, ValueError):
        return VerificationResult.UNABLE_TO_VERIFY

    repo_root = Path(__file__).resolve().parent.parent
    circuits_dir = repo_root / "proofs" / "circuits"
    vkey_path = repo_root / "proofs" / "keys" / "verification_keys" / "redaction_validity_vkey.json"
    prover = Groth16Prover(circuits_dir=circuits_dir)
    proof = ZKProof(proof=proof_blob, public_signals=public_signals, circuit="redaction_validity")

    try:
        verified = prover.verify(proof=proof, verification_key_path=vkey_path)
    except (FileNotFoundError, OSError, ValueError):
        return VerificationResult.UNABLE_TO_VERIFY

    return VerificationResult.VALID if verified else VerificationResult.INVALID


@dataclass
class RedactionProofWithLedger:
    """
    Wrapper that bundles an SMT existence proof for the Poseidon root with the
    Groth16 ZK redaction proof blob and its public inputs.

    This is the primary artifact produced by the dual-anchor redaction flow.
    A verifier can check both halves independently:

    1. ``verify_smt_anchor(smt_root_hash)`` – confirms the Poseidon root is
       anchored in the BLAKE3 SMT.
    2. ``verify_all(smt_root_hash, zk_verifier=...)`` – additionally invokes a
       pluggable ZK verifier once one is available.

    Attributes:
        smt_proof: SMT existence proof showing that the Poseidon root is stored
                   in the 256-height Sparse Merkle Tree.
        zk_proof: Opaque Groth16 proof blob (e.g. parsed snarkjs JSON output).
                  The structure is left uninterpreted by this layer; pass it
                  through to a dedicated ZK verifier.
        zk_public_inputs: The three public inputs from the Groth16 circuit.
    """

    smt_proof: ExistenceProof
    zk_proof: dict[str, Any]
    zk_public_inputs: ZKPublicInputs

    def verify_smt_anchor(self, smt_root_hash: bytes) -> bool:
        """
        Verify that the Poseidon ``originalRoot`` is anchored in the SMT.

        Performs three checks:

        1. The SMT existence proof is cryptographically valid
           (calls :func:`~protocol.ssmf.verify_proof`).
        2. The proof's ``root_hash`` matches *smt_root_hash* (ties the proof
           to a specific committed tree state).
        3. The proof's ``value_hash`` equals the big-endian 32-byte
           serialization of ``zk_public_inputs.original_root`` (confirms the
           anchored value is the same root used in the ZK circuit).

        Args:
            smt_root_hash: The 32-byte SMT root hash against which the proof
                           should be validated (typically from a ledger entry).

        Returns:
            ``True`` if all three checks pass; ``False`` otherwise.
        """
        if len(smt_root_hash) != 32:
            return False

        # Check 1: cryptographic proof validity
        if not verify_proof(self.smt_proof):
            return False

        # Check 2: proof is against the expected tree state
        if self.smt_proof.root_hash != smt_root_hash:
            return False

        # Check 3: anchored value matches the ZK public input root
        try:
            expected_value = poseidon_root_to_bytes(self.zk_public_inputs.original_root)
        except ValueError:
            return False

        return self.smt_proof.value_hash == expected_value

    def verify_all(
        self,
        smt_root_hash: bytes,
        zk_verifier: Callable[[dict[str, Any], ZKPublicInputs], VerificationResult | bool]
        | None = None,
    ) -> VerificationResult:
        """
        Verify both the SMT anchor and (optionally) the ZK proof.

        By default, this method verifies the Groth16 proof using
        :func:`verify_zk_redaction`. A custom *zk_verifier* may still be
        provided for testing or alternate verification backends.

        Args:
            smt_root_hash: The 32-byte SMT root hash; passed to
                           :meth:`verify_smt_anchor`.
            zk_verifier: Optional callable with signature
                         ``(zk_proof, zk_public_inputs) -> VerificationResult``.
                         When provided, this overrides the default verifier. Legacy
                         callables that return ``bool`` are also supported and will
                         be coerced into :class:`VerificationResult`.

        Returns:
            VerificationResult describing the combined SMT + ZK verification outcome.
        """
        if not self.verify_smt_anchor(smt_root_hash):
            return VerificationResult.INVALID

        if zk_verifier is not None:
            zk_result = zk_verifier(self.zk_proof, self.zk_public_inputs)
        else:
            zk_result = verify_zk_redaction(self.zk_proof, self.zk_public_inputs)

        if isinstance(zk_result, VerificationResult):
            return zk_result
        return VerificationResult.VALID if zk_result else VerificationResult.INVALID


@dataclass(frozen=True)
class DualHashCommitment:
    """
    Public commitment that binds a BLAKE3 Merkle root to a Poseidon Merkle root.

    Only the root pair is exposed; no tree structure or leaf data is included.
    The Poseidon root is expressed as a decimal string (field element) so it
    can be fed directly into the Groth16 circuit as ``originalRoot``.
    """

    blake3_root: str  # 64-char hex
    poseidon_root: str  # decimal string (0 <= root < SNARK_SCALAR_FIELD)
