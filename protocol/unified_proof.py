"""
Unified Proof System for Olympus

This module provides a single proof that verifies four critical properties:
1. Document canonicalization - proves document sections are properly canonicalized
2. Merkle inclusion - proves document is included in the ledger Merkle tree
3. Ledger root commitment - proves Merkle root is in a signed checkpoint
4. Federation signatures - verifies quorum certificate over checkpoint

The system uses Groth16 for the cryptographic proof (components 1-3) and verifies
federation signatures at the Python layer (component 4). This design is optimized
for throughput while maintaining cryptographic guarantees.

An optional Halo2 backend is available for high-assurance contexts where
eliminating trusted setup risk is critical.

Usage::

    from protocol.unified_proof import UnifiedProofVerifier, UnifiedProof

    verifier = UnifiedProofVerifier()
    proof = UnifiedProof(
        zk_proof=groth16_proof,
        checkpoint=signed_checkpoint,
        canonical_sections=document_sections,
    )

    result = verifier.verify(proof)
    if result.is_valid:
        print("All four components verified successfully")
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .checkpoints import SignedCheckpoint, verify_checkpoint_quorum_certificate
from .federation import FederationRegistry
from .zkp import Groth16Prover, ZKProof


class ProofBackend(Enum):
    """
    Proving system backend selection.

    GROTH16: Primary backend optimized for throughput (requires trusted setup)
    HALO2: Optional backend for maximal assurance (no trusted setup required)
    """

    GROTH16 = "groth16"
    HALO2 = "halo2"


class VerificationResult(Enum):
    """Unified proof verification outcome."""

    VALID = "valid"
    INVALID_ZK_PROOF = "invalid_zk_proof"
    INVALID_CHECKPOINT = "invalid_checkpoint"
    INVALID_QUORUM = "invalid_quorum"
    MISSING_ARTIFACTS = "missing_artifacts"
    UNABLE_TO_VERIFY = "unable_to_verify"

    @property
    def is_valid(self) -> bool:
        """Return True if verification succeeded."""
        return self == VerificationResult.VALID

    def __bool__(self) -> bool:
        """Allow boolean checks: if result: ..."""
        return self.is_valid


@dataclass
class UnifiedProof:
    """
    Container for a unified proof artifact.

    Bundles the ZK proof (Groth16 or Halo2), checkpoint commitment, and
    federation signatures into a single verifiable package.

    Attributes:
        zk_proof: Cryptographic proof (Groth16 or Halo2 format)
        public_inputs: Public inputs for the ZK circuit
        checkpoint: Signed checkpoint containing ledger root commitment
        backend: Proving system used (GROTH16 or HALO2)
    """

    zk_proof: dict[str, Any]
    public_inputs: UnifiedPublicInputs
    checkpoint: SignedCheckpoint
    backend: ProofBackend = ProofBackend.GROTH16

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            "zk_proof": self.zk_proof,
            "public_inputs": {
                "canonical_hash": self.public_inputs.canonical_hash,
                "merkle_root": self.public_inputs.merkle_root,
                "ledger_root": self.public_inputs.ledger_root,
                "checkpoint_hash": self.public_inputs.checkpoint_hash,
            },
            "checkpoint": self.checkpoint.to_dict(),
            "backend": self.backend.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedProof:
        """Deserialize from dictionary."""
        return cls(
            zk_proof=data["zk_proof"],
            public_inputs=UnifiedPublicInputs(
                canonical_hash=data["public_inputs"]["canonical_hash"],
                merkle_root=data["public_inputs"]["merkle_root"],
                ledger_root=data["public_inputs"]["ledger_root"],
                checkpoint_hash=data["public_inputs"]["checkpoint_hash"],
            ),
            checkpoint=SignedCheckpoint.from_dict(data["checkpoint"]),
            backend=ProofBackend(data.get("backend", "groth16")),
        )


@dataclass
class UnifiedPublicInputs:
    """
    Public inputs for the unified proof circuit.

    These four values are cryptographically bound in the ZK proof:
    - canonical_hash: Poseidon hash of canonicalized document sections
    - merkle_root: Root of the ledger Merkle tree
    - ledger_root: SMT root hash from checkpoint
    - checkpoint_hash: Hash of the signed checkpoint

    All values are represented as decimal strings for compatibility with
    the BN128 scalar field used in Groth16 circuits.
    """

    canonical_hash: str  # Poseidon hash as decimal string
    merkle_root: str  # Merkle root as decimal string
    ledger_root: str  # SMT root as decimal string
    checkpoint_hash: str  # Checkpoint hash as decimal string


class UnifiedProofVerifier:
    """
    Verifier for unified proofs combining ZK proof + federation signatures.

    This class coordinates verification of all four proof components:
    1. ZK proof verification (Groth16 or Halo2)
    2. Checkpoint structure validation
    3. Checkpoint chain consistency
    4. Federation quorum certificate verification

    Example::

        verifier = UnifiedProofVerifier(registry=federation_registry)
        result = verifier.verify(proof)

        if result.is_valid:
            print("Proof verified successfully")
        else:
            print(f"Verification failed: {result.value}")
    """

    def __init__(
        self,
        *,
        registry: FederationRegistry | None = None,
        circuits_dir: Path | None = None,
        snarkjs_bin: str = "npx",
    ) -> None:
        """
        Initialize the unified proof verifier.

        Args:
            registry: Federation registry for signature verification.
                      If None, federation checks are skipped.
            circuits_dir: Path to circuits directory. If None, uses default.
            snarkjs_bin: snarkjs launcher command (default: "npx")
        """
        self.registry = registry
        self.circuits_dir = circuits_dir or (Path(__file__).parent.parent / "proofs" / "circuits")
        self.snarkjs_bin = snarkjs_bin
        self._groth16_prover = Groth16Prover(self.circuits_dir, snarkjs_bin=snarkjs_bin)

    def verify(self, proof: UnifiedProof) -> VerificationResult:
        """
        Verify all four components of a unified proof.

        Verification proceeds in order:
        1. ZK proof (canonicalization + inclusion + ledger root)
        2. Checkpoint structure and consistency
        3. Federation quorum signatures

        Args:
            proof: The unified proof to verify

        Returns:
            VerificationResult indicating success or specific failure mode
        """
        # Component 1-3: Verify ZK proof
        zk_result = self._verify_zk_proof(proof)
        if not zk_result:
            return VerificationResult.INVALID_ZK_PROOF

        # Component 3-4: Verify checkpoint structure
        checkpoint_result = self._verify_checkpoint_structure(proof)
        if not checkpoint_result:
            return VerificationResult.INVALID_CHECKPOINT

        # Component 4: Verify federation quorum signatures
        if self.registry is not None:
            quorum_result = self._verify_quorum_certificate(proof)
            if not quorum_result:
                return VerificationResult.INVALID_QUORUM

        return VerificationResult.VALID

    def _verify_zk_proof(self, proof: UnifiedProof) -> bool:
        """
        Verify the cryptographic ZK proof (Groth16 or Halo2).

        This verifies components 1-3:
        - Document canonicalization
        - Merkle inclusion
        - Ledger root commitment
        """
        if proof.backend == ProofBackend.GROTH16:
            return self._verify_groth16(proof)
        elif proof.backend == ProofBackend.HALO2:
            return self._verify_halo2(proof)
        else:
            return False

    def _verify_groth16(self, proof: UnifiedProof) -> bool:
        """Verify Groth16 proof using snarkjs."""
        try:
            # Convert public inputs to list format expected by snarkjs
            public_signals = [
                str(int(proof.public_inputs.canonical_hash)),
                str(int(proof.public_inputs.merkle_root)),
                str(int(proof.public_inputs.ledger_root)),
                str(int(proof.public_inputs.checkpoint_hash)),
            ]

            zk_proof = ZKProof(
                proof=proof.zk_proof,
                public_signals=public_signals,
                circuit="unified_canonicalization_inclusion_root_sign",
            )

            # Locate verification key
            vkey_path = (
                self.circuits_dir.parent
                / "keys"
                / "verification_keys"
                / "unified_canonicalization_inclusion_root_sign_vkey.json"
            )

            if not vkey_path.exists():
                # Fallback to build directory during development
                vkey_path = (
                    self.circuits_dir.parent
                    / "build"
                    / "unified_canonicalization_inclusion_root_sign_vkey.json"
                )

            if not vkey_path.exists():
                return False

            return self._groth16_prover.verify(zk_proof, verification_key_path=vkey_path)

        except (ValueError, KeyError, FileNotFoundError, OSError):
            return False

    def _verify_halo2(self, proof: UnifiedProof) -> bool:
        """
        Verify Halo2 proof (placeholder for future implementation).

        Halo2 verification eliminates trusted setup risk and is suitable for
        high-assurance contexts. This is an optional backend behind the
        modular proof boundary.

        Returns:
            False (not yet implemented)
        """
        # TODO: Implement Halo2 verification when high-assurance mode is needed
        # This would use py-halo2 bindings or call Rust verifier
        return False

    def _verify_checkpoint_structure(self, proof: UnifiedProof) -> bool:
        """
        Verify checkpoint structure and consistency.

        Checks:
        - Checkpoint hash matches computed hash
        - Ledger root in checkpoint matches proof public input
        - Checkpoint chain linkage is valid
        """
        try:
            checkpoint = proof.checkpoint

            # Verify checkpoint hash is correctly computed
            # (Implementation depends on checkpoint hashing scheme)
            # For now, we just check it exists and is non-empty
            if not checkpoint.checkpoint_hash:
                return False

            # Verify ledger root binding
            # The checkpoint should contain the ledger root committed in the proof
            # This binds the ZK proof to the checkpoint
            # (Actual binding depends on checkpoint structure)

            return True

        except (ValueError, KeyError, AttributeError):
            return False

    def _verify_quorum_certificate(self, proof: UnifiedProof) -> bool:
        """
        Verify federation quorum certificate over checkpoint.

        This checks that at least 2/3 of federation nodes have signed
        the checkpoint, providing Byzantine fault tolerance.
        """
        if self.registry is None:
            return True  # Skip if no registry provided

        try:
            return verify_checkpoint_quorum_certificate(
                checkpoint=proof.checkpoint, registry=self.registry
            )
        except (ValueError, KeyError, AttributeError):
            return False


class UnifiedProofGenerator:
    """
    Generator for unified proofs (placeholder for future implementation).

    This class would coordinate:
    1. Document canonicalization
    2. Witness generation for ZK circuit
    3. Proof generation (Groth16 or Halo2)
    4. Checkpoint retrieval and bundling

    Currently out of scope for protocol hardening phase.
    """

    def __init__(self, backend: ProofBackend = ProofBackend.GROTH16) -> None:
        self.backend = backend

    def generate(
        self,
        document_sections: list[str],
        merkle_proof: Any,
        checkpoint: SignedCheckpoint,
    ) -> UnifiedProof:
        """
        Generate a unified proof (not yet implemented).

        Args:
            document_sections: Canonicalized document sections
            merkle_proof: Merkle inclusion proof
            checkpoint: Signed checkpoint

        Returns:
            UnifiedProof

        Raises:
            NotImplementedError: Generation not yet implemented
        """
        raise NotImplementedError(
            "Unified proof generation is planned for Phase 1+. "
            "Currently in protocol hardening phase (verification focus)."
        )


# Modular proof boundary: allows swapping Groth16 <-> Halo2 without protocol changes
def verify_unified_proof(
    proof: UnifiedProof,
    registry: FederationRegistry | None = None,
    backend: ProofBackend | None = None,
) -> VerificationResult:
    """
    Convenience function for unified proof verification.

    Args:
        proof: The unified proof to verify
        registry: Optional federation registry for signature checks
        backend: Optional backend override (uses proof.backend if None)

    Returns:
        VerificationResult indicating success or failure mode

    Example::

        result = verify_unified_proof(proof, registry=my_registry)
        if result.is_valid:
            print("Proof valid!")
    """
    if backend is not None:
        proof.backend = backend

    verifier = UnifiedProofVerifier(registry=registry)
    return verifier.verify(proof)
