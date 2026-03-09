"""
Redaction protocol for Olympus.

This module provides cryptographic redaction proofs that allow a prover to
reveal a subset of document sections while proving they are derived from a
committed Merkle root, without revealing the content of redacted sections.

Designed for FOIA workflows where an agency must prove that a redacted
response is derived from the same pre-committed original document.

Pipeline:
    commit_document()  → create Merkle commitment before disclosure
    create_redaction_proof()  → prove a subset of sections at release time
    verify_redaction_proof()  → independently verify the proof

Independence guarantee: verification requires only the proof and the
revealed content — no access to the original document or private keys.
"""

from dataclasses import dataclass
from typing import Any

from .hashes import hash_bytes
from .merkle import MerkleProof, MerkleTree, verify_proof
from .redaction_ledger import (
    RedactionProofWithLedger,
    ZKPublicInputs,
    poseidon_root_record_key,
    poseidon_root_to_bytes,
)
from .ssmf import SparseMerkleTree
from .telemetry import get_tracer


@dataclass
class RedactionProof:
    """
    Cryptographic proof that revealed document sections are derived from a
    pre-committed Merkle root.

    Attributes:
        original_root: Hex-encoded Merkle root hash of the committed document.
        revealed_indices: Zero-based indices of revealed document sections.
        revealed_hashes: Hex-encoded BLAKE3 hashes of each revealed section.
        merkle_proofs: Merkle inclusion proofs for each revealed section.
    """

    original_root: str
    revealed_indices: list[int]
    revealed_hashes: list[str]
    merkle_proofs: list[MerkleProof]

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, RedactionProof):
            return NotImplemented
        return (
            self.original_root == other.original_root
            and self.revealed_indices == other.revealed_indices
            and self.revealed_hashes == other.revealed_hashes
            and self.merkle_proofs == other.merkle_proofs
        )


def apply_redaction(
    original: str,
    mask: list[int],
    replacement: str = "█",
) -> str:
    """
    Apply a redaction mask to a string.

    Each character in ``original`` is replaced by ``replacement`` where the
    corresponding mask value is 1, and left unchanged where it is 0.

    Args:
        original: The original string to redact.
        mask: A list of integers (0 or 1), one per character.  1 means
              redact that character; 0 means keep it.
        replacement: Character(s) used as the redaction marker.

    Returns:
        Redacted string with masked characters replaced by ``replacement``.

    Raises:
        ValueError: If ``len(mask) != len(original)``.
    """
    if len(mask) != len(original):
        raise ValueError(
            f"Mask length must equal original text length (mask={len(mask)}, text={len(original)})"
        )

    return "".join(replacement if mask[i] else ch for i, ch in enumerate(original))


class RedactionProtocol:
    """
    Merkle-based selective-disclosure redaction protocol.

    Workflow:
      1. Before any FOIA request arrives, call :meth:`commit_document` to
         obtain a :class:`~protocol.merkle.MerkleTree` and root hash.
         Record the root hash in the ledger.
      2. At release time, call :meth:`create_redaction_proof` with the tree
         and the indices of sections the agency chooses to reveal.
      3. Any third party can call :meth:`verify_redaction_proof` with only
         the proof and the revealed text — no original document needed.
    """

    @staticmethod
    def create_leaf_hashes(parts: list[str]) -> list[bytes]:
        """
        Compute BLAKE3 leaf hashes for a list of document sections.

        Each section is encoded as UTF-8 before hashing.

        Args:
            parts: Ordered list of document sections (strings).

        Returns:
            List of 32-byte BLAKE3 hashes, one per section.
        """
        return [hash_bytes(part.encode("utf-8")) for part in parts]

    @staticmethod
    def commit_document(document_parts: list[str]) -> tuple["MerkleTree", str]:
        """
        Commit to a document by building a Merkle tree over its sections.

        The commitment is deterministic: identical inputs always produce the
        same root hash.

        Args:
            document_parts: Ordered list of document sections.

        Returns:
            Tuple of ``(tree, root_hash_hex)`` where ``root_hash_hex`` is the
            64-character hex-encoded BLAKE3 Merkle root.
        """
        tracer = get_tracer()
        with tracer.start_as_current_span("redaction.commit_document") as span:
            span.set_attribute("document_parts_count", len(document_parts))
            leaf_hashes = RedactionProtocol.create_leaf_hashes(document_parts)
            tree = MerkleTree(leaf_hashes)
            root_hash = tree.get_root().hex()
            span.set_attribute("merkle_root", root_hash)
            return tree, root_hash

    @staticmethod
    def create_redaction_proof(
        tree: "MerkleTree",
        revealed_indices: list[int],
    ) -> RedactionProof:
        """
        Create a selective-disclosure redaction proof.

        For each index in ``revealed_indices``, generates a Merkle inclusion
        proof that ties the corresponding leaf to the committed root.

        Args:
            tree: The :class:`~protocol.merkle.MerkleTree` returned by
                  :meth:`commit_document`.
            revealed_indices: Zero-based indices of sections to reveal.

        Returns:
            A :class:`RedactionProof` containing the original root hash,
            revealed leaf hashes, and Merkle inclusion proofs.
        """
        tracer = get_tracer()
        with tracer.start_as_current_span("redaction.create_proof") as span:
            span.set_attribute("revealed_indices_count", len(revealed_indices))
            original_root = tree.get_root().hex()
            revealed_hashes: list[str] = []
            merkle_proofs: list[MerkleProof] = []

            for idx in revealed_indices:
                # tree.leaves holds the raw leaf bytes (hash_bytes output)
                revealed_hashes.append(tree.leaves[idx].hex())
                merkle_proofs.append(tree.generate_proof(idx))

            span.set_attribute("original_root", original_root)
            return RedactionProof(
                original_root=original_root,
                revealed_indices=list(revealed_indices),
                revealed_hashes=revealed_hashes,
                merkle_proofs=merkle_proofs,
            )

    @staticmethod
    def verify_redaction_proof(
        proof: RedactionProof,
        revealed_content: list[str],
    ) -> bool:
        """
        Verify a redaction proof against revealed content.

        Checks:
        1. Structural consistency (lengths match across proof fields).
        2. Each revealed section hashes to the committed leaf hash.
        3. Each Merkle inclusion proof is cryptographically valid.
        4. Every Merkle proof's root hash matches the claimed original root.

        No access to the original document or signing keys is required.

        Args:
            proof: The :class:`RedactionProof` issued at release time.
            revealed_content: The actual text of each revealed section, in
                              the same order as ``proof.revealed_indices``.

        Returns:
            ``True`` if the proof is valid; ``False`` otherwise.
        """
        tracer = get_tracer()
        with tracer.start_as_current_span("redaction.verify_proof") as span:
            span.set_attribute("revealed_indices_count", len(proof.revealed_indices))
            span.set_attribute("original_root", proof.original_root)

            n = len(proof.revealed_indices)

            # Structural consistency checks
            if len(revealed_content) != n:
                span.set_attribute("verification_result", "failed_content_length_mismatch")
                return False
            if len(proof.revealed_hashes) != n:
                span.set_attribute("verification_result", "failed_hashes_length_mismatch")
                return False
            if len(proof.merkle_proofs) != n:
                span.set_attribute("verification_result", "failed_proofs_length_mismatch")
                return False

            for i, content in enumerate(revealed_content):
                # 1. Content must hash to the committed leaf hash
                content_hash = hash_bytes(content.encode("utf-8")).hex()
                if content_hash != proof.revealed_hashes[i]:
                    span.set_attribute("verification_result", f"failed_hash_mismatch_at_{i}")
                    return False

                # 2. Merkle inclusion proof must be cryptographically valid
                mp = proof.merkle_proofs[i]
                if not verify_proof(mp):
                    span.set_attribute("verification_result", f"failed_merkle_proof_invalid_at_{i}")
                    return False

                # 3. Proof root must match the claimed original root
                if mp.root_hash.hex() != proof.original_root:
                    span.set_attribute("verification_result", f"failed_root_mismatch_at_{i}")
                    return False

            span.set_attribute("verification_result", "success")
            return True

    @staticmethod
    def commit_document_dual(
        document_parts: list[str],
        poseidon_root: str,
        smt: "SparseMerkleTree",
        document_id: str,
        version: int,
    ) -> tuple["MerkleTree", str]:
        """
        Commit a document using the dual-anchor strategy.

        Builds the standard BLAKE3 Merkle commitment (same as
        :meth:`commit_document`) **and** inserts the Poseidon Merkle root used
        by the Groth16 ZK circuit into *smt* under a dedicated
        ``"redaction_root_poseidon"`` key.

        This anchors both commitment types in the same BLAKE3 SMT so that a
        verifier can:

        1. Confirm SMT membership of the Poseidon root (via an existence proof).
        2. Independently verify the ZK proof against the public inputs that
           include the same Poseidon root.

        No BLAKE3→Poseidon bridge circuit is needed; the two proofs are
        checked separately.

        Args:
            document_parts: Ordered list of document sections.
            poseidon_root: Decimal string of the Poseidon Merkle root for the
                           same document sections (computed externally, e.g.
                           via :class:`~protocol.poseidon_tree.PoseidonMerkleTree`).
            smt: The :class:`~protocol.ssmf.SparseMerkleTree` to update.
            document_id: Unique identifier for this document (used in key
                         derivation; see :func:`~protocol.redaction_ledger.poseidon_root_record_key`).
            version: Version number for append-only key derivation.

        Returns:
            Tuple of ``(tree, blake3_root_hex)`` identical to the return value
            of :meth:`commit_document`.

        Raises:
            ValueError: If *poseidon_root* is not a valid field element.
        """
        # Standard BLAKE3 commitment
        tree, blake3_root = RedactionProtocol.commit_document(document_parts)

        # Anchor the Poseidon root in the SMT under its own key namespace
        key = poseidon_root_record_key(document_id, version)
        value = poseidon_root_to_bytes(poseidon_root)
        smt.update(key, value)

        return tree, blake3_root

    @staticmethod
    def create_redaction_proof_with_ledger(
        tree: "MerkleTree",
        revealed_indices: list[int],
        poseidon_root: str,
        smt: "SparseMerkleTree",
        document_id: str,
        version: int,
        zk_proof: "dict[str, Any]",
        redacted_commitment: str,
        revealed_count: int,
    ) -> "RedactionProofWithLedger":
        """
        Create a :class:`~protocol.redaction_ledger.RedactionProofWithLedger`.

        Generates an SMT existence proof for the Poseidon root that was
        previously inserted by :meth:`commit_document_dual`, then wraps it
        together with the ZK proof blob and its public inputs.

        Args:
            tree: The :class:`~protocol.merkle.MerkleTree` from
                  :meth:`commit_document_dual`.
            revealed_indices: Zero-based indices of sections to reveal (used to
                              build the inner :class:`RedactionProof`).
            poseidon_root: Decimal string of the Poseidon root (must match what
                           was inserted via :meth:`commit_document_dual`).
            smt: The SMT containing the Poseidon root record.
            document_id: Document identifier (same as passed to
                         :meth:`commit_document_dual`).
            version: Version number (same as passed to
                     :meth:`commit_document_dual`).
            zk_proof: Opaque Groth16 proof dict. The expected structure follows
                      the snarkjs JSON format with keys ``"pi_a"``, ``"pi_b"``,
                      ``"pi_c"``, and ``"protocol"``. This layer treats the
                      dict as opaque and passes it through to the ZK verifier.
            redacted_commitment: Decimal string of the ``redactedCommitment``
                                 public signal from the ZK circuit.
            revealed_count: Integer value of the ``revealedCount`` public signal.

        Returns:
            A :class:`~protocol.redaction_ledger.RedactionProofWithLedger`
            ready for transport and verification.
        """
        key = poseidon_root_record_key(document_id, version)
        smt_proof = smt.prove_existence(key)

        public_inputs = ZKPublicInputs(
            original_root=poseidon_root,
            redacted_commitment=redacted_commitment,
            revealed_count=revealed_count,
        )

        return RedactionProofWithLedger(
            smt_proof=smt_proof,
            zk_proof=zk_proof,
            zk_public_inputs=public_inputs,
        )

    @staticmethod
    def reconstruct_redacted_document(
        revealed_content: list[str],
        revealed_indices: list[int],
        total_parts: int,
        redaction_marker: str = "[REDACTED]",
    ) -> list[str]:
        """
        Reconstruct a document representation with redaction markers.

        Positions not present in ``revealed_indices`` are filled with
        ``redaction_marker``.

        Args:
            revealed_content: Revealed section text, one entry per index in
                               ``revealed_indices`` (extra items are ignored).
            revealed_indices: Ordered zero-based indices of revealed sections.
            total_parts: Total number of sections in the original document.
            redaction_marker: Placeholder text for redacted sections.

        Returns:
            List of length ``total_parts`` containing revealed text or
            ``redaction_marker`` at each position.
        """
        # Build a mapping from index to revealed text
        index_to_content: dict[int, str] = {}
        for idx, content in zip(revealed_indices, revealed_content):
            index_to_content[idx] = content

        return [
            index_to_content[i] if i in index_to_content else redaction_marker
            for i in range(total_parts)
        ]
