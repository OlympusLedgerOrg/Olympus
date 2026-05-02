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

import os as _os
from dataclasses import dataclass, field
from typing import Any

from .canonical import normalize_whitespace
from .hashes import blake3_to_field_element, hash_bytes
from .merkle import MerkleProof, MerkleTree, verify_proof
from .poseidon_tree import (
    POSEIDON_DOMAIN_COMMITMENT,
    PoseidonMerkleTree,
    poseidon_hash_with_domain,
)
from .redaction_ledger import (
    DualHashCommitment,
    RedactionProofWithLedger,
    ZKPublicInputs,
    poseidon_root_record_key,
    poseidon_root_to_bytes,
)
from .ssmf import SparseMerkleTree
from .telemetry import get_tracer


# Poseidon redaction circuit parameters
# Default: depth 4 → 16 leaves. Configurable via OLYMPUS_POSEIDON_TREE_DEPTH
# (supports up to depth 8 → 256 leaves).
_POSEIDON_TREE_DEPTH_RAW = _os.environ.get("OLYMPUS_POSEIDON_TREE_DEPTH", "4")
try:
    _POSEIDON_TREE_DEPTH = int(_POSEIDON_TREE_DEPTH_RAW)
except ValueError as _exc:
    raise ValueError(
        f"OLYMPUS_POSEIDON_TREE_DEPTH must be an integer (1–8); got {_POSEIDON_TREE_DEPTH_RAW!r}"
    ) from _exc
if _POSEIDON_TREE_DEPTH < 1 or _POSEIDON_TREE_DEPTH > 8:
    raise ValueError(
        f"OLYMPUS_POSEIDON_TREE_DEPTH must be between 1 and 8; got {_POSEIDON_TREE_DEPTH}"
    )


def _poseidon_capacity_error(max_leaves: int, actual: int) -> ValueError:
    """Return a :class:`ValueError` for exceeding the Poseidon tree capacity."""
    return ValueError(f"Poseidon tree supports at most {max_leaves} sections; got {actual}")


@dataclass
class RedactionProofRequest:
    """Request object for :meth:`RedactionProtocol.create_redaction_proof_with_ledger`.

    Encapsulates all parameters needed to create a
    :class:`~protocol.redaction_ledger.RedactionProofWithLedger`, improving
    readability at call sites and enabling forward-compatible extension.

    Attributes:
        document_parts: Ordered list of document sections (same canonical bytes
            used at commit time).
        revealed_indices: Zero-based indices of sections to reveal.
        poseidon_root: Decimal string of the Poseidon root (must match what was
            inserted via :meth:`~RedactionProtocol.commit_document_dual`).
        smt: The SMT containing the Poseidon root record.
        document_id: Document identifier (same as passed to
            :meth:`~RedactionProtocol.commit_document_dual`).
        version: Version number (same as passed to
            :meth:`~RedactionProtocol.commit_document_dual`).
        zk_proof: Opaque Groth16 proof dict (snarkjs JSON format with keys
            ``"pi_a"``, ``"pi_b"``, ``"pi_c"``, and ``"protocol"``).
        poseidon_tree_depth: Depth of the Poseidon Merkle tree.  Determines the
            maximum number of sections (``2**poseidon_tree_depth``).  Defaults
            to :data:`_POSEIDON_TREE_DEPTH` (4 → 16 leaves).  Increase this
            value when documents may exceed that section count.
    """

    document_parts: list[str]
    revealed_indices: list[int]
    poseidon_root: str
    smt: "SparseMerkleTree"
    document_id: str
    version: int
    zk_proof: "dict[str, Any]"
    poseidon_tree_depth: int = field(default=_POSEIDON_TREE_DEPTH)


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


@dataclass
class SectionMetadata:
    """Structured canonicalization metadata for a document section.

    Each section in a canonicalized document carries metadata that binds its
    content to its position and length. This prevents length-extension and
    section-reordering attacks in the Poseidon commitment chain.

    Attributes:
        section_index: Zero-based position of the section.
        section_count: Total number of sections in the document.
        section_length: Byte length of the canonical section content.
        section_hash: BLAKE3 hex hash of the canonical section bytes.
    """

    section_index: int
    section_count: int
    section_length: int
    section_hash: str


@dataclass
class RedactionCorrectnessProof:
    """Binds an original commitment to a redacted commitment.

    This proof ensures that a redacted document is derived from the same
    pre-committed original by binding both the BLAKE3 Merkle roots and
    the Poseidon Merkle roots together.

    Attributes:
        original_blake3_root: Hex BLAKE3 root of the original document.
        redacted_blake3_root: Hex BLAKE3 root of the redacted document
            (with redacted sections replaced by zero-hash leaves).
        original_poseidon_root: Decimal Poseidon root of the original.
        redacted_poseidon_root: Decimal Poseidon root of the redacted.
        revealed_indices: Indices of sections that are revealed.
        binding_hash: BLAKE3 hash binding all four roots together.
    """

    original_blake3_root: str
    redacted_blake3_root: str
    original_poseidon_root: str
    redacted_poseidon_root: str
    revealed_indices: list[int]
    binding_hash: str


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
    def canonical_section_bytes(section: str) -> bytes:
        """
        Canonical byte representation for a document section.

        The canonical form normalizes whitespace (per ``normalize_whitespace``)
        and encodes the result as UTF-8. Both the BLAKE3 and Poseidon Merkle
        trees MUST derive their leaves from this exact byte sequence to ensure
        the two commitments are bound to the same document semantics.
        """
        normalized = normalize_whitespace(section)
        return normalized.encode("utf-8")

    @classmethod
    def canonical_section_bytes_list(cls, parts: list[str]) -> list[bytes]:
        """Apply :meth:`canonical_section_bytes` to every part."""
        return [cls.canonical_section_bytes(part) for part in parts]

    @staticmethod
    def create_leaf_hashes(parts: list[str]) -> list[bytes]:
        """
        Compute BLAKE3 leaf hashes for a list of document sections.

        Each section is normalized (``normalize_whitespace``) and encoded as
        UTF-8 before hashing. The resulting bytes are later domain-separated
        as Merkle leaves by :class:`~protocol.merkle.MerkleTree`.

        Args:
            parts: Ordered list of document sections (strings).

        Returns:
            List of 32-byte BLAKE3 hashes, one per section.
        """
        canonical_bytes = RedactionProtocol.canonical_section_bytes_list(parts)
        return [hash_bytes(part_bytes) for part_bytes in canonical_bytes]

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

        Raises:
            ValueError: If any index is out of bounds for the tree.
        """
        n_leaves = len(tree.leaves)
        for idx in revealed_indices:
            if idx < 0 or idx >= n_leaves:
                raise ValueError(
                    f"Revealed index {idx} is out of bounds for a tree with "
                    f"{n_leaves} leaf/leaves (valid range: 0–{n_leaves - 1})"
                )
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
                content_hash = hash_bytes(RedactionProtocol.canonical_section_bytes(content)).hex()
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

                # 4. Leaf index must match the revealed index
                if mp.leaf_index != proof.revealed_indices[i]:
                    span.set_attribute("verification_result", f"failed_leaf_index_mismatch_at_{i}")
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
        poseidon_tree_depth: int = _POSEIDON_TREE_DEPTH,
    ) -> tuple["MerkleTree", DualHashCommitment]:
        """
        Commit a document using the dual-anchor strategy.

        Builds the standard BLAKE3 Merkle commitment (same as
        :meth:`commit_document`) **and** inserts the Poseidon Merkle root used
        by the Groth16 ZK circuit into *smt* under a dedicated
        ``"redaction_root_poseidon"`` key. The public commitment is reduced to
        the root pair only (BLAKE3 root + Poseidon root); no Merkle tree
        structure is persisted or returned.

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
            poseidon_tree_depth: Depth of the Poseidon Merkle tree used to
                produce *poseidon_root*.  Determines the maximum number of
                sections (``2**poseidon_tree_depth``).  Defaults to
                :data:`_POSEIDON_TREE_DEPTH`.

        Returns:
            Tuple of ``(tree, DualHashCommitment)``. The commitment contains
            only the BLAKE3 root (hex) and Poseidon root (decimal string).

        Raises:
            ValueError: If *poseidon_root* is not a valid field element.
        """
        max_leaves = 1 << poseidon_tree_depth
        if len(document_parts) > max_leaves:
            raise _poseidon_capacity_error(max_leaves, len(document_parts))

        canonical_sections = RedactionProtocol.canonical_section_bytes_list(document_parts)

        # Standard BLAKE3 commitment using the canonical section bytes
        leaf_hashes = [hash_bytes(part_bytes) for part_bytes in canonical_sections]
        tree = MerkleTree(leaf_hashes)
        blake3_root = tree.get_root().hex()

        # Anchor the Poseidon root in the SMT under its own key namespace.
        # ADR-0003: the Poseidon root is not produced by a content parser, so
        # we use the fallback parser identity for this SMT leaf's domain binding.
        key = poseidon_root_record_key(document_id, version)
        poseidon_bytes = poseidon_root_to_bytes(poseidon_root)
        smt.update(key, poseidon_bytes, "fallback@1.0.0", "v1")

        normalized_poseidon_root = str(int.from_bytes(poseidon_bytes, byteorder="big"))
        commitment = DualHashCommitment(
            blake3_root=blake3_root,
            poseidon_root=normalized_poseidon_root,
        )

        return tree, commitment

    @staticmethod
    def _poseidon_leaves_from_sections(
        canonical_sections: list[bytes],
        depth: int = _POSEIDON_TREE_DEPTH,
    ) -> list[int]:
        """Derive Poseidon field elements from canonical section bytes with padding.

        Args:
            canonical_sections: Canonical byte representations of document sections.
            depth: Poseidon tree depth; determines the padded leaf count
                (``2**depth``).  Defaults to :data:`_POSEIDON_TREE_DEPTH`.

        Raises:
            ValueError: If the number of sections exceeds ``2**depth``.
        """
        max_leaves = 1 << depth
        if len(canonical_sections) > max_leaves:
            raise _poseidon_capacity_error(max_leaves, len(canonical_sections))

        leaves = [int(blake3_to_field_element(part_bytes)) for part_bytes in canonical_sections]
        if len(leaves) < max_leaves:
            leaves.extend([0] * (max_leaves - len(leaves)))
        return leaves

    @classmethod
    def build_poseidon_tree(
        cls,
        document_parts: list[str],
        depth: int = _POSEIDON_TREE_DEPTH,
    ) -> tuple[PoseidonMerkleTree, list[int]]:
        """
        Build the Poseidon Merkle tree for a document.

        Returns both the tree and the padded leaf vector (``2**depth`` leaves).

        Args:
            document_parts: Ordered list of document sections.
            depth: Poseidon tree depth; the tree supports ``2**depth`` sections.
                Defaults to :data:`_POSEIDON_TREE_DEPTH` (4 → 16 sections).

        Raises:
            ValueError: If ``document_parts`` exceeds ``2**depth`` sections.
        """
        max_leaves = 1 << depth
        # L3-B: Explicit guard before hashing (defense-in-depth)
        if len(document_parts) > max_leaves:
            raise _poseidon_capacity_error(max_leaves, len(document_parts))
        canonical_sections = cls.canonical_section_bytes_list(document_parts)
        leaves = cls._poseidon_leaves_from_sections(canonical_sections, depth=depth)
        return PoseidonMerkleTree(leaves, depth=depth), leaves

    @staticmethod
    def create_redaction_proof_with_ledger(
        document_parts: "RedactionProofRequest | list[str]",
        revealed_indices: list[int] | None = None,
        poseidon_root: str | None = None,
        smt: "SparseMerkleTree | None" = None,
        document_id: str | None = None,
        version: int | None = None,
        zk_proof: "dict[str, Any] | None" = None,
        poseidon_tree_depth: int = _POSEIDON_TREE_DEPTH,
    ) -> "RedactionProofWithLedger":
        """
        Create a :class:`~protocol.redaction_ledger.RedactionProofWithLedger`.

        Generates an SMT existence proof for the Poseidon root that was
        previously inserted by :meth:`commit_document_dual`, then wraps it
        together with the ZK proof blob and its public inputs.

        This method accepts either a :class:`RedactionProofRequest` object as
        the sole positional argument (via *document_parts*), or the individual
        keyword/positional arguments for backwards compatibility.

        Args:
            document_parts: A :class:`RedactionProofRequest` that bundles all
                parameters, **or** the ordered list of document sections (same
                canonical bytes used at commit time) when passing arguments
                individually.
            revealed_indices: Zero-based indices of sections to reveal.  Must
                be provided when *document_parts* is a list.
            poseidon_root: Decimal string of the Poseidon root (must match what
                was inserted via :meth:`commit_document_dual`).  Must be
                provided when *document_parts* is a list.
            smt: The SMT containing the Poseidon root record.  Must be provided
                when *document_parts* is a list.
            document_id: Document identifier (same as passed to
                :meth:`commit_document_dual`).  Must be provided when
                *document_parts* is a list.
            version: Version number (same as passed to
                :meth:`commit_document_dual`).  Must be provided when
                *document_parts* is a list.
            zk_proof: Opaque Groth16 proof dict.  The expected structure
                follows the snarkjs JSON format with keys ``"pi_a"``,
                ``"pi_b"``, ``"pi_c"``, and ``"protocol"``.  This layer treats
                the dict as opaque and passes it through to the ZK verifier.
                Must be provided when *document_parts* is a list.
            poseidon_tree_depth: Depth of the Poseidon Merkle tree when passing
                arguments individually.  Ignored when a
                :class:`RedactionProofRequest` is provided (use
                :attr:`RedactionProofRequest.poseidon_tree_depth` instead).
                Defaults to :data:`_POSEIDON_TREE_DEPTH`.

        Returns:
            A :class:`~protocol.redaction_ledger.RedactionProofWithLedger`
            ready for transport and verification.
        """
        # Unpack from a request object if one was provided
        if isinstance(document_parts, RedactionProofRequest):
            req = document_parts
            document_parts = req.document_parts
            revealed_indices = req.revealed_indices
            poseidon_root = req.poseidon_root
            smt = req.smt
            document_id = req.document_id
            version = req.version
            zk_proof = req.zk_proof
            depth = req.poseidon_tree_depth
        else:
            if (
                revealed_indices is None
                or poseidon_root is None
                or smt is None
                or document_id is None
                or version is None
                or zk_proof is None
            ):
                raise ValueError(
                    "All of revealed_indices, poseidon_root, smt, document_id, version, "
                    "and zk_proof must be provided when document_parts is passed as a list"
                )
            depth = poseidon_tree_depth

        max_leaves = 1 << depth
        poseidon_tree, poseidon_leaves = RedactionProtocol.build_poseidon_tree(
            document_parts, depth=depth
        )
        computed_poseidon_root = poseidon_tree.get_root()
        normalized_poseidon_root = str(int(poseidon_root))
        poseidon_root_to_bytes(normalized_poseidon_root)

        if normalized_poseidon_root != computed_poseidon_root:
            raise ValueError(
                "Provided poseidon_root does not match canonical document sections; "
                "ensure both commitments use the same canonical leaf bytes"
            )

        if any(idx < 0 or idx >= len(document_parts) for idx in revealed_indices):
            raise ValueError("Revealed indices must be within the document length")

        revealed_set = set(revealed_indices)
        nullified_leaves = [
            poseidon_leaves[i] if i in revealed_set else 0 for i in range(max_leaves)
        ]
        redacted_tree = PoseidonMerkleTree(nullified_leaves, depth=depth)
        redacted_commitment = redacted_tree.get_root()
        revealed_count = len(revealed_set)

        key = poseidon_root_record_key(document_id, version)
        smt_proof = smt.prove_existence(key)

        public_inputs = ZKPublicInputs(
            original_root=computed_poseidon_root,
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

    @staticmethod
    def build_section_metadata(document_parts: list[str]) -> list[SectionMetadata]:
        """
        Build structured canonicalization metadata for each document section.

        The metadata includes sectionCount, sectionLength, and sectionHash for
        every section, binding each section's content to its position and the
        total document structure. This prevents length-extension attacks and
        section-reordering attacks in the Poseidon commitment chain.

        Args:
            document_parts: Ordered list of document sections.

        Returns:
            List of :class:`SectionMetadata` objects, one per section.
        """
        canonical_bytes = RedactionProtocol.canonical_section_bytes_list(document_parts)
        section_count = len(document_parts)
        metadata: list[SectionMetadata] = []
        for i, section_bytes in enumerate(canonical_bytes):
            metadata.append(
                SectionMetadata(
                    section_index=i,
                    section_count=section_count,
                    section_length=len(section_bytes),
                    section_hash=hash_bytes(section_bytes).hex(),
                )
            )
        return metadata

    @staticmethod
    def structured_canonical_commitment(document_parts: list[str]) -> str:
        """
        Compute a structured canonical commitment over document sections.

        Chains Poseidon hashes over ``(sectionCount, sectionLength_i,
        sectionHash_i)`` triples to bind the document structure into the
        commitment. This ensures that two documents with different section
        counts or different section lengths cannot produce the same
        commitment, even if the concatenated content is identical.

        Args:
            document_parts: Ordered list of document sections.

        Returns:
            Decimal string of the Poseidon commitment hash.
        """
        from .hashes import SNARK_SCALAR_FIELD as _F

        metadata = RedactionProtocol.build_section_metadata(document_parts)
        section_count = len(document_parts)

        # Seed the chain with the section count
        acc = section_count % _F

        for meta in metadata:
            # Chain: acc = Poseidon(acc, sectionLength) with commitment domain
            acc = poseidon_hash_with_domain(
                acc, meta.section_length % _F, POSEIDON_DOMAIN_COMMITMENT
            )
            # Chain: acc = Poseidon(acc, sectionHash-as-field-element)
            section_hash_int = int(meta.section_hash, 16) % _F
            acc = poseidon_hash_with_domain(acc, section_hash_int, POSEIDON_DOMAIN_COMMITMENT)

        return str(acc % _F)

    @staticmethod
    def create_redaction_correctness_proof(
        document_parts: list[str],
        revealed_indices: list[int],
        poseidon_tree_depth: int = _POSEIDON_TREE_DEPTH,
    ) -> RedactionCorrectnessProof:
        """
        Create a correctness proof binding original and redacted commitments.

        This proof demonstrates that the redacted document is derived from the
        original by computing both BLAKE3 and Poseidon Merkle roots for the
        original and the redacted version, then binding all four roots with a
        BLAKE3 hash.

        Args:
            document_parts: Ordered list of original document sections.
            revealed_indices: Zero-based indices of sections to reveal.
            poseidon_tree_depth: Depth of the Poseidon Merkle tree.  Determines
                the maximum number of sections (``2**poseidon_tree_depth``).
                Defaults to :data:`_POSEIDON_TREE_DEPTH`.

        Returns:
            :class:`RedactionCorrectnessProof` binding both commitments.

        Raises:
            ValueError: If revealed indices are out of bounds or if document
                exceeds ``2**poseidon_tree_depth`` sections.
        """
        from .hashes import HASH_SEPARATOR

        max_leaves = 1 << poseidon_tree_depth

        # L3-B: Explicit guard before hashing
        if len(document_parts) > max_leaves:
            raise _poseidon_capacity_error(max_leaves, len(document_parts))

        if any(idx < 0 or idx >= len(document_parts) for idx in revealed_indices):
            raise ValueError("Revealed indices must be within the document length")

        # Original commitments
        orig_tree, orig_blake3_root = RedactionProtocol.commit_document(document_parts)
        poseidon_tree, poseidon_leaves = RedactionProtocol.build_poseidon_tree(
            document_parts, depth=poseidon_tree_depth
        )
        orig_poseidon_root = poseidon_tree.get_root()

        # Redacted BLAKE3: replace redacted leaves with a domain-separated marker
        # to avoid collision with legitimately empty document sections.
        revealed_set = set(revealed_indices)
        redacted_leaf_hash = hash_bytes(b"OLY:REDACTED-SECTION")
        redacted_leaf_hashes = [
            RedactionProtocol.create_leaf_hashes(document_parts)[i]
            if i in revealed_set
            else redacted_leaf_hash
            for i in range(len(document_parts))
        ]
        redacted_blake3_tree = MerkleTree(redacted_leaf_hashes)
        redacted_blake3_root = redacted_blake3_tree.get_root().hex()

        # Redacted Poseidon: replace redacted leaves with 0
        redacted_poseidon_leaves = [
            poseidon_leaves[i] if i in revealed_set else 0 for i in range(max_leaves)
        ]
        redacted_poseidon_tree = PoseidonMerkleTree(
            redacted_poseidon_leaves, depth=poseidon_tree_depth
        )
        redacted_poseidon_root = redacted_poseidon_tree.get_root()

        # Bind all four roots together
        binding_data = HASH_SEPARATOR.join(
            [
                orig_blake3_root,
                redacted_blake3_root,
                orig_poseidon_root,
                redacted_poseidon_root,
                ",".join(str(i) for i in sorted(revealed_indices)),
            ]
        )
        binding_hash = hash_bytes(binding_data.encode("utf-8")).hex()

        return RedactionCorrectnessProof(
            original_blake3_root=orig_blake3_root,
            redacted_blake3_root=redacted_blake3_root,
            original_poseidon_root=orig_poseidon_root,
            redacted_poseidon_root=redacted_poseidon_root,
            revealed_indices=sorted(revealed_indices),
            binding_hash=binding_hash,
        )

    @staticmethod
    def verify_redaction_correctness_proof(
        proof: RedactionCorrectnessProof,
    ) -> bool:
        """
        Verify a redaction correctness proof.

        Re-derives the binding hash from the four roots and the revealed
        indices and checks it matches the stored binding hash.

        Args:
            proof: The :class:`RedactionCorrectnessProof` to verify.

        Returns:
            ``True`` if the binding hash is valid, ``False`` otherwise.
        """
        from .hashes import HASH_SEPARATOR

        binding_data = HASH_SEPARATOR.join(
            [
                proof.original_blake3_root,
                proof.redacted_blake3_root,
                proof.original_poseidon_root,
                proof.redacted_poseidon_root,
                ",".join(str(i) for i in sorted(proof.revealed_indices)),
            ]
        )
        expected = hash_bytes(binding_data.encode("utf-8")).hex()
        return expected == proof.binding_hash
