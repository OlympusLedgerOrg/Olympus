"""
Merkle tree implementation for Olympus

This module implements Merkle trees and Merkle forests for efficient
cryptographic commitments and proof generation.
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Optional

from .events import CanonicalEvent
from .hashes import HASH_SEPARATOR, LEAF_PREFIX, blake3_hash, node_hash


# Merkle tree version - DO NOT CHANGE
# Changing this breaks all historical Merkle proofs
MERKLE_VERSION = "merkle_v1"
_SEP = HASH_SEPARATOR.encode("utf-8")
logger = logging.getLogger(__name__)


@dataclass
class MerkleNode:
    """A node in a Merkle tree."""

    hash: bytes
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None


@dataclass
class MerkleProof:
    """A Merkle inclusion proof."""

    leaf_hash: bytes
    leaf_index: int
    siblings: list[tuple[bytes, str | bool]]  # (hash, "left" | "right")
    root_hash: bytes


@dataclass
class InclusionProof(MerkleProof):
    """Alias for MerkleProof to match protocol terminology."""


class MerkleTree:
    """
    A Merkle tree for committing to a set of documents.
    """

    def __init__(self, leaves: Sequence[bytes | CanonicalEvent]):
        """
        Construct a Merkle tree from leaf data.

        Leaf data is domain-separated using LEAF_PREFIX before tree construction,
        ensuring structural ambiguity between leaf nodes and internal nodes is
        impossible (second-preimage resistance).

        Args:
            leaves: List of leaf data (canonical event bytes or CanonicalEvent instances)
        """
        if not leaves:
            raise ValueError("Cannot create empty Merkle tree")

        self.leaves: list[bytes] = [self._extract_leaf_bytes(leaf) for leaf in leaves]
        # Apply LEAF_PREFIX domain separation with HASH_SEPARATOR to prevent
        # collisions with internal nodes and to follow structured hashing rules.
        self._leaf_hashes: list[bytes] = [merkle_leaf_hash(leaf) for leaf in self.leaves]
        leaf_nodes = [MerkleNode(hash=h) for h in self._leaf_hashes]
        self._root_node = self._build_tree(leaf_nodes)

    @staticmethod
    def _extract_leaf_bytes(leaf: bytes | CanonicalEvent) -> bytes:
        """Normalize leaf input to raw bytes."""
        if isinstance(leaf, CanonicalEvent):
            return leaf.canonical_bytes
        if isinstance(leaf, bytes | bytearray):
            return bytes(leaf)
        raise ValueError("Leaves must be bytes or CanonicalEvent instances")

    def _build_tree(self, nodes: list[MerkleNode]) -> MerkleNode:
        """Build tree from bottom up."""
        if len(nodes) == 1:
            return nodes[0]

        # Build parent level
        parents = []
        for i in range(0, len(nodes), 2):
            left_node = nodes[i]
            right_node = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            parent_hash = node_hash(left_node.hash, right_node.hash)
            parents.append(
                MerkleNode(
                    hash=parent_hash,
                    left=left_node,
                    right=right_node,
                )
            )

        return self._build_tree(parents)

    def get_root(self) -> bytes:
        """Get the Merkle root hash."""
        return self._root_node.hash

    def root(self) -> bytes:
        """Get the Merkle root hash (alias for get_root)."""
        return self.get_root()

    def generate_proof(self, leaf_index: int) -> MerkleProof:
        """
        Generate inclusion proof for a leaf.

        Args:
            leaf_index: Index of leaf to prove

        Returns:
            Merkle proof
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise ValueError("Invalid leaf index")

        leaf_hash = self._leaf_hashes[leaf_index]
        siblings = []

        # Collect siblings along path to root
        current_level: list[MerkleNode] = [MerkleNode(hash=h) for h in self._leaf_hashes]
        index = leaf_index

        while len(current_level) > 1:
            if index % 2 == 0:
                # Left child, sibling is on right
                sibling_index = index + 1 if index + 1 < len(current_level) else index
                siblings.append((current_level[sibling_index].hash, "right"))
            else:
                # Right child, sibling is on left
                siblings.append((current_level[index - 1].hash, "left"))

            # Move to parent level
            new_level: list[MerkleNode] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else current_level[i]
                new_hash = node_hash(left.hash, right.hash)
                new_level.append(MerkleNode(hash=new_hash, left=left, right=right))

            current_level = new_level
            index = index // 2

        return MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=leaf_index,
            siblings=siblings,
            root_hash=self._root_node.hash,
        )


def verify_proof(proof: MerkleProof) -> bool:
    """
    Verify a Merkle inclusion proof.

    Args:
        proof: Merkle proof to verify

    Returns:
        True if proof is valid
    """
    current_hash = proof.leaf_hash

    for sibling_hash, is_right in proof.siblings:
        if isinstance(is_right, bool):
            is_right = "right" if is_right else "left"
        if is_right == "right":
            current_hash = node_hash(current_hash, sibling_hash)
        elif is_right == "left":
            current_hash = node_hash(sibling_hash, current_hash)
        else:
            raise ValueError("Sibling position must be 'left' or 'right'")

    return current_hash == proof.root_hash


def deserialize_merkle_proof(proof_data: dict[str, Any]) -> MerkleProof:
    """
    Deserialize a Merkle proof, normalizing legacy sibling encodings.

    Historical serialized proofs used string values ("left"/"right") for sibling
    positions. Modern proofs use booleans. This function accepts both and
    normalizes them to the canonical string form before constructing a MerkleProof.

    Args:
        proof_data: Serialized Merkle proof dictionary.

    Returns:
        MerkleProof with normalized sibling positions.
    """
    normalized_siblings: list[tuple[bytes, str]] = []
    for sibling_hash_hex, is_right in proof_data.get("siblings", []):
        if isinstance(is_right, str):
            normalized_flag = is_right.lower() == "right"
            logger.debug("Normalized legacy sibling format", extra={"is_right": is_right})
        else:
            normalized_flag = bool(is_right)
        normalized_siblings.append(
            (bytes.fromhex(sibling_hash_hex), "right" if normalized_flag else "left")
        )

    return MerkleProof(
        leaf_hash=bytes.fromhex(str(proof_data["leaf_hash"])),
        leaf_index=int(proof_data["leaf_index"]),
        siblings=normalized_siblings,
        root_hash=bytes.fromhex(str(proof_data["root_hash"])),
    )


def merkle_leaf_hash(payload: bytes) -> bytes:
    """
    Compute the domain-separated hash of a leaf payload using HASH_SEPARATOR.

    Args:
        payload: Raw leaf payload (canonical event bytes).

    Returns:
        32-byte BLAKE3 hash for use as a Merkle leaf.
    """
    if not isinstance(payload, bytes | bytearray):
        raise ValueError("Leaf payload must be bytes")
    return blake3_hash([LEAF_PREFIX, _SEP, bytes(payload)])
