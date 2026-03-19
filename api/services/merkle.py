"""
Binary Merkle-tree construction and inclusion-proof generation.

Uses SHA-256 for internal nodes.  Lone nodes at any level are promoted
without rehashing (CT-style promotion), matching the behaviour of RFC 6962.

Note on algorithm choice
------------------------
The existing ``protocol.merkle`` module uses BLAKE3 (consistent with the
protocol layer).  This service uses SHA-256 as specified in the FOIA backend
problem statement.  A future integration milestone will reconcile the two.

.. deprecated::
   This module is **quarantined** pending migration to BLAKE3.  All new
   callers should use ``protocol.hashes.merkle_root`` (BLAKE3) instead.
   Existing FOIA tests may continue to exercise this service until the
   migration is complete.
"""

from __future__ import annotations

import hashlib
import warnings
from dataclasses import dataclass, field

# Emit a deprecation notice on first import so operators can audit usage.
warnings.warn(
    "api.services.merkle uses SHA-256, which diverges from the protocol-standard "
    "BLAKE3 Merkle tree.  Use protocol.hashes.merkle_root for new code.  "
    "See fix-04 in the pre-public audit remediation.",
    DeprecationWarning,
    stacklevel=2,
)


@dataclass
class MerkleRoot:
    """The root of a Merkle tree built from a set of leaf hashes.

    Attributes:
        root_hash: Hex-encoded SHA-256 root of the tree.
        leaf_hashes: Sorted list of leaf hashes used to build the tree.
        levels: Internal structure — each element is one level of the tree,
                starting from the leaves (index 0) up to the root (last index).
    """

    root_hash: str
    leaf_hashes: list[str]
    levels: list[list[str]] = field(default_factory=list)


@dataclass
class MerkleProof:
    """An inclusion proof for a single leaf in a Merkle tree.

    Attributes:
        leaf_hash: The hash being proven.
        root_hash: The claimed root of the tree.
        siblings: List of (hash, direction) pairs along the path from the leaf
                  to the root.  ``direction`` is "left" if the sibling is on
                  the left side, "right" if on the right.
    """

    leaf_hash: str
    root_hash: str
    siblings: list[tuple[str, str]] = field(default_factory=list)


def _sha256_pair(left: str, right: str) -> str:
    """Compute SHA-256(left_bytes || right_bytes) over hex-encoded inputs."""
    data = bytes.fromhex(left) + bytes.fromhex(right)
    return hashlib.sha256(data).hexdigest()


def build_tree(leaf_hashes: list[str]) -> MerkleRoot:
    """Build a binary Merkle tree from a list of leaf hashes.

    Leaves are sorted before building so the tree is deterministic regardless
    of insertion order.  Lone nodes at any level are promoted without rehashing
    (CT-style / RFC 6962 behaviour).

    Args:
        leaf_hashes: Hex-encoded SHA-256 leaf hashes.

    Returns:
        A :class:`MerkleRoot` containing the computed root and internal levels.

    Raises:
        ValueError: If ``leaf_hashes`` is empty.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build a Merkle tree from an empty leaf list.")

    current = sorted(leaf_hashes)
    levels: list[list[str]] = [list(current)]

    while len(current) > 1:
        next_level: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
                next_level.append(_sha256_pair(left, right))
            else:
                # CT-style lone-node promotion
                next_level.append(left)
        current = next_level
        levels.append(list(current))

    return MerkleRoot(root_hash=current[0], leaf_hashes=sorted(leaf_hashes), levels=levels)


def generate_proof(leaf_hash: str, tree: MerkleRoot) -> MerkleProof:
    """Generate a Merkle inclusion proof for a given leaf.

    Args:
        leaf_hash: Hex-encoded hash of the leaf to prove.
        tree: A :class:`MerkleRoot` previously built by :func:`build_tree`.

    Returns:
        A :class:`MerkleProof` with the sibling path from leaf to root.

    Raises:
        ValueError: If ``leaf_hash`` is not present in the tree.
    """
    if leaf_hash not in tree.leaf_hashes:
        raise ValueError(f"Leaf {leaf_hash!r} not found in Merkle tree.")

    siblings: list[tuple[str, str]] = []
    index = tree.levels[0].index(leaf_hash)

    for level in tree.levels[:-1]:  # stop before the root level
        if index % 2 == 0:
            # Current node is left child; sibling is on the right
            sibling_index = index + 1
            if sibling_index < len(level):
                siblings.append((level[sibling_index], "right"))
            # Lone node — no sibling to append
        else:
            # Current node is right child; sibling is on the left
            sibling_index = index - 1
            siblings.append((level[sibling_index], "left"))
        index //= 2

    return MerkleProof(leaf_hash=leaf_hash, root_hash=tree.root_hash, siblings=siblings)


def verify_proof(leaf_hash: str, proof: MerkleProof, root: str) -> bool:
    """Verify a Merkle inclusion proof against a known root.

    Args:
        leaf_hash: Hex-encoded leaf hash to verify.
        proof: A :class:`MerkleProof` containing the sibling path.
        root: Hex-encoded expected Merkle root.

    Returns:
        ``True`` if the proof is valid, ``False`` otherwise.
    """
    current = leaf_hash
    for sibling_hash, direction in proof.siblings:
        if direction == "left":
            current = _sha256_pair(sibling_hash, current)
        else:
            current = _sha256_pair(current, sibling_hash)
    return current == root
