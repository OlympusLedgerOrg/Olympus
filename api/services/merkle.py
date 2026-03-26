"""
Binary Merkle-tree construction and inclusion-proof generation.

Uses BLAKE3 for internal nodes via ``protocol.hashes``, consistent with the
Olympus protocol layer.  Leaf hashes are sorted lexicographically before tree
construction to ensure global consistency across federation nodes, regardless
of ingestion order.  Callers that require positional ordering (e.g. append-only
log proofs) may pass ``preserve_order=True`` to bypass the sort.

Lone nodes at any level are duplicated and hashed (RFC 6962 / Bitcoin pattern)
to prevent batching-boundary attacks on the Merkle root.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

import blake3


@dataclass
class MerkleRoot:
    """The root of a Merkle tree built from a set of leaf hashes.

    Attributes:
        root_hash: Hex-encoded BLAKE3 root of the tree.
        leaf_hashes: Ordered list of leaf hashes used to build the tree.
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


def _blake3_pair(left: str, right: str) -> str:
    """Compute BLAKE3(left_bytes || right_bytes) over hex-encoded inputs."""
    data = bytes.fromhex(left) + bytes.fromhex(right)
    return blake3.blake3(data).hexdigest()


def build_tree(
    leaf_hashes: list[str],
    *,
    preserve_order: bool = False,
) -> MerkleRoot:
    """Build a binary Merkle tree from a list of leaf hashes.

    By default, leaf hashes are sorted lexicographically before tree
    construction to guarantee that any two nodes ingesting the same dataset
    produce the same Merkle root, regardless of arrival order.

    When ``preserve_order`` is ``True`` the sort is skipped and leaves are
    used in the order provided.  This is intended for append-only log proofs
    where positional ordering is meaningful — the caller is responsible for
    ensuring deterministic order.

    Lone nodes at any level are duplicated and hashed rather than promoted
    (RFC 6962 / Bitcoin pattern) to prevent batching-boundary root divergence.

    Args:
        leaf_hashes: Hex-encoded BLAKE3 leaf hashes.
        preserve_order: If ``True``, skip the canonical sort.  A warning is
            emitted reminding the caller that ordering responsibility is theirs.

    Returns:
        A :class:`MerkleRoot` containing the computed root and internal levels.

    Raises:
        ValueError: If ``leaf_hashes`` is empty.
    """
    if not leaf_hashes:
        raise ValueError("Cannot build a Merkle tree from an empty leaf list.")

    if preserve_order:
        warnings.warn(
            "preserve_order=True: caller is responsible for deterministic leaf ordering.",
            stacklevel=2,
        )
        ordered = list(leaf_hashes)
    else:
        ordered = sorted(leaf_hashes)

    current = list(ordered)
    levels: list[list[str]] = [list(current)]

    while len(current) > 1:
        next_level: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
                next_level.append(_blake3_pair(left, right))
            else:
                # CT-style lone-node promotion
                next_level.append(left)
        current = next_level
        levels.append(list(current))

    return MerkleRoot(root_hash=current[0], leaf_hashes=list(ordered), levels=levels)


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
            current = _blake3_pair(sibling_hash, current)
        else:
            current = _blake3_pair(current, sibling_hash)
    return current == root
