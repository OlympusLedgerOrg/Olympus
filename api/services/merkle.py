"""
Binary Merkle-tree construction and inclusion-proof generation.

Uses BLAKE3 for internal nodes via ``protocol.hashes``, consistent with the
Olympus protocol layer.  Leaf hashes are sorted lexicographically before tree
construction to ensure global consistency across federation nodes, regardless
of ingestion order.  Callers that require positional ordering (e.g. append-only
log proofs) may pass ``preserve_order=True`` to bypass the sort.

Lone nodes at any level are duplicated and hashed (RFC 6962 / Bitcoin pattern)
to prevent batching-boundary attacks on the Merkle root.

Domain separation uses the canonical Olympus protocol prefixes:
  leaf node:     BLAKE3(OLY:LEAF:V1 || | || leaf_data)
  internal node: BLAKE3(OLY:NODE:V1 || | || left_hash || | || right_hash)
  self-pair:     BLAKE3(OLY:NODE:V1 || | || lone_hash || | || lone_hash)

These prefixes are shared with ``protocol/merkle.py`` so that proofs generated
by either layer are verifiable by both.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from protocol.hashes import (
    HASH_SEPARATOR,
    LEAF_PREFIX,
    NODE_PREFIX,
    blake3_hash as _blake3_hash,
)


# Domain separation prefixes re-exported from protocol.hashes for test access.
# These are the canonical prefixes used across the entire Olympus protocol.
_LEAF_PREFIX = LEAF_PREFIX
_INTERNAL_PREFIX = NODE_PREFIX
_SEP = HASH_SEPARATOR.encode("utf-8")


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
        tree_size: Number of leaves in the tree that produced this proof.
                   Used by the verifier for strict depth validation.  A value
                   of ``0`` disables depth checks (legacy compatibility).
    """

    leaf_hash: str
    root_hash: str
    siblings: list[tuple[str, str]] = field(default_factory=list)
    tree_size: int = 0


def _blake3_leaf(data: bytes) -> str:
    """Compute a domain-separated leaf hash: ``BLAKE3(OLY:LEAF:V1 || | || data)``."""
    return _blake3_hash([_LEAF_PREFIX, _SEP, data]).hex()


def _blake3_pair(left: str, right: str) -> str:
    """Compute a domain-separated internal node hash.

    ``BLAKE3(OLY:NODE:V1 || | || left_bytes || | || right_bytes)`` over hex-encoded inputs.
    """
    return _blake3_hash(
        [_INTERNAL_PREFIX, _SEP, bytes.fromhex(left), _SEP, bytes.fromhex(right)]
    ).hex()


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

    leaf_level = [_blake3_leaf(bytes.fromhex(h)) for h in ordered]
    current = list(leaf_level)
    levels: list[list[str]] = [list(current)]

    # Single-leaf tree: self-pair to ensure the root differs from the leaf
    # (prevents trivial root == leaf identity, consistent with duplicate-and-hash
    # behaviour for lone nodes at every level).
    if len(current) == 1:
        current = [_blake3_pair(current[0], current[0])]
        levels.append(list(current))

    while len(current) > 1:
        next_level: list[str] = []
        for i in range(0, len(current), 2):
            left = current[i]
            if i + 1 < len(current):
                right = current[i + 1]
                next_level.append(_blake3_pair(left, right))
            else:
                # Duplicate-and-hash: lone node is self-paired to prevent
                # batching-boundary root divergence (RFC 6962 / Bitcoin pattern).
                next_level.append(_blake3_pair(left, left))
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
    index = tree.leaf_hashes.index(leaf_hash)

    for level in tree.levels[:-1]:  # stop before the root level
        if index % 2 == 0:
            # Current node is left child; sibling is on the right
            sibling_index = index + 1
            if sibling_index < len(level):
                siblings.append((level[sibling_index], "right"))
            else:
                # Lone node — self-paired; sibling is itself
                siblings.append((level[index], "right"))
        else:
            # Current node is right child; sibling is on the left
            sibling_index = index - 1
            siblings.append((level[sibling_index], "left"))
        index //= 2

    return MerkleProof(
        leaf_hash=leaf_hash,
        root_hash=tree.root_hash,
        siblings=siblings,
        tree_size=len(tree.leaf_hashes),
    )


_VALID_DIRECTIONS = frozenset({"left", "right"})


def _expected_proof_depth(tree_size: int) -> int:
    """Return the expected number of siblings for a tree with *tree_size* leaves.

    With the self-pair policy (lone nodes are duplicated, not promoted) every
    leaf always has a sibling at every level, so the depth is deterministic:

    - 1 leaf  → 1 (the self-pair level)
    - n > 1   → ceil(log2(n))
    """
    if tree_size <= 1:
        return 1
    return (tree_size - 1).bit_length()


def verify_proof(leaf_hash: str, proof: MerkleProof, root: str) -> bool:
    """Verify a Merkle inclusion proof against a known root.

    Enforces:
    1. Sibling direction strings must be exactly ``"left"`` or ``"right"``.
    2. When ``proof.tree_size > 0``, the number of siblings must match the
       expected depth for the declared tree size.

    Args:
        leaf_hash: Hex-encoded leaf hash to verify.
        proof: A :class:`MerkleProof` containing the sibling path.
        root: Hex-encoded expected Merkle root.

    Returns:
        ``True`` if the proof is valid, ``False`` otherwise.

    Raises:
        ValueError: If sibling direction is invalid or proof depth does not
            match the declared ``tree_size``.
    """
    # Validate direction strings
    for _hash, direction in proof.siblings:
        if direction not in _VALID_DIRECTIONS:
            raise ValueError(
                f"Invalid sibling direction {direction!r} (must be exactly 'left' or 'right')"
            )

    # Strict depth validation when tree_size is known
    if proof.tree_size > 0:
        expected = _expected_proof_depth(proof.tree_size)
        actual = len(proof.siblings)
        if actual != expected:
            raise ValueError(
                f"Proof depth mismatch: got {actual} siblings but expected "
                f"{expected} for tree_size={proof.tree_size}"
            )

    current = leaf_hash
    for sibling_hash, direction in proof.siblings:
        if direction == "left":
            current = _blake3_pair(sibling_hash, current)
        else:
            current = _blake3_pair(current, sibling_hash)
    return current == root
