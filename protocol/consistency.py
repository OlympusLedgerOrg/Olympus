"""
Merkle consistency proof protocol for Olympus.

This module provides Certificate Transparency-style consistency proofs that
demonstrate a newer tree is an append-only extension of an older tree.
Consistency proofs allow observers to detect split-view logs by comparing
Signed Tree Heads (STHs) across epochs.

The core algorithms are implemented in protocol.merkle, and this module
provides the structured API defined in the Olympus protocol specification.
"""

from dataclasses import dataclass
from typing import Any

from .merkle import MerkleTree, generate_consistency_proof as _merkle_generate_proof
from .merkle import verify_consistency_proof as _merkle_verify_proof


@dataclass(frozen=True)
class ConsistencyProof:
    """
    Merkle consistency proof demonstrating append-only tree growth.

    A consistency proof contains a minimal set of subtree hashes (O(log n))
    that allows a verifier to reconstruct both the old and new tree roots,
    confirming that the newer tree is an append-only extension of the older tree.

    Attributes:
        old_tree_size: Number of leaves in the prior tree.
        new_tree_size: Number of leaves in the current tree (must be >= old_tree_size).
        proof_nodes: List of 32-byte subtree hashes forming the consistency proof.
    """

    old_tree_size: int
    new_tree_size: int
    proof_nodes: list[bytes]

    def __post_init__(self) -> None:
        """Validate consistency proof structure."""
        if self.old_tree_size < 0 or self.new_tree_size < 0:
            raise ValueError("Tree sizes must be non-negative")
        if self.old_tree_size > self.new_tree_size:
            raise ValueError("old_tree_size cannot exceed new_tree_size")
        if not isinstance(self.proof_nodes, list):
            raise ValueError("proof_nodes must be a list")
        for i, node in enumerate(self.proof_nodes):
            if not isinstance(node, bytes):
                raise ValueError(f"proof_nodes[{i}] must be bytes")
            if len(node) != 32:
                raise ValueError(f"proof_nodes[{i}] must be 32 bytes, got {len(node)}")

    def to_dict(self) -> dict[str, Any]:
        """Serialize the consistency proof to a dictionary."""
        return {
            "old_tree_size": self.old_tree_size,
            "new_tree_size": self.new_tree_size,
            "proof_nodes": [node.hex() for node in self.proof_nodes],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ConsistencyProof":
        """Deserialize a consistency proof from a dictionary."""
        return cls(
            old_tree_size=int(data["old_tree_size"]),
            new_tree_size=int(data["new_tree_size"]),
            proof_nodes=[bytes.fromhex(node) for node in data["proof_nodes"]],
        )


def generate_consistency_proof(
    old_tree_size: int,
    new_tree_size: int,
    tree: MerkleTree,
) -> ConsistencyProof:
    """
    Generate a Merkle consistency proof demonstrating that a tree of ``new_tree_size``
    leaves extends a prior tree of ``old_tree_size`` leaves.

    This implements RFC 6962 Certificate Transparency style consistency proofs.
    The proof contains a minimal set of subtree hashes (O(log n)) that allows
    the verifier to reconstruct both the old and new roots, confirming that
    the tree has grown in an append-only manner.

    Args:
        old_tree_size: Number of leaves in the prior tree.
        new_tree_size: Number of leaves in the current tree (must satisfy new_tree_size >= old_tree_size).
        tree: MerkleTree instance containing at least ``new_tree_size`` leaves.

    Returns:
        ConsistencyProof containing the proof nodes.

    Raises:
        ValueError: If sizes are invalid or tree has insufficient leaves.

    Example:
        >>> from protocol.hashes import hash_bytes
        >>> from protocol.merkle import MerkleTree, ct_merkle_root
        >>> leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
        >>> tree = MerkleTree(leaves)
        >>> proof = generate_consistency_proof(5, 10, tree)
        >>> old_root = ct_merkle_root(leaves[:5])
        >>> new_root = tree.get_root()
        >>> assert verify_consistency_proof(old_root, new_root, proof)
    """
    if old_tree_size < 0 or new_tree_size < 0:
        raise ValueError("Tree sizes must be non-negative")
    if old_tree_size > new_tree_size:
        raise ValueError("old_tree_size cannot exceed new_tree_size")
    if new_tree_size > len(tree.leaves):
        raise ValueError(
            f"Tree has {len(tree.leaves)} leaves but new_tree_size is {new_tree_size}"
        )

    # Use the internal Merkle leaf hashes (with LEAF_PREFIX applied)
    leaf_hashes = tree._leaf_hashes

    # Generate the proof using the merkle module implementation
    proof_nodes = _merkle_generate_proof(leaf_hashes, old_tree_size, new_tree_size)

    return ConsistencyProof(
        old_tree_size=old_tree_size,
        new_tree_size=new_tree_size,
        proof_nodes=proof_nodes,
    )


def verify_consistency_proof(
    old_root: bytes,
    new_root: bytes,
    proof: ConsistencyProof,
) -> bool:
    """
    Verify that ``new_root`` represents a Merkle tree that extends the tree with
    root ``old_root``.

    This implements RFC 6962 Certificate Transparency style consistency proof
    verification. The proof contains O(log n) subtree hashes that allow
    reconstruction of both the old and new tree roots.

    Args:
        old_root: Merkle root of the prior tree (size ``proof.old_tree_size``).
        new_root: Merkle root of the newer tree (size ``proof.new_tree_size``).
        proof: ConsistencyProof as produced by :func:`generate_consistency_proof`.

    Returns:
        True if the proof is valid and demonstrates append-only growth.

    Example:
        >>> from protocol.hashes import hash_bytes
        >>> from protocol.merkle import MerkleTree, ct_merkle_root
        >>> leaves = [hash_bytes(f"leaf-{i}".encode()) for i in range(10)]
        >>> tree = MerkleTree(leaves)
        >>> proof = generate_consistency_proof(5, 10, tree)
        >>> old_root = ct_merkle_root(leaves[:5])
        >>> new_root = tree.get_root()
        >>> verify_consistency_proof(old_root, new_root, proof)
        True
    """
    if not isinstance(old_root, bytes) or len(old_root) != 32:
        return False
    if not isinstance(new_root, bytes) or len(new_root) != 32:
        return False

    # Delegate to the merkle module implementation
    return _merkle_verify_proof(
        old_root,
        new_root,
        proof.proof_nodes,
        proof.old_tree_size,
        proof.new_tree_size,
    )
