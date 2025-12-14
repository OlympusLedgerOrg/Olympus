"""
Merkle tree implementation for Olympus

This module implements Merkle trees and Merkle forests for efficient
cryptographic commitments and proof generation.
"""

from typing import List, Tuple, Optional
from dataclasses import dataclass
from .hashes import hash_bytes, merkle_parent_hash

# Merkle tree version - DO NOT CHANGE
# Changing this breaks all historical Merkle proofs
MERKLE_VERSION = "merkle_v1"


@dataclass
class MerkleNode:
    """A node in a Merkle tree."""
    hash: bytes
    left: Optional['MerkleNode'] = None
    right: Optional['MerkleNode'] = None


@dataclass
class MerkleProof:
    """A Merkle inclusion proof."""
    leaf_hash: bytes
    leaf_index: int
    siblings: List[Tuple[bytes, bool]]  # (hash, is_right_sibling)
    root_hash: bytes


class MerkleTree:
    """
    A Merkle tree for committing to a set of documents.
    """
    
    def __init__(self, leaves: List[bytes]):
        """
        Construct a Merkle tree from leaf hashes.
        
        Args:
            leaves: List of leaf hashes
        """
        if not leaves:
            raise ValueError("Cannot create empty Merkle tree")
        
        self.leaves = leaves
        self._root_node = self._build_tree(leaves)
    
    def _build_tree(self, hashes: List[bytes]) -> MerkleNode:
        """Build tree from bottom up."""
        if len(hashes) == 1:
            return MerkleNode(hash=hashes[0])
        
        # Build parent level
        parents = []
        for i in range(0, len(hashes), 2):
            left_hash = hashes[i]
            right_hash = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
            parent_hash = merkle_parent_hash(left_hash, right_hash)
            parents.append(parent_hash)
        
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
        
        leaf_hash = self.leaves[leaf_index]
        siblings = []
        
        # Collect siblings along path to root
        hashes = self.leaves[:]
        index = leaf_index
        
        while len(hashes) > 1:
            if index % 2 == 0:
                # Left child, sibling is on right
                sibling_index = index + 1 if index + 1 < len(hashes) else index
                siblings.append((hashes[sibling_index], True))
            else:
                # Right child, sibling is on left
                siblings.append((hashes[index - 1], False))
            
            # Move to parent level
            new_hashes = []
            for i in range(0, len(hashes), 2):
                left = hashes[i]
                right = hashes[i + 1] if i + 1 < len(hashes) else hashes[i]
                new_hashes.append(merkle_parent_hash(left, right))
            
            hashes = new_hashes
            index = index // 2
        
        return MerkleProof(
            leaf_hash=leaf_hash,
            leaf_index=leaf_index,
            siblings=siblings,
            root_hash=self._root_node.hash
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
        if is_right:
            current_hash = merkle_parent_hash(current_hash, sibling_hash)
        else:
            current_hash = merkle_parent_hash(sibling_hash, current_hash)
    
    return current_hash == proof.root_hash
