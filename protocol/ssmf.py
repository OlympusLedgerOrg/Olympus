"""Sparse Sharded Merkle Forest implementation (Phase 0)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .hashes import leaf_hash, node_hash


@dataclass
class ProofNode:
    hash: bytes
    is_right: bool

    def to_hex(self) -> Tuple[str, bool]:
        return self.hash.hex(), self.is_right


@dataclass
class SparseMerkleProof:
    key: bytes
    leaf_hash: bytes
    siblings: List[ProofNode]
    exists: bool
    value_hash: Optional[bytes] = None

    def to_dict(self) -> dict:
        return {
            "key": self.key.hex(),
            "leaf_hash": self.leaf_hash.hex(),
            "siblings": [{"hash": h.hash.hex(), "is_right": h.is_right} for h in self.siblings],
            "exists": self.exists,
            "value_hash": self.value_hash.hex() if self.value_hash else None,
        }


class SparseMerkleTree:
    """256-height sparse Merkle tree with precomputed empty nodes."""

    def __init__(self, height: int = 256):
        self.height = height
        self.nodes: Dict[Tuple[int, int], bytes] = {}
        self.leaves: Dict[bytes, bytes] = {}
        self.empty_hashes = self._precompute_empty_hashes()

    def _precompute_empty_hashes(self) -> List[bytes]:
        empties = [leaf_hash(b"\x00" * 32, b"\x00" * 32)]
        for _ in range(self.height):
            empties.append(node_hash(empties[-1], empties[-1]))
        return empties

    def _index_for_key(self, key: bytes) -> int:
        if len(key) != 32:
            raise ValueError("Keys must be 32 bytes (already hashed)")
        return int.from_bytes(key, "big")

    def root(self) -> bytes:
        return self.nodes.get((self.height, 0), self.empty_hashes[self.height])

    def set(self, key: bytes, value_hash: bytes, version: Optional[str] = None) -> bytes:
        """Insert a leaf (append-only semantics: each key+version unique)."""
        index = self._index_for_key(key)
        leaf = leaf_hash(key, value_hash)
        self.leaves[key] = value_hash
        self.nodes[(0, index)] = leaf

        current = leaf
        for level in range(1, self.height + 1):
            sibling_index = index ^ 1
            sibling_hash = self.nodes.get((level - 1, sibling_index), self.empty_hashes[level - 1])

            if index % 2 == 0:
                parent = node_hash(current, sibling_hash)
            else:
                parent = node_hash(sibling_hash, current)

            index = index >> 1
            self.nodes[(level, index)] = parent
            current = parent

        return current

    def get(self, key: bytes, version: Optional[str] = None) -> Optional[bytes]:
        """Retrieve value hash for key."""
        return self.leaves.get(key)

    def _collect_siblings(self, key: bytes) -> List[ProofNode]:
        index = self._index_for_key(key)
        siblings: List[ProofNode] = []
        for level in range(self.height):
            sibling_index = index ^ 1
            sibling_hash = self.nodes.get((level, sibling_index), self.empty_hashes[level])
            siblings.append(ProofNode(hash=sibling_hash, is_right=(sibling_index % 2 == 1)))
            index >>= 1
        return siblings

    def prove_existence(self, key: bytes, version: Optional[str] = None) -> SparseMerkleProof:
        value_hash = self.get(key, version)
        if value_hash is None:
            raise ValueError("Key not found")
        leaf = leaf_hash(key, value_hash)
        siblings = self._collect_siblings(key)
        return SparseMerkleProof(key=key, leaf_hash=leaf, siblings=siblings, exists=True, value_hash=value_hash)

    def prove_nonexistence(self, key: bytes, version: Optional[str] = None) -> SparseMerkleProof:
        if key in self.leaves:
            raise ValueError("Key exists; cannot produce non-existence proof")
        leaf = self.empty_hashes[0]
        siblings = self._collect_siblings(key)
        return SparseMerkleProof(key=key, leaf_hash=leaf, siblings=siblings, exists=False, value_hash=None)


def verify_proof(root: bytes, key: bytes, proof: SparseMerkleProof, value_hash: Optional[bytes] = None) -> bool:
    """Verify existence or non-existence proof."""
    if proof.key != key:
        return False

    current = proof.leaf_hash
    if proof.exists:
        value = value_hash or proof.value_hash
        if value is None:
            return False
        expected_leaf = leaf_hash(key, value)
        if expected_leaf != proof.leaf_hash:
            return False

    index = int.from_bytes(key, "big")
    for sibling in proof.siblings:
        if index % 2 == 0:
            current = node_hash(current, sibling.hash)
        else:
            current = node_hash(sibling.hash, current)
        index >>= 1

    return current == root
