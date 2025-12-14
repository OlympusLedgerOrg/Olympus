"""
Zero-knowledge redaction protocol for Olympus

This module implements the protocol for proving that a redacted document
is a faithful redaction of an original committed document.
"""

from typing import List, Set, Dict, Any
from dataclasses import dataclass
from .merkle import MerkleTree, MerkleProof, verify_proof
from .hashes import hash_bytes


@dataclass
class RedactionProof:
    """
    Proof that a redacted document is a valid redaction.
    """
    original_root: str  # Hex-encoded Merkle root of original
    revealed_indices: List[int]  # Indices of revealed leaves
    revealed_hashes: List[str]  # Hex-encoded hashes of revealed leaves
    merkle_proofs: List[MerkleProof]  # Inclusion proofs for each revealed leaf


class RedactionProtocol:
    """
    Protocol for creating and verifying redacted documents.
    """
    
    @staticmethod
    def create_leaf_hashes(document_parts: List[str]) -> List[bytes]:
        """
        Create leaf hashes from document parts.
        
        Args:
            document_parts: List of document parts (e.g., paragraphs, sentences)
            
        Returns:
            List of leaf hashes
        """
        return [hash_bytes(part.encode('utf-8')) for part in document_parts]
    
    @staticmethod
    def commit_document(document_parts: List[str]) -> tuple[MerkleTree, str]:
        """
        Commit to a document by creating its Merkle tree.
        
        Args:
            document_parts: List of document parts
            
        Returns:
            Tuple of (Merkle tree, hex-encoded root hash)
        """
        leaf_hashes = RedactionProtocol.create_leaf_hashes(document_parts)
        tree = MerkleTree(leaf_hashes)
        return tree, tree.get_root().hex()
    
    @staticmethod
    def create_redaction_proof(
        tree: MerkleTree,
        revealed_indices: List[int]
    ) -> RedactionProof:
        """
        Create a proof for a redacted version.
        
        Args:
            tree: Original document's Merkle tree
            revealed_indices: Indices of leaves to reveal
            
        Returns:
            Redaction proof
        """
        root_hash = tree.get_root().hex()
        revealed_hashes = [tree.leaves[i].hex() for i in revealed_indices]
        merkle_proofs = [tree.generate_proof(i) for i in revealed_indices]
        
        return RedactionProof(
            original_root=root_hash,
            revealed_indices=revealed_indices,
            revealed_hashes=revealed_hashes,
            merkle_proofs=merkle_proofs
        )
    
    @staticmethod
    def verify_redaction_proof(
        proof: RedactionProof,
        revealed_content: List[str]
    ) -> bool:
        """
        Verify a redaction proof.
        
        Args:
            proof: Redaction proof to verify
            revealed_content: The actual revealed content
            
        Returns:
            True if proof is valid
        """
        # Check that number of revealed items matches
        if len(proof.revealed_indices) != len(revealed_content):
            return False
        
        if len(proof.revealed_hashes) != len(revealed_content):
            return False
        
        if len(proof.merkle_proofs) != len(revealed_content):
            return False
        
        # Verify each revealed leaf
        for i, content in enumerate(revealed_content):
            # Check content hash matches
            content_hash = hash_bytes(content.encode('utf-8')).hex()
            if content_hash != proof.revealed_hashes[i]:
                return False
            
            # Verify Merkle proof
            merkle_proof = proof.merkle_proofs[i]
            if not verify_proof(merkle_proof):
                return False
            
            # Check proof root matches claimed original root
            if merkle_proof.root_hash.hex() != proof.original_root:
                return False
        
        return True
    
    @staticmethod
    def reconstruct_redacted_document(
        revealed_content: List[str],
        revealed_indices: List[int],
        total_parts: int,
        redaction_marker: str = "[REDACTED]"
    ) -> List[str]:
        """
        Reconstruct a redacted document with markers.
        
        Args:
            revealed_content: List of revealed parts
            revealed_indices: Indices of revealed parts
            total_parts: Total number of parts in original
            redaction_marker: Marker to use for redacted parts
            
        Returns:
            List representing full document with redactions
        """
        revealed_map = dict(zip(revealed_indices, revealed_content))
        
        result = []
        for i in range(total_parts):
            if i in revealed_map:
                result.append(revealed_map[i])
            else:
                result.append(redaction_marker)
        
        return result


def apply_redaction(original: str, mask: List[int], replacement: str = "█") -> str:
    """
    Apply a redaction mask to text.
    
    Semantics: 1 = redact, 0 = keep
    
    Args:
        original: Original text string
        mask: List of integers (0 or 1) indicating which characters to redact
        replacement: String to use for redacted characters
        
    Returns:
        Redacted text with replacement characters
    """
    if len(mask) != len(original):
        raise ValueError("Mask length must equal original text length")
    
    result = []
    for char, mask_bit in zip(original, mask):
        if mask_bit == 1:
            result.append(replacement)
        else:
            result.append(char)
    
    return ''.join(result)
