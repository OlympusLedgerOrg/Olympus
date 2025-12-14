"""
Ledger protocol implementation for Olympus

This module implements the append-only ledger for recording document commitments.
"""

from typing import List, Optional, Dict, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from .hashes import hash_bytes, hash_string, HASH_SEPARATOR


@dataclass
class LedgerEntry:
    """An entry in the Olympus ledger."""
    timestamp: str  # ISO 8601 format
    document_hash: str  # Hex-encoded
    merkle_root: str  # Hex-encoded
    shard_id: str
    source_signature: str
    previous_hash: str  # Hex-encoded, empty string for genesis
    entry_hash: str  # Hex-encoded hash of this entry
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LedgerEntry':
        """Create from dictionary."""
        return cls(**data)


class Ledger:
    """
    Append-only ledger for Olympus.
    
    The ledger maintains a chain of entries where each entry includes
    a hash of the previous entry, creating a tamper-evident log.
    """
    
    def __init__(self):
        """Initialize an empty ledger."""
        self.entries: List[LedgerEntry] = []
    
    def append(
        self,
        document_hash: str,
        merkle_root: str,
        shard_id: str,
        source_signature: str
    ) -> LedgerEntry:
        """
        Append a new entry to the ledger.
        
        Args:
            document_hash: Hash of the document
            merkle_root: Root of Merkle tree
            shard_id: Identifier for the shard
            source_signature: Signature from source
            
        Returns:
            The newly created entry
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'
        previous_hash = self.entries[-1].entry_hash if self.entries else ""
        
        # Compute entry hash
        entry_data = f"{timestamp}{HASH_SEPARATOR}{document_hash}{HASH_SEPARATOR}{merkle_root}{HASH_SEPARATOR}{shard_id}{HASH_SEPARATOR}{source_signature}{HASH_SEPARATOR}{previous_hash}"
        entry_hash = hash_string(entry_data).hex()
        
        entry = LedgerEntry(
            timestamp=timestamp,
            document_hash=document_hash,
            merkle_root=merkle_root,
            shard_id=shard_id,
            source_signature=source_signature,
            previous_hash=previous_hash,
            entry_hash=entry_hash
        )
        
        self.entries.append(entry)
        return entry
    
    def get_entry(self, entry_hash: str) -> Optional[LedgerEntry]:
        """
        Retrieve an entry by its hash.
        
        Args:
            entry_hash: Hash of the entry to retrieve
            
        Returns:
            The entry if found, None otherwise
        """
        for entry in self.entries:
            if entry.entry_hash == entry_hash:
                return entry
        return None
    
    def verify_chain(self) -> bool:
        """
        Verify the integrity of the entire ledger chain.
        
        Returns:
            True if chain is valid
        """
        if not self.entries:
            return True
        
        # Check genesis entry
        if self.entries[0].previous_hash != "":
            return False
        
        # Check each entry
        for i, entry in enumerate(self.entries):
            # Verify entry hash
            entry_data = f"{entry.timestamp}{HASH_SEPARATOR}{entry.document_hash}{HASH_SEPARATOR}{entry.merkle_root}{HASH_SEPARATOR}{entry.shard_id}{HASH_SEPARATOR}{entry.source_signature}{HASH_SEPARATOR}{entry.previous_hash}"
            expected_hash = hash_string(entry_data).hex()
            if entry.entry_hash != expected_hash:
                return False
            
            # Verify chain linkage
            if i > 0:
                if entry.previous_hash != self.entries[i - 1].entry_hash:
                    return False
        
        return True
    
    def get_all_entries(self) -> List[LedgerEntry]:
        """Get all entries in the ledger."""
        return self.entries.copy()
