"""
Application state management for Olympus API

This module manages the in-memory state of shards and their sparse Merkle trees,
backed by a SQLite database for persistence.
"""

import sqlite3
from typing import Optional, Union
from protocol.ssmf import SparseMerkleTree, ExistenceProof, NonExistenceProof


class ShardState:
    """
    State for a single shard, wrapping a sparse Merkle tree.
    """
    
    def __init__(self, shard_id: str):
        """
        Initialize shard state.
        
        Args:
            shard_id: Unique identifier for this shard
        """
        self.shard_id = shard_id
        self.tree = SparseMerkleTree()
    
    def prove(self, key: bytes, version: Optional[str] = None) -> Union[ExistenceProof, NonExistenceProof]:
        """
        Generate a proof for a key (existence or non-existence).
        
        Args:
            key: 32-byte key to prove
            version: Optional version parameter (reserved for future use)
            
        Returns:
            ExistenceProof if key exists, NonExistenceProof otherwise
        """
        # Note: version parameter is reserved for future use
        # Currently, versioning is handled via record_key() in the key derivation
        return self.tree.prove(key)


class OlympusState:
    """
    Global state for Olympus API, managing multiple shards and database connection.
    """
    
    def __init__(self, db_path: str):
        """
        Initialize Olympus state.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.shards = {}
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema if needed."""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shards (
                shard_id TEXT PRIMARY KEY,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shard_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                shard_id TEXT NOT NULL,
                key BLOB NOT NULL,
                value_hash BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (shard_id) REFERENCES shards(shard_id)
            )
        """)
        self.conn.commit()
    
    def _shard(self, shard_id: str) -> ShardState:
        """
        Get or create a shard by ID.
        
        Args:
            shard_id: Shard identifier
            
        Returns:
            ShardState instance
        """
        if shard_id not in self.shards:
            self.shards[shard_id] = ShardState(shard_id)
        return self.shards[shard_id]
    
    def proof(self, shard_id: str, key: bytes, version: Optional[str] = None) -> Union[ExistenceProof, NonExistenceProof]:
        """
        Generate a proof for a key in a specific shard.
        
        Args:
            shard_id: Shard identifier
            key: 32-byte key to prove
            version: Optional version parameter
            
        Returns:
            ExistenceProof if key exists, NonExistenceProof otherwise
        """
        shard = self._shard(shard_id)
        return shard.prove(key, version)
