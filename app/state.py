"""
Application state management for Olympus API

Wires to existing protocol/ssmf.py. Implements unified proof that never raises on absence.
"""


from protocol.hashes import forest_root
from protocol.ssmf import ExistenceProof, NonExistenceProof, SparseMerkleTree


class ShardState:
    """State for a single shard, wrapping a sparse Merkle tree."""

    def __init__(self, shard_id: str):
        """
        Initialize shard state.

        Args:
            shard_id: Unique identifier for this shard
        """
        self.shard_id = shard_id
        self.tree = SparseMerkleTree()

    def prove(self, key: bytes, version: str | None = None) -> ExistenceProof | NonExistenceProof:
        """
        Generate a proof for a key (existence or non-existence).

        Unified proof MUST NOT raise on absence.

        Args:
            key: 32-byte key to prove
            version: Optional version parameter (reserved for future use, currently ignored)
                     Note: Versioning must be handled by caller via record_key() when constructing the key

        Returns:
            ExistenceProof if key exists, NonExistenceProof otherwise
        """
        # Version parameter is reserved for future use but currently ignored
        return self.tree.prove(key)


class OlympusState:
    """
    Global state for Olympus API, managing multiple shards.
    """

    def __init__(self, db_path: str = "/tmp/olympus.sqlite"):
        """
        Initialize Olympus state.

        Args:
            db_path: Path to database file (file-backed, NOT :memory:)
        """
        self.db_path = db_path
        self.shards: dict[str, ShardState] = {}

    def _shard(self, shard_id: str) -> ShardState:
        """
        Get or create a shard by ID.

        Creates shard on write/proof only.

        Args:
            shard_id: Shard identifier

        Returns:
            ShardState instance
        """
        if shard_id not in self.shards:
            self.shards[shard_id] = ShardState(shard_id)
        return self.shards[shard_id]

    def list_shards(self) -> list:
        """Get list of shard IDs."""
        return sorted(self.shards.keys())

    def header_latest(self, shard_id: str) -> dict | None:
        """
        Get latest header for a shard.

        Returns None if shard missing (do NOT create).

        Args:
            shard_id: Shard identifier

        Returns:
            Latest header dict if shard exists, None otherwise
        """
        # Do NOT create shard if it doesn't exist
        if shard_id not in self.shards:
            return None

        # For now, return a minimal header (headers not yet implemented)
        shard = self.shards[shard_id]
        return {
            "shard_id": shard_id,
            "root_hash": shard.tree.get_root().hex(),
        }

    def proof(self, shard_id: str, key: bytes, version: str | None = None) -> ExistenceProof | NonExistenceProof:
        """
        Generate a proof for a key in a specific shard.

        Unified proof — absence is NOT an error.

        Args:
            shard_id: Shard identifier
            key: 32-byte key to prove
            version: Optional version parameter

        Returns:
            ExistenceProof if key exists, NonExistenceProof otherwise
        """
        shard = self._shard(shard_id)
        return shard.prove(key, version)

    def roots(self) -> dict:
        """
        Get root hashes for all shards and global root.

        Returns:
            Dict with global_root and per-shard roots
        """
        shard_roots = {}
        for shard_id, shard in self.shards.items():
            shard_roots[shard_id] = shard.tree.get_root().hex()

        # Compute global root using forest_root over header hashes
        # For now, use shard roots as a proxy (in full impl, would use actual header hashes)
        header_hashes = [bytes.fromhex(root) for root in shard_roots.values()]

        if header_hashes:
            global_root = forest_root(header_hashes).hex()
        else:
            # Empty forest - use a zero hash
            global_root = (b'\x00' * 32).hex()

        return {
            "global_root": global_root,
            "shards": shard_roots
        }


