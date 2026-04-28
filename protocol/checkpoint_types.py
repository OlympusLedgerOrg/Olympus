"""Core checkpoint data types shared between protocol.checkpoints and protocol.checkpoint_forks.

This module is intentionally kept free of cross-module protocol imports so that
both ``protocol.checkpoints`` and ``protocol.checkpoint_forks`` can import from
here without creating an import cycle.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class SignedCheckpoint:
    """
    A signed commitment to the global ledger state at a specific point in time.

    Checkpoints serve as public witnesses to prevent split-view attacks where
    a malicious operator presents different histories to different auditors.
    """

    # Checkpoint sequence number (monotonically increasing)
    sequence: int

    # ISO 8601 timestamp when this checkpoint was created
    timestamp: str

    # Hex-encoded hash of the latest ledger entry at this checkpoint
    ledger_head_hash: str

    # Hex-encoded hash of the previous checkpoint (empty for genesis)
    previous_checkpoint_hash: str

    # Total number of ledger entries up to and including this checkpoint
    ledger_height: int

    # Optional shard-specific state commitments
    shard_roots: dict[str, str]  # shard_id -> root_hash

    # Merkle consistency proof linking to the previous checkpoint's ledger root
    consistency_proof: list[str]

    # Hex-encoded hash of the checkpoint payload (computed from above fields)
    checkpoint_hash: str

    # Federation quorum certificate binding federation signatures to this checkpoint
    federation_quorum_certificate: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedCheckpoint:
        """Create from dictionary."""
        return cls(
            sequence=data["sequence"],
            timestamp=data["timestamp"],
            ledger_head_hash=data["ledger_head_hash"],
            previous_checkpoint_hash=data["previous_checkpoint_hash"],
            ledger_height=data["ledger_height"],
            shard_roots=data.get("shard_roots", {}),
            consistency_proof=data.get("consistency_proof", []),
            checkpoint_hash=data["checkpoint_hash"],
            federation_quorum_certificate=data["federation_quorum_certificate"],
        )
