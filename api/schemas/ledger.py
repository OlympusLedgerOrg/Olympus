"""
Pydantic v2 schemas for ledger endpoints.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class LedgerStateResponse(BaseModel):
    """Response for GET /ledger/state."""

    global_state_root: str
    shard_count: int
    total_commits: int
    last_epoch: datetime | None


class CommitSummary(BaseModel):
    """Compact commit summary used in shard listings."""

    commit_id: str
    doc_hash: str
    epoch: datetime
    shard_id: str
    merkle_root: str | None


class ShardStateResponse(BaseModel):
    """Response for GET /ledger/shard/{shard_id}."""

    shard_id: str
    state_root: str
    commit_count: int
    latest_commits: list[CommitSummary]


class ProofResponse(BaseModel):
    """Response for GET /ledger/proof/{commit_id}."""

    commit_id: str
    merkle_proof: list[dict]
    zk_proof: dict | None
    shard_id: str
    epoch: datetime
