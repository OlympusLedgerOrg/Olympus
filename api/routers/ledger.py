"""
Ledger state and proof endpoints.

GET /ledger/state           — global state root
GET /ledger/shard/{shard_id} — per-shard state
GET /ledger/proof/{commit_id} — inclusion proof for a commit
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import func, select

from api.auth import RateLimit
from api.deps import DBSession
from api.models.document import DocCommit
from api.schemas.ledger import (
    CommitSummary,
    LedgerStateResponse,
    ProofResponse,
    ShardStateResponse,
)
from api.services.merkle import MerkleProof, build_tree, generate_proof
from api.services.shard import compute_state_root
from api.services.zkproof import generate_proof_stub


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/ledger", tags=["ledger"])


@router.get("/state", response_model=LedgerStateResponse)
async def get_ledger_state(db: DBSession, _rl: RateLimit):
    """Return the global ledger state.

    Aggregates the state roots of all shards (currently a single shard) and
    returns a summary including total commit count and the most recent epoch.

    Args:
        db: Injected async database session.

    Returns:
        Global state root, shard count, total commits, and last epoch.
    """
    result = await db.execute(select(DocCommit))
    commits = list(result.scalars().all())

    total_commits = len(commits)
    last_epoch = max((c.epoch_timestamp for c in commits), default=None)

    # Phase 0: single shard
    shard_ids = list({c.shard_id for c in commits}) or ["0x4F3A"]
    shard_roots: list[str] = []
    for sid in shard_ids:
        shard_roots.append(await compute_state_root(sid, db))

    if shard_roots and any(r != "0" * 64 for r in shard_roots):
        # Build a second-level tree over shard roots
        from api.services.merkle import build_tree as _bt  # noqa: PLC0415
        global_root = _bt([r for r in shard_roots if r != "0" * 64]).root_hash
    else:
        global_root = "0" * 64

    return LedgerStateResponse(
        global_state_root=global_root,
        shard_count=len(shard_ids),
        total_commits=total_commits,
        last_epoch=last_epoch,
    )


@router.get("/shard/{shard_id}", response_model=ShardStateResponse)
async def get_shard_state(shard_id: str, db: DBSession, _rl: RateLimit):
    """Return the state of a single shard.

    Args:
        shard_id: Hex shard identifier.
        db: Injected async database session.

    Returns:
        Shard state root, commit count, and latest commits.
    """
    result = await db.execute(
        select(DocCommit)
        .where(DocCommit.shard_id == shard_id)
        .order_by(DocCommit.epoch_timestamp.desc())
        .limit(10)
    )
    commits = list(result.scalars().all())

    state_root = await compute_state_root(shard_id, db)
    count_result = await db.execute(
        select(func.count()).where(DocCommit.shard_id == shard_id)
    )
    commit_count = count_result.scalar() or 0

    return ShardStateResponse(
        shard_id=shard_id,
        state_root=state_root,
        commit_count=commit_count,
        latest_commits=[
            CommitSummary(
                commit_id=c.commit_id,
                doc_hash=c.doc_hash,
                epoch=c.epoch_timestamp,
                shard_id=c.shard_id,
                merkle_root=c.merkle_root,
            )
            for c in commits
        ],
    )


@router.get("/proof/{commit_id}", response_model=ProofResponse)
async def get_commit_proof(commit_id: str, db: DBSession, _rl: RateLimit):
    """Return the Merkle inclusion proof and ZK proof stub for a commit.

    Args:
        commit_id: Hex commit identifier (e.g. ``"0xc7d4a2f8e1b3095d"``).
        db: Injected async database session.

    Returns:
        Merkle proof, ZK proof stub, shard, and epoch.

    Raises:
        HTTPException 404: If the commit is not found.
    """
    result = await db.execute(select(DocCommit).where(DocCommit.commit_id == commit_id))
    commit = result.scalars().first()
    if not commit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": f"Commit {commit_id!r} not found.", "code": "COMMIT_NOT_FOUND"},
        )

    all_result = await db.execute(
        select(DocCommit.doc_hash)
        .where(DocCommit.shard_id == commit.shard_id)
        .order_by(DocCommit.epoch_timestamp)
    )
    all_hashes = list(all_result.scalars().all())

    merkle_proof_data: list[dict] = []
    if all_hashes:
        try:
            tree = build_tree(all_hashes)
            proof: MerkleProof = generate_proof(commit.doc_hash, tree)
            merkle_proof_data = [{"hash": h, "direction": d} for h, d in proof.siblings]
        except ValueError:
            pass

    zk_proof = generate_proof_stub(commit.commit_id, commit.doc_hash)

    return ProofResponse(
        commit_id=commit.commit_id,
        merkle_proof=merkle_proof_data,
        zk_proof=zk_proof,
        shard_id=commit.shard_id,
        epoch=commit.epoch_timestamp,
    )
