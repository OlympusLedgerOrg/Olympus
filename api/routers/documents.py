"""
Document commit and verify endpoints.

POST /doc/commit  — anchor a document hash to the ledger
POST /doc/verify  — verify a previously committed document hash
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from api.auth import RequireAPIKey, RateLimit
from api.deps import DBSession
from api.models.document import DocCommit
from api.models.request import PublicRecordsRequest
from api.schemas.document import (
    DocCommitRequest,
    DocCommitResponse,
    DocVerifyRequest,
    DocVerifyResponse,
)
from api.services.hasher import generate_commit_id
from api.services.merkle import MerkleProof, build_tree, generate_proof
from api.services.shard import DEFAULT_SHARD_ID, compute_state_root
from api.services.zkproof import generate_proof_stub


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/doc", tags=["documents"])


@router.post("/commit", response_model=DocCommitResponse, status_code=status.HTTP_201_CREATED)
async def commit_document(body: DocCommitRequest, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit):
    """Anchor a document hash to the Olympus ledger.

    Generates a unique commit identifier, assigns the commit to the default
    shard, rebuilds the shard Merkle tree, and persists the commit record.
    Olympus stores hashes only — the underlying document is never submitted.

    Args:
        body: Commit request containing the BLAKE3 doc_hash.
        db: Injected async database session.

    Returns:
        Commit confirmation with commit_id, epoch, shard, and Merkle root.
    """
    if body.request_id is not None:
        result = await db.execute(
            select(PublicRecordsRequest).where(PublicRecordsRequest.id == body.request_id)
        )
        if result.scalars().first() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"detail": f"Request {body.request_id!r} not found.", "code": "REQUEST_NOT_FOUND"},
            )

    commit_id = generate_commit_id()
    shard_id = DEFAULT_SHARD_ID

    commit = DocCommit(
        doc_hash=body.doc_hash,
        commit_id=commit_id,
        shard_id=shard_id,
        request_id=body.request_id,
        embargo_until=body.embargo_until,
        is_multi_recipient=body.is_multi_recipient,
        merkle_root=None,
    )
    db.add(commit)
    await db.flush()  # Assign PK and make visible to queries within this txn

    # Compute the root now that the new hash is in the session
    new_root = await compute_state_root(shard_id, db)
    commit.merkle_root = new_root

    await db.commit()
    await db.refresh(commit)

    logger.info("Committed doc_hash=%s as commit_id=%s", body.doc_hash, commit_id)

    return DocCommitResponse(
        commit_id=commit.commit_id,
        doc_hash=commit.doc_hash,
        epoch=commit.epoch_timestamp,
        shard_id=commit.shard_id,
        merkle_root=commit.merkle_root,
    )


@router.post("/verify", response_model=DocVerifyResponse)
async def verify_document(body: DocVerifyRequest, db: DBSession, _rl: RateLimit):
    """Verify a previously committed document hash.

    Looks up the commit by ``commit_id`` or ``doc_hash`` (at least one is
    required), regenerates the Merkle inclusion proof and ZK proof stub,
    and returns a verification result.

    Args:
        body: Verify request with at least one of commit_id or doc_hash.
        db: Injected async database session.

    Returns:
        Verification result with proof details.
    """
    if not body.commit_id and not body.doc_hash:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"detail": "At least one of commit_id or doc_hash is required.", "code": "MISSING_LOOKUP_KEY"},
        )

    q = select(DocCommit)
    if body.commit_id:
        q = q.where(DocCommit.commit_id == body.commit_id)
    else:
        q = q.where(DocCommit.doc_hash == body.doc_hash)

    result = await db.execute(q)
    commit = result.scalars().first()

    if not commit:
        return DocVerifyResponse(verified=False)

    # Rebuild the Merkle tree for the shard and generate an inclusion proof
    all_hashes_result = await db.execute(
        select(DocCommit.doc_hash)
        .where(DocCommit.shard_id == commit.shard_id)
        .order_by(DocCommit.epoch_timestamp)
    )
    all_hashes = list(all_hashes_result.scalars().all())

    merkle_proof_data: list[dict] | None = None
    if all_hashes:
        try:
            tree = build_tree(all_hashes)
            proof: MerkleProof = generate_proof(commit.doc_hash, tree)
            merkle_proof_data = [
                {"hash": h, "direction": d} for h, d in proof.siblings
            ]
        except ValueError:
            pass

    zk_proof = generate_proof_stub(commit.commit_id, commit.doc_hash)

    return DocVerifyResponse(
        verified=True,
        commit=DocCommitResponse(
            commit_id=commit.commit_id,
            doc_hash=commit.doc_hash,
            epoch=commit.epoch_timestamp,
            shard_id=commit.shard_id,
            merkle_root=commit.merkle_root,
        ),
        merkle_proof=merkle_proof_data,
        zk_proof=zk_proof,
    )
