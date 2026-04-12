"""
Document commit and verify endpoints.

POST /doc/commit  — anchor a document hash to the ledger
POST /doc/verify  — verify a previously committed document hash
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import exists, select

from api.auth import RateLimit, RequireAPIKey
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
from protocol.log_sanitization import sanitize_for_log


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/doc", tags=["documents"])

_MERKLE_LEAF_LIMIT = 50_000


@router.post(
    "/commit",
    response_model=DocCommitResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_404_NOT_FOUND: {
            "description": "The request_id does not match any existing public records request."
        },
        status.HTTP_409_CONFLICT: {
            "description": "The doc_hash has already been committed to the ledger."
        },
    },
)
async def commit_document(
    body: DocCommitRequest, db: DBSession, _api_key: RequireAPIKey, _rl: RateLimit
):
    """Anchor a document hash to the Olympus ledger.

    Generates a unique commit identifier, assigns the commit to the default
    shard, rebuilds the shard Merkle tree, and persists the commit record.
    Olympus stores hashes only — the underlying document is never submitted.

    If the same ``doc_hash`` has already been committed, a ``409 Conflict``
    is returned with the existing commit details so the caller can reference
    the original record.

    Args:
        body: Commit request containing the BLAKE3 doc_hash.
        db: Injected async database session.

    Returns:
        Commit confirmation with commit_id, epoch, shard, and Merkle root.

    Raises:
        HTTPException 404: If request_id is provided but no matching public records request exists.
        HTTPException 409: If the doc_hash has already been committed.
    """
    if body.request_id is not None:
        result = await db.execute(
            select(exists().where(PublicRecordsRequest.id == body.request_id))
        )
        if not result.scalar():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "detail": f"Request {body.request_id!r} not found.",
                    "code": "REQUEST_NOT_FOUND",
                },
            )

    # Check for existing commit with the same doc_hash (idempotency).
    existing_result = await db.execute(
        select(DocCommit).where(DocCommit.doc_hash == body.doc_hash).limit(1)
    )
    existing = existing_result.scalars().first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": "This document hash has already been committed.",
                "code": "DUPLICATE_DOC_HASH",
                "existing_commit_id": existing.commit_id,
            },
        )

    commit_id = generate_commit_id()
    shard_id = DEFAULT_SHARD_ID

    # AUDIT(doc_hash provenance): doc_hash is client-provided via the
    # DocCommitRequest schema (validated as 64 lowercase hex chars).  The
    # /doc/commit endpoint is a *commitment* API — the server never sees the
    # underlying document, only its BLAKE3 fingerprint.  For records ingested
    # via /ingest/records, doc_hash (stored as content_hash) is computed
    # server-side from canonical_v2 bytes:
    #   canonicalize_document(content) → document_to_bytes() → hash_bytes()
    # Both paths feed into build_tree(preserve_order=True) via
    # compute_state_root(), so the Merkle tree anchor is only as strong as
    # the hash fed into it.  Client-submitted hashes are accepted on trust;
    # the ingest path enforces canonical computation.
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
    logger.info(
        "Committed doc_hash=%s as commit_id=%s",
        sanitize_for_log(body.doc_hash),
        sanitize_for_log(commit_id),
    )

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
            detail={
                "detail": "At least one of commit_id or doc_hash is required.",
                "code": "MISSING_LOOKUP_KEY",
            },
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

    # Enforce embargo: embargoed documents must not be visible before their release date
    if commit.embargo_until and commit.embargo_until > datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This document is under embargo and not yet publicly available.",
        )

    # Rebuild the Merkle tree for the shard and generate an inclusion proof
    all_hashes_result = await db.execute(
        select(DocCommit.doc_hash)
        .where(DocCommit.shard_id == commit.shard_id)
        .order_by(DocCommit.epoch_timestamp)
        .limit(_MERKLE_LEAF_LIMIT)
    )
    all_hashes = list(all_hashes_result.scalars().all())

    merkle_proof_data: list[dict] | None = None
    if all_hashes:
        try:
            tree = build_tree(all_hashes, preserve_order=True)
            proof: MerkleProof = generate_proof(commit.doc_hash, tree)
            merkle_proof_data = [{"hash": h, "direction": d} for h, d in proof.siblings]
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
