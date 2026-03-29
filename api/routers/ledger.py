"""
Ledger state and proof endpoints.

GET  /ledger/state                — global state root
GET  /ledger/shard/{shard_id}     — per-shard state
GET  /ledger/proof/{commit_id}    — inclusion proof for a commit
GET  /ledger/activity             — human-readable activity feed
POST /ledger/ingest/simple        — user-friendly document ingestion
POST /ledger/verify/simple        — user-friendly document verification
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import func, select

from api.auth import RateLimit, RequireAPIKey
from api.config import get_settings
from api.deps import DBSession
from api.models.document import DocCommit
from api.models.ledger_activity import LedgerActivity
from api.schemas.ledger import (
    ActivityFeedResponse,
    ActivityItem,
    CommitSummary,
    LedgerStateResponse,
    ProofResponse,
    ShardStateResponse,
    SimpleIngestionResponse,
    SimpleVerificationResponse,
)
from api.services.ingestion import ingest_document
from api.services.merkle import MerkleProof, build_tree, generate_proof
from api.services.shard import compute_state_root
from api.services.upload_validation import validate_file_magic
from api.services.verification import verify_by_commit_id, verify_by_doc_hash, verify_by_file


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
    # Use aggregate queries instead of a full table scan to avoid OOM on large tables.
    total_result = await db.execute(select(func.count()).select_from(DocCommit))
    total_commits: int = total_result.scalar() or 0

    epoch_result = await db.execute(select(func.max(DocCommit.epoch_timestamp)))
    last_epoch = epoch_result.scalar()

    # Fetch distinct shard IDs with a bounded query.
    # Phase 0 deployments use a single shard; this limit is a safety guard
    # until a dedicated shard registry (Phase 1) replaces the full table scan.
    shard_result = await db.execute(
        select(DocCommit.shard_id).distinct().limit(1000)
    )
    shard_ids = [row[0] for row in shard_result.all()] or ["0x4F3A"]

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
    count_result = await db.execute(select(func.count()).where(DocCommit.shard_id == shard_id))
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
            tree = build_tree(all_hashes, preserve_order=True)
            proof: MerkleProof = generate_proof(commit.doc_hash, tree)
            merkle_proof_data = [{"hash": h, "direction": d} for h, d in proof.siblings]
        except ValueError:
            pass

    import os as _os

    _env = _os.getenv("OLYMPUS_ENV", "production")
    if _env == "development":
        from api.services.zkproof import generate_proof_stub

        zk_proof = generate_proof_stub(commit.commit_id, commit.doc_hash)
    else:
        zk_proof = {
            "protocol": "groth16",
            "curve": "bn128",
            "proof_type": "pending",
            "note": "ZK proof generation pending Groth16 trusted setup ceremony.",
            "verified": False,
        }

    return ProofResponse(
        commit_id=commit.commit_id,
        merkle_proof=merkle_proof_data,
        zk_proof=zk_proof,
        shard_id=commit.shard_id,
        epoch=commit.epoch_timestamp,
        proof_type=zk_proof.get("proof_type", "unknown"),
    )


# ── User-friendly endpoints ───────────────────────────────────────────────────


@router.get("/activity", response_model=ActivityFeedResponse)
async def get_ledger_activity(
    db: DBSession,
    _rl: RateLimit,
    limit: int = Query(50, ge=1, le=200),
    activity_type: str | None = Query(None),
) -> ActivityFeedResponse:
    """Return a human-readable feed of recent ledger events.

    Returns plain-English descriptions of what has been happening in the
    ledger — document submissions, verifications, and errors — suitable
    for display to non-technical users.

    Args:
        db: Injected async database session.
        limit: Maximum number of items to return (1–200, default 50).
        activity_type: Optional filter by activity type
            (e.g. ``"DOCUMENT_SUBMITTED"``, ``"VERIFICATION_SUCCESS"``).

    Returns:
        :class:`ActivityFeedResponse` with items ordered newest first.
    """
    query = select(LedgerActivity).order_by(LedgerActivity.timestamp.desc())
    if activity_type:
        query = query.where(LedgerActivity.activity_type == activity_type.upper())

    count_query = select(func.count()).select_from(LedgerActivity)
    if activity_type:
        count_query = count_query.where(LedgerActivity.activity_type == activity_type.upper())

    result = await db.execute(query.limit(limit))
    activities = list(result.scalars().all())

    count_result = await db.execute(count_query)
    total = count_result.scalar() or 0

    return ActivityFeedResponse(
        items=[
            ActivityItem(
                id=a.id,
                timestamp=a.timestamp,
                activity_type=a.activity_type,
                title=a.title,
                description=a.description,
                related_commit_id=a.related_commit_id,
                related_request_id=a.related_request_id,
                user_friendly_status=a.user_friendly_status,
            )
            for a in activities
        ],
        total=total,
    )


@router.post("/ingest/simple", response_model=SimpleIngestionResponse)
async def simple_document_ingest(
    request: Request,
    db: DBSession,
    _rl: RateLimit,
    _key: RequireAPIKey,
    file: UploadFile = File(...),
    request_id: str | None = Form(None),
    description: str | None = Form(None),
) -> SimpleIngestionResponse:
    """Upload a document to the ledger with guided step-by-step feedback.

    Accepts any common document format (PDF, Word, plain text, images) and
    returns a plain-English summary of each processing step so non-technical
    users understand exactly what happened.

    Args:
        request: Raw HTTP request (used to pre-check Content-Length).
        db: Injected async database session.
        file: The document to submit.
        request_id: Optional FOIA request ID to associate with this document.
        description: Optional short description of the document.

    Returns:
        :class:`SimpleIngestionResponse` with numbered steps and outcome.
    """
    settings = get_settings()
    max_mb = settings.max_upload_bytes // 1024 // 1024
    # Pre-check Content-Length to avoid reading oversized payloads into memory.
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > settings.max_upload_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum size of {max_mb} MB.",
                )
        except ValueError:
            pass  # malformed header — let the post-read check catch it

    file_bytes = await file.read()
    if len(file_bytes) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum size of {max_mb} MB.",
        )
    validate_file_magic(file_bytes, file.content_type or "application/octet-stream")
    return await ingest_document(
        file_bytes=file_bytes,
        filename=file.filename or "upload",
        content_type=file.content_type,
        request_id=request_id,
        description=description,
        db=db,
    )


@router.post("/verify/simple", response_model=SimpleVerificationResponse)
async def simple_document_verify(
    request: Request,
    db: DBSession,
    _rl: RateLimit,
    file: UploadFile | None = File(None),
    commit_id: str | None = Form(None),
    doc_hash: str | None = Form(None),
) -> SimpleVerificationResponse:
    """Verify whether a document is recorded in the ledger.

    Accepts three verification methods:

    1. **Upload file** — computes the fingerprint and checks the ledger.
    2. **Record ID** — looks up by permanent record ID (``OLY-NNNN``) or raw commit ID.
    3. **Document hash** — looks up directly by BLAKE3 hex hash.

    Returns a plain-English verdict with step-by-step proof details.

    Args:
        request: Raw HTTP request (used to pre-check Content-Length).
        db: Injected async database session.
        file: Optional uploaded file to verify by content.
        commit_id: Optional record ID or raw commit ID.
        doc_hash: Optional pre-computed BLAKE3 hex hash.

    Returns:
        :class:`SimpleVerificationResponse` with a clear verified/not-found verdict.

    Raises:
        HTTPException 400: If none of the three inputs are provided.
    """
    if file is not None and file.filename:
        settings = get_settings()
        max_mb = settings.max_upload_bytes // 1024 // 1024
        # Pre-check Content-Length before buffering the entire upload.
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > settings.max_upload_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File exceeds maximum size of {max_mb} MB.",
                    )
            except ValueError:
                pass  # malformed header — post-read check will catch it

        file_bytes = await file.read()
        if len(file_bytes) > settings.max_upload_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"File exceeds maximum size of {max_mb} MB.",
            )
        validate_file_magic(file_bytes, file.content_type or "application/octet-stream")
        return await verify_by_file(
            file_bytes=file_bytes,
            filename=file.filename,
            db=db,
        )

    if commit_id:
        return await verify_by_commit_id(commit_id=commit_id, db=db)

    if doc_hash:
        return await verify_by_doc_hash(doc_hash=doc_hash, db=db)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "detail": (
                "Please provide one of: a file to upload, a record ID (e.g. OLY-0123), "
                "or a document hash."
            ),
            "code": "MISSING_INPUT",
        },
    )
