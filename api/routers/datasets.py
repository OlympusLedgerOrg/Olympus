"""
Dataset provenance endpoints (ADR-0010 v4).

POST /datasets/commit                     — commit a dataset manifest
GET  /datasets                            — list datasets (paginated)
GET  /datasets/{dataset_id}               — full detail for a dataset
GET  /datasets/{dataset_id}/verify        — independent verification
GET  /datasets/{dataset_id}/history       — version history
POST /datasets/{dataset_id}/lineage       — record model consumption
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

import nacl.exceptions
import nacl.signing
from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from api.auth import RateLimit, RequireAPIKey
from api.deps import DBSession
from api.models.credential import KeyCredential
from api.models.dataset import (
    DatasetArtifact,
    DatasetArtifactFile,
    DatasetLineageEvent,
)
from api.schemas.dataset import (
    DatasetCommitRequest,
    DatasetCommitResponse,
    DatasetDetailResponse,
    DatasetFileEntry,
    DatasetHistoryEntry,
    DatasetHistoryResponse,
    DatasetListResponse,
    DatasetVerifyResponse,
    LineageCommitRequest,
    LineageCommitResponse,
)
from api.services.merkle import MerkleProof, build_tree, generate_proof
from api.services.shard import DEFAULT_SHARD_ID, compute_state_root
from protocol.canonical_json import canonical_json_bytes
from protocol.hashes import (
    DATASET_LINEAGE_PREFIX,
    blake3_hash,
    compute_dataset_commit_id,
    dataset_key,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/datasets", tags=["datasets"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_manifest_dict(body: DatasetCommitRequest) -> dict:
    """Build the canonical manifest dict from the request body."""
    return {
        "dataset_name": body.dataset_name,
        "dataset_version": body.dataset_version,
        "source_uri": body.source_uri,
        "canonical_namespace": body.canonical_namespace,
        "granularity": body.granularity,
        "license_spdx": body.license_spdx,
        "license_uri": body.license_uri,
        "usage_restrictions": body.usage_restrictions,
        "file_format": body.file_format,
        "files": [f.model_dump() for f in body.files],
        "manifest_schema_version": body.manifest_schema_version,
    }


def _verify_signature(pubkey_hex: str, commit_id: str, signature_hex: str) -> bool:
    """Verify Ed25519 signature over commit_id bytes."""
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
        verify_key.verify(bytes.fromhex(commit_id), bytes.fromhex(signature_hex))
    except (nacl.exceptions.BadSignatureError, ValueError, Exception):
        return False
    return True


async def _check_key_not_revoked(db: "DBSession", pubkey_hex: str) -> None:
    """Cross-reference committer_pubkey against key_credentials (D12).

    If a credential exists for this pubkey and its ``revoked_at`` is in
    the past, reject the request with 403.
    """
    result = await db.execute(
        select(KeyCredential.revoked_at).where(
            KeyCredential.holder_key == pubkey_hex
        )
    )
    cred = result.scalars().first()
    if cred is not None and cred <= datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Committer key has been revoked.",
        )


def _is_key_revoked_at(revoked_at: datetime | None, reference: datetime) -> bool:
    """Return True if the key was revoked before ``reference``."""
    if revoked_at is None:
        return False
    return revoked_at <= reference


# ---------------------------------------------------------------------------
# POST /datasets/commit
# ---------------------------------------------------------------------------


@router.post(
    "/commit",
    response_model=DatasetCommitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def commit_dataset(
    body: DatasetCommitRequest,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> DatasetCommitResponse:
    """Anchor a dataset manifest to the Olympus ledger.

    Validates the caller's Ed25519 signature, computes deterministic hashes
    (content-only, no timestamp in identity), checks for replay via
    uniqueness constraint, requests an RFC 3161 timestamp, and persists
    the commitment record.
    """
    # 1. Validate parent references
    parent_commit_id = body.parent_commit_id or ""

    if body.parent_dataset_id is not None:
        result = await db.execute(
            select(DatasetArtifact.id).where(
                DatasetArtifact.dataset_id == body.parent_dataset_id
            )
        )
        if not result.scalars().first():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="parent_dataset_id not found.",
            )

    if parent_commit_id:
        result = await db.execute(
            select(DatasetArtifact.dataset_id).where(
                DatasetArtifact.commit_id == parent_commit_id
            )
        )
        parent_row = result.scalars().first()
        if parent_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="parent_commit_id not found.",
            )

    # 2. Canonical manifest → manifest_hash
    manifest_dict = _build_manifest_dict(body)
    manifest_bytes = canonical_json_bytes(manifest_dict)
    manifest_hash = blake3_hash([manifest_bytes]).hex()

    # 3. dataset_id (includes committer_pubkey to prevent cross-org collision)
    ds_id = dataset_key(
        body.dataset_name, body.source_uri,
        body.canonical_namespace, body.committer_pubkey,
    )

    # 4. commit_id (deterministic, content-only — no timestamp)
    commit_id = compute_dataset_commit_id(
        ds_id, parent_commit_id, manifest_hash, body.committer_pubkey,
    )

    # 5. Check replay: UNIQUE(dataset_id, parent_commit_id, manifest_hash)
    existing = await db.execute(
        select(DatasetArtifact.commit_id).where(
            DatasetArtifact.dataset_id == ds_id,
            DatasetArtifact.parent_commit_id == parent_commit_id,
            DatasetArtifact.manifest_hash == manifest_hash,
        )
    )
    existing_commit = existing.scalars().first()
    if existing_commit is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": "Duplicate commit: same content already committed.",
                "existing_commit_id": existing_commit,
            },
        )

    # 6. Verify Ed25519 signature
    if not _verify_signature(body.committer_pubkey, commit_id, body.commit_signature):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Ed25519 signature.",
        )

    # 7. Cross-reference committer key against key_credentials (D12)
    await _check_key_not_revoked(db, body.committer_pubkey)

    # 8. epoch_timestamp (set AFTER identity computation — not in hash)
    epoch_ts = datetime.now(timezone.utc)

    # 9. RFC 3161 timestamp with explicit status
    rfc3161_tst_hex: str | None = None
    rfc3161_tsa_url: str | None = None
    timestamp_status = "pending"
    try:
        from protocol.rfc3161 import DEFAULT_TSA_URL, request_timestamp

        token = request_timestamp(commit_id, DEFAULT_TSA_URL)
        rfc3161_tst_hex = token.tst_bytes.hex()
        rfc3161_tsa_url = token.tsa_url
        timestamp_status = "verified"
    except Exception:
        logger.warning(
            "RFC 3161 timestamp request failed; commit_id=%s status=pending",
            commit_id,
        )

    # 10. Compute totals from files
    total_bytes = sum(f.byte_size for f in body.files)
    total_records = sum(
        f.record_count for f in body.files if f.record_count is not None
    ) or None

    # 11. Build usage_restrictions JSON
    usage_json = json.dumps(body.usage_restrictions) if body.usage_restrictions else None

    shard_id = DEFAULT_SHARD_ID

    # 12. Create DatasetArtifact
    artifact = DatasetArtifact(
        dataset_id=ds_id,
        commit_id=commit_id,
        parent_commit_id=parent_commit_id,
        epoch_timestamp=epoch_ts,
        shard_id=shard_id,
        merkle_root=None,
        committer_pubkey=body.committer_pubkey,
        commit_signature=body.commit_signature,
        committer_label=body.committer_label,
        rfc3161_tst_hex=rfc3161_tst_hex,
        rfc3161_tsa_url=rfc3161_tsa_url,
        timestamp_status=timestamp_status,
        dataset_name=body.dataset_name,
        dataset_version=body.dataset_version,
        source_uri=body.source_uri,
        canonical_namespace=body.canonical_namespace,
        granularity=body.granularity,
        license_spdx=body.license_spdx,
        license_uri=body.license_uri,
        usage_restrictions=usage_json,
        manifest_hash=manifest_hash,
        manifest_schema_version=body.manifest_schema_version,
        canonicalization_method="canonical_json_v2",
        total_byte_size=total_bytes,
        total_record_count=total_records,
        file_count=len(body.files),
        file_format=body.file_format,
        parent_dataset_id=body.parent_dataset_id,
        transform_description=body.transform_description,
    )
    db.add(artifact)

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate commit: same content already committed.",
        )

    # 13. Child file rows
    for f in body.files:
        db.add(DatasetArtifactFile(
            artifact_id=artifact.id,
            path=f.path,
            content_hash=f.content_hash,
            byte_size=f.byte_size,
            record_count=f.record_count,
        ))
    await db.flush()

    # 14. Compute shard state root (deterministic ordering)
    new_root = await compute_state_root(shard_id, db)
    artifact.merkle_root = new_root

    await db.commit()
    await db.refresh(artifact)

    logger.info(
        "Dataset committed dataset_id=%s commit_id=%s timestamp_status=%s",
        ds_id, commit_id, timestamp_status,
    )

    return DatasetCommitResponse(
        dataset_id=artifact.dataset_id,
        commit_id=artifact.commit_id,
        manifest_hash=artifact.manifest_hash,
        epoch=artifact.epoch_timestamp,
        shard_id=artifact.shard_id,
        merkle_root=artifact.merkle_root,
        file_count=artifact.file_count,
        timestamp_status=artifact.timestamp_status,
        rfc3161_tsa_url=artifact.rfc3161_tsa_url,
    )


# ---------------------------------------------------------------------------
# GET /datasets
# ---------------------------------------------------------------------------


@router.get("", response_model=DatasetListResponse)
async def list_datasets(
    db: DBSession,
    _rl: RateLimit,
    license: str | None = Query(None),
    version: str | None = Query(None),
    source: str | None = Query(None),
    search: str | None = Query(None),
    namespace: str | None = Query(None),
    committer: str | None = Query(None),
    timestamp_status: str | None = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
) -> DatasetListResponse:
    """List datasets with optional filters and pagination."""
    q = select(DatasetArtifact)

    if license is not None:
        q = q.where(DatasetArtifact.license_spdx == license)
    if version is not None:
        q = q.where(DatasetArtifact.dataset_version == version)
    if source is not None:
        escaped = source.replace("%", r"\%").replace("_", r"\_")
        q = q.where(DatasetArtifact.source_uri.ilike(f"%{escaped}%"))
    if search is not None:
        escaped = search.replace("%", r"\%").replace("_", r"\_")
        q = q.where(DatasetArtifact.dataset_name.ilike(f"%{escaped}%"))
    if namespace is not None:
        q = q.where(DatasetArtifact.canonical_namespace == namespace)
    if committer is not None:
        q = q.where(DatasetArtifact.committer_pubkey == committer)
    if timestamp_status is not None:
        q = q.where(DatasetArtifact.timestamp_status == timestamp_status)

    # Total count
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar() or 0

    # Paginate
    q = q.order_by(DatasetArtifact.epoch_timestamp.desc())
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    rows = result.scalars().all()

    return DatasetListResponse(
        items=[
            DatasetCommitResponse(
                dataset_id=r.dataset_id,
                commit_id=r.commit_id,
                manifest_hash=r.manifest_hash,
                epoch=r.epoch_timestamp,
                shard_id=r.shard_id,
                merkle_root=r.merkle_root,
                file_count=r.file_count,
                timestamp_status=r.timestamp_status,
                rfc3161_tsa_url=r.rfc3161_tsa_url,
            )
            for r in rows
        ],
        page=page,
        per_page=per_page,
        total=total,
    )


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id}
# ---------------------------------------------------------------------------


@router.get("/{dataset_id}", response_model=DatasetDetailResponse)
async def get_dataset(
    dataset_id: str, db: DBSession, _rl: RateLimit,
) -> DatasetDetailResponse:
    """Return the latest commit for a logical dataset."""
    result = await db.execute(
        select(DatasetArtifact)
        .where(DatasetArtifact.dataset_id == dataset_id)
        .order_by(DatasetArtifact.epoch_timestamp.desc())
        .limit(1)
    )
    artifact = result.scalars().first()
    if artifact is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Dataset not found.",
        )

    # Load child files
    files_result = await db.execute(
        select(DatasetArtifactFile).where(
            DatasetArtifactFile.artifact_id == artifact.id
        )
    )
    files = files_result.scalars().all()

    return DatasetDetailResponse(
        dataset_id=artifact.dataset_id,
        commit_id=artifact.commit_id,
        manifest_hash=artifact.manifest_hash,
        epoch=artifact.epoch_timestamp,
        shard_id=artifact.shard_id,
        merkle_root=artifact.merkle_root,
        file_count=artifact.file_count,
        timestamp_status=artifact.timestamp_status,
        rfc3161_tsa_url=artifact.rfc3161_tsa_url,
        dataset_name=artifact.dataset_name,
        dataset_version=artifact.dataset_version,
        source_uri=artifact.source_uri,
        license_spdx=artifact.license_spdx,
        committer_pubkey=artifact.committer_pubkey,
        committer_label=artifact.committer_label,
        parent_commit_id=artifact.parent_commit_id,
        parent_dataset_id=artifact.parent_dataset_id,
        anchor_tx_hash=artifact.anchor_tx_hash,
        anchor_network=artifact.anchor_network,
        files=[
            DatasetFileEntry(
                path=f.path,
                content_hash=f.content_hash,
                byte_size=f.byte_size,
                record_count=f.record_count,
            )
            for f in files
        ],
        proof_bundle_uri=artifact.proof_bundle_uri,
    )


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id}/verify
# ---------------------------------------------------------------------------


@router.get("/{dataset_id}/verify", response_model=DatasetVerifyResponse)
async def verify_dataset(
    dataset_id: str, db: DBSession, _rl: RateLimit,
) -> DatasetVerifyResponse:
    """Run independent verification checks on a committed dataset.

    Checks:
      1. commit_id matches deterministic recomputation (no timestamp)
      2. Ed25519 signature is valid
      3. RFC 3161 timestamp status is "verified"
      4. Commit chain integrity
      5. Key revocation cross-reference
      6. Merkle inclusion proof
    """
    result = await db.execute(
        select(DatasetArtifact)
        .where(DatasetArtifact.dataset_id == dataset_id)
        .order_by(DatasetArtifact.epoch_timestamp.desc())
        .limit(1)
    )
    artifact = result.scalars().first()
    if artifact is None:
        return DatasetVerifyResponse(verified=False)

    checks: dict[str, bool] = {}

    # 1. Recompute commit_id (content-only — no timestamp)
    expected_commit_id = compute_dataset_commit_id(
        artifact.dataset_id,
        artifact.parent_commit_id,
        artifact.manifest_hash,
        artifact.committer_pubkey,
    )
    checks["commit_id_valid"] = expected_commit_id == artifact.commit_id

    # 2. Verify signature
    checks["signature_valid"] = _verify_signature(
        artifact.committer_pubkey, artifact.commit_id, artifact.commit_signature,
    )

    # 3. RFC 3161 status check
    rfc3161_valid: bool | None = None
    if artifact.timestamp_status == "verified" and artifact.rfc3161_tst_hex is not None:
        rfc3161_valid = True
        checks["rfc3161_valid"] = True
    elif artifact.timestamp_status == "pending":
        rfc3161_valid = False
        checks["rfc3161_valid"] = False
    else:
        rfc3161_valid = False
        checks["rfc3161_valid"] = False

    # 4. Chain integrity
    chain_valid = True
    current = artifact
    while current.parent_commit_id:
        parent_result = await db.execute(
            select(DatasetArtifact).where(
                DatasetArtifact.commit_id == current.parent_commit_id
            )
        )
        parent = parent_result.scalars().first()
        if parent is None:
            chain_valid = False
            break
        expected = compute_dataset_commit_id(
            parent.dataset_id, parent.parent_commit_id,
            parent.manifest_hash, parent.committer_pubkey,
        )
        if expected != parent.commit_id:
            chain_valid = False
            break
        current = parent
    checks["chain_valid"] = chain_valid

    # 5. Key revocation cross-reference (D12)
    key_revoked: bool | None = None
    cred_result = await db.execute(
        select(KeyCredential.revoked_at).where(
            KeyCredential.holder_key == artifact.committer_pubkey
        )
    )
    cred_revoked_at = cred_result.scalars().first()
    if cred_revoked_at is not None:
        key_revoked = _is_key_revoked_at(cred_revoked_at, artifact.epoch_timestamp)
    else:
        key_revoked = False
    checks["key_not_revoked"] = not key_revoked

    # 6. Merkle inclusion proof
    all_hashes_result = await db.execute(
        select(DatasetArtifact.manifest_hash)
        .where(DatasetArtifact.shard_id == artifact.shard_id)
        .order_by(DatasetArtifact.epoch_timestamp, DatasetArtifact.manifest_hash)
    )
    all_hashes = list(all_hashes_result.scalars().all())

    merkle_proof_data: list[dict] | None = None
    if all_hashes:
        try:
            tree = build_tree(all_hashes, preserve_order=True)
            proof: MerkleProof = generate_proof(artifact.manifest_hash, tree)
            merkle_proof_data = [
                {"hash": h, "direction": d} for h, d in proof.siblings
            ]
        except ValueError:
            pass

    verified = all(checks.values())

    return DatasetVerifyResponse(
        verified=verified,
        checks=checks,
        dataset=DatasetCommitResponse(
            dataset_id=artifact.dataset_id,
            commit_id=artifact.commit_id,
            manifest_hash=artifact.manifest_hash,
            epoch=artifact.epoch_timestamp,
            shard_id=artifact.shard_id,
            merkle_root=artifact.merkle_root,
            file_count=artifact.file_count,
            timestamp_status=artifact.timestamp_status,
            rfc3161_tsa_url=artifact.rfc3161_tsa_url,
        ),
        merkle_proof=merkle_proof_data,
        rfc3161_valid=rfc3161_valid,
        signature_valid=checks.get("signature_valid"),
        commit_id_valid=checks.get("commit_id_valid"),
        chain_valid=checks.get("chain_valid"),
        key_revoked=key_revoked,
    )


# ---------------------------------------------------------------------------
# GET /datasets/{dataset_id}/history
# ---------------------------------------------------------------------------


@router.get("/{dataset_id}/history", response_model=DatasetHistoryResponse)
async def dataset_history(
    dataset_id: str, db: DBSession, _rl: RateLimit,
) -> DatasetHistoryResponse:
    """Return ordered version history for a logical dataset."""
    result = await db.execute(
        select(DatasetArtifact)
        .where(DatasetArtifact.dataset_id == dataset_id)
        .order_by(DatasetArtifact.epoch_timestamp.asc())
    )
    rows = result.scalars().all()
    if not rows:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Dataset not found.",
        )

    return DatasetHistoryResponse(
        dataset_id=dataset_id,
        commits=[
            DatasetHistoryEntry(
                commit_id=r.commit_id,
                parent_commit_id=r.parent_commit_id,
                dataset_version=r.dataset_version,
                epoch=r.epoch_timestamp,
                committer_pubkey=r.committer_pubkey,
                committer_label=r.committer_label,
                manifest_hash=r.manifest_hash,
                file_count=r.file_count,
            )
            for r in rows
        ],
    )


# ---------------------------------------------------------------------------
# POST /datasets/{dataset_id}/lineage
# ---------------------------------------------------------------------------


@router.post(
    "/{dataset_id}/lineage",
    response_model=LineageCommitResponse,
    status_code=status.HTTP_201_CREATED,
)
async def commit_lineage(
    dataset_id: str,
    body: LineageCommitRequest,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> LineageCommitResponse:
    """Record that a model consumed this dataset."""
    # 1. Verify dataset exists
    result = await db.execute(
        select(DatasetArtifact.dataset_id).where(
            DatasetArtifact.dataset_id == dataset_id
        ).limit(1)
    )
    if not result.scalars().first():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset not found.",
        )

    # 2. Compute deterministic commit_id (content-only, no timestamp)
    # Find parent commit (latest commit for this dataset)
    latest_result = await db.execute(
        select(DatasetArtifact.commit_id)
        .where(DatasetArtifact.dataset_id == dataset_id)
        .order_by(DatasetArtifact.epoch_timestamp.desc())
        .limit(1)
    )
    parent_commit_id = latest_result.scalars().first() or ""

    payload = (
        f"{dataset_id}:{parent_commit_id}:{body.model_id}"
        f":{body.committer_pubkey}"
    )
    commit_id = blake3_hash([DATASET_LINEAGE_PREFIX, payload.encode()]).hex()

    # 3. Check uniqueness (dataset_id, model_id, event_type, committer_pubkey)
    existing = await db.execute(
        select(DatasetLineageEvent.commit_id).where(
            DatasetLineageEvent.dataset_id == dataset_id,
            DatasetLineageEvent.model_id == body.model_id,
            DatasetLineageEvent.event_type == body.event_type,
            DatasetLineageEvent.committer_pubkey == body.committer_pubkey,
        )
    )
    existing_commit = existing.scalars().first()
    if existing_commit is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": "Duplicate lineage event.",
                "existing_commit_id": existing_commit,
            },
        )

    # 4. Verify signature
    if not _verify_signature(body.committer_pubkey, commit_id, body.commit_signature):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid Ed25519 signature.",
        )

    # 5. Cross-reference key revocation
    await _check_key_not_revoked(db, body.committer_pubkey)

    epoch_ts = datetime.now(timezone.utc)
    shard_id = DEFAULT_SHARD_ID

    # 6. Create lineage event
    event = DatasetLineageEvent(
        dataset_id=dataset_id,
        commit_id=commit_id,
        parent_commit_id=parent_commit_id,
        epoch_timestamp=epoch_ts,
        shard_id=shard_id,
        committer_pubkey=body.committer_pubkey,
        commit_signature=body.commit_signature,
        timestamp_status="pending",
        model_id=body.model_id,
        model_version=body.model_version,
        model_org=body.model_org,
        event_type=body.event_type,
    )
    db.add(event)

    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate lineage event.",
        )

    new_root = await compute_state_root(shard_id, db)
    event.merkle_root = new_root

    await db.commit()

    return LineageCommitResponse(
        commit_id=event.commit_id,
        dataset_id=event.dataset_id,
        model_id=event.model_id,
        event_type=event.event_type,
        epoch=event.epoch_timestamp,
        timestamp_status=event.timestamp_status,
    )
