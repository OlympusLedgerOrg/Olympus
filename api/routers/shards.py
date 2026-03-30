"""
Protocol-layer shard, proof, and verification endpoints.

Provides read-only HTTP endpoints for third-party auditors to verify
records, proofs, signatures, and ledger integrity.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query

from api.auth import RateLimit, RequireAPIKey
from api.schemas.shards import (
    ExistenceProofResponse,
    HeaderVerificationResponse,
    LedgerEntryResponse,
    LedgerTailResponse,
    NonExistenceProofResponse,
    ShardHeaderResponse,
    ShardHistoryEntryResponse,
    ShardHistoryResponse,
    ShardInfo,
    StateRootDiffEntryResponse,
    StateRootDiffResponse,
    TimestampTokenResponse,
)
from api.services.storage_layer import _require_storage, db_op
from protocol.shards import canonical_header
from protocol.telemetry import opentelemetry_available, prometheus_available, record_smt_divergence


logger = logging.getLogger(__name__)
router = APIRouter(tags=["shards"])

# Shard IDs are alphanumeric strings with optional hyphens, colons, and dots.
# Maximum 128 characters.  This rejects path traversal, SQL injection, and
# other malformed inputs at the FastAPI validation layer (M5).
_SHARD_ID_RE = r"^[A-Za-z0-9:._-]{1,128}$"
_SHARD_ID_PATTERN = re.compile(_SHARD_ID_RE)
_SHARD_ID_PATH = Path(
    ...,
    description="Shard identifier (alphanumeric, hyphens, colons, dots; max 128 chars)",
    pattern=_SHARD_ID_RE,
)


@router.get("/shards", response_model=list[ShardInfo])
async def list_shards(_rl: RateLimit) -> list[ShardInfo]:
    """
    List all shards with their latest state.

    Returns:
        List of shard information
    """
    storage = _require_storage()
    with db_op("list shards"):
        shard_ids = storage.get_all_shard_ids()
        result = []

        for shard_id in shard_ids:
            header_data = storage.get_latest_header(shard_id)
            if header_data:
                result.append(
                    ShardInfo(
                        shard_id=shard_id,
                        latest_seq=header_data["seq"],
                        latest_root=header_data["header"]["root_hash"],
                    )
                )

        return result


@router.get("/shards/{shard_id}/header/latest", response_model=ShardHeaderResponse)
async def get_latest_header(
    shard_id: str = _SHARD_ID_PATH, *, _rl: RateLimit
) -> ShardHeaderResponse:
    """
    Get the latest shard header with signature.

    Includes everything needed for offline Ed25519 signature verification.

    Args:
        shard_id: Shard identifier

    Returns:
        Latest shard header with signature and canonical JSON
    """
    storage = _require_storage()
    with db_op("get header"):
        header_data = storage.get_latest_header(shard_id)

        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        header = header_data["header"]

        canonical_json = canonical_header(header).decode("utf-8")

        return ShardHeaderResponse(
            shard_id=header["shard_id"],
            seq=header_data["seq"],
            root_hash=header["root_hash"],
            tree_size=header["tree_size"],
            header_hash=header["header_hash"],
            previous_header_hash=header["previous_header_hash"],
            timestamp=header["timestamp"],
            signature=header_data["signature"],
            pubkey=header_data["pubkey"],
            canonical_header_json=canonical_json,
        )


@router.get("/shards/{shard_id}/proof")
async def get_proof(
    _rl: RateLimit,
    shard_id: str = _SHARD_ID_PATH,
    record_type: str = Query(..., description="Type of record (e.g., 'document')"),
    record_id: str = Query(..., description="Record identifier"),
    version: int = Query(..., description="Record version", ge=1),
) -> ExistenceProofResponse | NonExistenceProofResponse:
    """
    Get existence or non-existence proof for a record.

    Includes full 256-entry Merkle sibling path for offline verification.

    Args:
        shard_id: Shard identifier
        record_type: Type of record
        record_id: Record identifier
        version: Record version (must be >= 1)

    Returns:
        Existence proof if record exists, non-existence proof otherwise
    """
    storage = _require_storage()
    with db_op("get proof"):
        # Try to get existence proof
        proof = storage.get_proof(shard_id, record_type, record_id, version)

        # Get latest header
        header_data = storage.get_latest_header(shard_id)
        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        # Build header response
        header = header_data["header"]
        canonical_json = canonical_header(header).decode("utf-8")

        shard_header = ShardHeaderResponse(
            shard_id=header["shard_id"],
            seq=header_data["seq"],
            root_hash=header["root_hash"],
            tree_size=header["tree_size"],
            header_hash=header["header_hash"],
            previous_header_hash=header["previous_header_hash"],
            timestamp=header["timestamp"],
            signature=header_data["signature"],
            pubkey=header_data["pubkey"],
            canonical_header_json=canonical_json,
        )

        if proof is not None:
            # Record exists - return existence proof
            return ExistenceProofResponse(
                shard_id=shard_id,
                record_type=record_type,
                record_id=record_id,
                version=version,
                key=proof.key.hex(),
                value_hash=proof.value_hash.hex(),
                siblings=[s.hex() for s in proof.siblings],
                root_hash=proof.root_hash.hex(),
                shard_header=shard_header,
            )
        else:
            # Record doesn't exist - return non-existence proof
            non_proof = storage.get_nonexistence_proof(shard_id, record_type, record_id, version)
            return NonExistenceProofResponse(
                shard_id=shard_id,
                record_type=record_type,
                record_id=record_id,
                version=version,
                key=non_proof.key.hex(),
                siblings=[s.hex() for s in non_proof.siblings],
                root_hash=non_proof.root_hash.hex(),
                shard_header=shard_header,
            )


@router.get("/ledger/{shard_id}/tail", response_model=LedgerTailResponse)
async def get_ledger_tail(
    _rl: RateLimit,
    shard_id: str = _SHARD_ID_PATH,
    n: int = Query(10, description="Number of entries to retrieve", ge=1, le=1000),
) -> LedgerTailResponse:
    """
    Get the last N ledger entries for a shard.

    Entries are returned in reverse chronological order (most recent first).
    Use this to verify the ledger chain linkage.

    Args:
        shard_id: Shard identifier
        n: Number of entries to retrieve (1-1000, default 10)

    Returns:
        List of ledger entries
    """
    storage = _require_storage()
    with db_op("get ledger tail"):
        entries = storage.get_ledger_tail(shard_id, n)

        return LedgerTailResponse(
            shard_id=shard_id,
            entries=[
                LedgerEntryResponse(
                    ts=entry.ts,
                    record_hash=entry.record_hash,
                    shard_id=entry.shard_id,
                    shard_root=entry.shard_root,
                    canonicalization=entry.canonicalization,
                    prev_entry_hash=entry.prev_entry_hash,
                    entry_hash=entry.entry_hash,
                )
                for entry in entries
            ],
        )


@router.get("/shards/{shard_id}/history", response_model=ShardHistoryResponse)
async def get_shard_history(
    _rl: RateLimit,
    shard_id: str = _SHARD_ID_PATH,
    n: int = Query(10, description="Number of headers to retrieve", ge=1, le=1000),
) -> ShardHistoryResponse:
    """
    Get recent historical shard headers for a shard.

    Args:
        shard_id: Shard identifier
        n: Number of header snapshots to return

    Returns:
        Recent shard header snapshots in reverse chronological order
    """
    storage = _require_storage()
    with db_op("get shard history"):
        history = storage.get_header_history(shard_id, n)
        return ShardHistoryResponse(
            shard_id=shard_id,
            headers=[ShardHistoryEntryResponse(**entry) for entry in history],
        )


@router.get("/shards/{shard_id}/diff", response_model=StateRootDiffResponse)
async def get_shard_state_diff(
    _rl: RateLimit,
    shard_id: str = _SHARD_ID_PATH,
    from_seq: int = Query(..., description="Baseline shard header sequence", ge=0),
    to_seq: int = Query(..., description="Target shard header sequence", ge=0),
) -> StateRootDiffResponse:
    """
    Compare two historical shard states and return leaf-level differences.

    Args:
        shard_id: Shard identifier
        from_seq: Baseline shard header sequence
        to_seq: Target shard header sequence

    Returns:
        Root hashes plus added, changed, and removed leaf keys
    """
    storage = _require_storage()
    with db_op("diff shard state"):
        try:
            diff = storage.get_root_diff(shard_id, from_seq, to_seq)
        except ValueError:
            raise HTTPException(
                status_code=404,
                detail="Shard header not found for the requested shard or sequence range",
            )
        return StateRootDiffResponse(
            shard_id=shard_id,
            from_seq=from_seq,
            to_seq=to_seq,
            from_root_hash=diff["from_root_hash"],
            to_root_hash=diff["to_root_hash"],
            added=[StateRootDiffEntryResponse(**entry) for entry in diff["added"]],
            changed=[StateRootDiffEntryResponse(**entry) for entry in diff["changed"]],
            removed=[StateRootDiffEntryResponse(**entry) for entry in diff["removed"]],
            summary={
                "added": len(diff["added"]),
                "changed": len(diff["changed"]),
                "removed": len(diff["removed"]),
            },
        )


@router.get("/shards/{shard_id}/header/latest/verify", response_model=HeaderVerificationResponse)
async def verify_latest_header(
    shard_id: str = _SHARD_ID_PATH, *, _rl: RateLimit
) -> HeaderVerificationResponse:
    """
    Verify the Ed25519 signature and RFC 3161 timestamp of the latest shard header.

    Returns both the signature validity and, if a timestamp token has been stored,
    the RFC 3161 token and whether it is cryptographically valid.

    Args:
        shard_id: Shard identifier.

    Returns:
        Verification result including signature status, timestamp token, and
        timestamp validity.
    """
    storage = _require_storage()
    with db_op("verify header"):
        header_data = storage.get_latest_header(shard_id)
        if header_data is None:
            raise HTTPException(status_code=404, detail=f"Shard not found: {shard_id}")

        header = header_data["header"]
        header_hash = header["header_hash"]
        signature = header_data["signature"]
        pubkey_hex = header_data["pubkey"]

        # Explicitly verify the header signature (don't rely on implicit validation)
        import nacl.signing

        from protocol.shards import verify_header

        try:
            verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
            signature_valid = verify_header(header, signature, verify_key)
        except Exception:
            signature_valid = False

        # Retrieve timestamp token if stored
        token_dict = storage.get_timestamp_token(shard_id, header_hash)
        timestamp_token: TimestampTokenResponse | None = None
        timestamp_valid: bool | None = None

        if token_dict is not None:
            timestamp_token = TimestampTokenResponse(
                tsa_url=token_dict["tsa_url"],
                tst_hex=token_dict["tst_hex"],
                hash_hex=token_dict["hash_hex"],
                timestamp=token_dict["timestamp"],
                tsa_cert_fingerprint=token_dict["tsa_cert_fingerprint"],
            )
            from protocol.rfc3161 import verify_timestamp_token

            try:
                timestamp_valid = verify_timestamp_token(
                    bytes.fromhex(token_dict["tst_hex"]),
                    token_dict["hash_hex"],
                )
            except Exception:
                timestamp_valid = False

        return HeaderVerificationResponse(
            shard_id=shard_id,
            header_hash=header_hash,
            signature_valid=signature_valid,
            timestamp_token=timestamp_token,
            timestamp_valid=timestamp_valid,
        )


@router.get("/metrics")
async def metrics(_api_key: RequireAPIKey, _rl: RateLimit) -> Any:
    """
    Prometheus metrics endpoint.

    Returns all registered Olympus metrics in Prometheus text exposition
    format (``Content-Type: text/plain; version=0.0.4``).

    Metrics exposed:
    - ``olympus_proof_generation_seconds`` — histogram of proof latency by operation.
    - ``olympus_ledger_height`` — current ledger height per shard.
    - ``olympus_smt_root_divergence_total`` — counter of SMT root divergence events.
    - ``olympus_ingest_operations_total`` — counter of ingest outcomes.

    Returns HTTP 503 if the ``prometheus-client`` library is not installed.
    """
    if not prometheus_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "prometheus-client is not installed. Install it with: pip install prometheus-client"
            ),
        )

    import prometheus_client
    from starlette.responses import Response

    data = prometheus_client.generate_latest()
    return Response(
        content=data,
        media_type=prometheus_client.CONTENT_TYPE_LATEST,
    )


@router.post("/shards/{shard_id}/alert/smt-divergence")
async def alert_smt_divergence(
    _api_key: RequireAPIKey,
    _rl: RateLimit,
    shard_id: str = _SHARD_ID_PATH,
    local_root: str = Query(..., description="Hex-encoded local SMT root"),
    remote_root: str = Query(..., description="Hex-encoded remote SMT root"),
    remote_node: str = Query(..., description="Remote node identifier (URL or node ID)"),
) -> dict[str, Any]:
    """
    Record an SMT root divergence event between this node and a remote peer.

    This endpoint is called by inter-node health-check processes when they
    detect that the SMT root for a shard differs between nodes.  It increments
    the ``olympus_smt_root_divergence_total`` Prometheus counter and emits a
    structured warning log so that alerting rules can fire.

    Args:
        shard_id:    The shard whose SMT root diverged.
        local_root:  Hex-encoded SMT root computed on this node.
        remote_root: Hex-encoded SMT root reported by the remote peer.
        remote_node: Identifier of the remote peer.

    Returns:
        Confirmation that the divergence event was recorded.
    """
    record_smt_divergence(
        shard_id=shard_id,
        local_root=local_root,
        remote_root=remote_root,
        remote_node=remote_node,
    )
    return {
        "recorded": True,
        "shard_id": shard_id,
        "local_root": local_root,
        "remote_root": remote_root,
        "remote_node": remote_node,
        "observability": {
            "opentelemetry": opentelemetry_available(),
            "prometheus": prometheus_available(),
        },
    }
