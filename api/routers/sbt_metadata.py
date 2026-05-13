"""
SBT metadata endpoint — public ERC-721 compatible JSON for on-chain credential mirrors.

GET /sbt/metadata/{credential_id}

No authentication required.  Intended to be set as the tokenURI on the
OlympusCredential ERC-5484 contract so that OpenSea, wallets, and other ERC-721
tooling can display Olympus credential data.

The endpoint serves metadata for all credentials (including ones without an
on-chain mirror) because the URI may be stamped into the token at mint time
before the credential's revocation status is known.  A 404 is only returned
when the credential_id does not exist in the Olympus database.

Environment
-----------
OLYMPUS_BASE_URL       — public base URL for link generation (default: http://localhost:8000)
OLYMPUS_SBT_IMAGE_URI  — URI for the credential image shown by wallet UIs
                         (default: the Olympus shield SVG embedded at /sbt/image)
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy import select

from api.deps import DBSession
from api.models.credential import KeyCredential
from api.models.credential_event import CredentialLedgerEvent


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/sbt", tags=["sbt"])


def _base_url() -> str:
    return os.environ.get("OLYMPUS_BASE_URL", "http://localhost:8000").rstrip("/")


def _image_uri(credential_type: str) -> str:
    """Return the image URI to embed in the ERC-721 metadata.

    Callers can override via ``OLYMPUS_SBT_IMAGE_URI``; otherwise a stable
    per-type URL on the Olympus node itself is used so the image always
    resolves even without IPFS or Arweave.
    """
    override = os.environ.get("OLYMPUS_SBT_IMAGE_URI", "").strip()
    if override:
        return override
    return f"{_base_url()}/sbt/image/{credential_type}"


def _unix_ts(dt) -> int:
    """Convert a naive-UTC or tz-aware datetime to a Unix timestamp integer."""
    if dt is None:
        return 0
    if dt.tzinfo is None:
        from datetime import timezone as _tz

        dt = dt.replace(tzinfo=_tz.utc)
    return int(dt.timestamp())


@router.get(
    "/metadata/{credential_id}",
    summary="ERC-721 compatible metadata for an Olympus credential",
    response_class=JSONResponse,
    tags=["sbt"],
)
async def get_sbt_metadata(
    credential_id: str,
    db: DBSession,
) -> JSONResponse:
    """Return ERC-721 compatible JSON metadata for a credential.

    This endpoint is designed to be used as the on-chain ``tokenURI`` value
    for OlympusCredential ERC-5484 SBT tokens.  It may also be called directly
    by verifiers or wallets to inspect a credential without querying the chain.

    **Response shape** follows the OpenSea metadata standard so that SBT
    credentials appear correctly in all ERC-721-aware tooling:

    ```json
    {
      "name": "Olympus Credential — journalist",
      "description": "...",
      "image": "https://…",
      "external_url": "https://…/sbt/metadata/<id>",
      "attributes": [
        {"trait_type": "Credential Type",   "value": "journalist"},
        {"trait_type": "Issuer",            "value": "The Daily Tribune"},
        {"trait_type": "Status",            "value": "Active"},
        {"trait_type": "Burn Authorization","value": "issuer_only"},
        {"trait_type": "Issued At",         "display_type": "date", "value": 1735689600},
        {"trait_type": "Ledger Commit ID",  "value": "0x…"}
      ]
    }
    ```

    Returns 404 when the credential_id does not exist.  The response is **not**
    authenticated — treat the data as advisory; authoritative verification
    requires an SMT inclusion proof from ``GET /key/credential/{id}/events``.
    """
    result = await db.execute(select(KeyCredential).where(KeyCredential.id == credential_id))
    cred = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Credential not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )

    # Determine display status from Olympus-native fields (not EVM chain state).
    is_active = cred.revoked_at is None
    display_status = "Active" if is_active else "Revoked"

    # Pull the most recent evm_minted event for the on-chain commit reference.
    evm_event_result = await db.execute(
        select(CredentialLedgerEvent)
        .where(
            CredentialLedgerEvent.credential_id == credential_id,
            CredentialLedgerEvent.event_type == "evm_minted",
        )
        .order_by(CredentialLedgerEvent.created_at.desc())
        .limit(1)
    )
    evm_event = evm_event_result.scalar_one_or_none()

    credential_type = cred.credential_type or "credential"
    issuer = cred.issuer or "Unknown Issuer"
    burn_auth = cred.burn_authorization or "issuer_only"

    attributes: list[dict] = [
        {"trait_type": "Credential Type", "value": credential_type},
        {"trait_type": "Issuer", "value": issuer},
        {"trait_type": "Status", "value": display_status},
        {"trait_type": "Burn Authorization", "value": burn_auth},
        {
            "trait_type": "Issued At",
            "display_type": "date",
            "value": _unix_ts(cred.issued_at),
        },
        {"trait_type": "Ledger Commit ID", "value": cred.commit_id},
    ]

    if cred.revoked_at is not None:
        attributes.append(
            {
                "trait_type": "Revoked At",
                "display_type": "date",
                "value": _unix_ts(cred.revoked_at),
            }
        )

    if evm_event is not None:
        attributes.append(
            {
                "trait_type": "On-Chain Commit ID",
                "value": evm_event.ledger_commit_id,
            }
        )

    base = _base_url()
    metadata = {
        "name": f"Olympus Credential — {credential_type}",
        "description": (
            f"An Olympus-native non-transferable credential of type '{credential_type}' "
            f"issued by {issuer!r}.  Authoritative verification uses the Olympus Sparse "
            "Merkle Tree inclusion proof, not the ERC-5484 on-chain mirror."
        ),
        "image": _image_uri(credential_type),
        "external_url": f"{base}/sbt/metadata/{credential_id}",
        "attributes": attributes,
    }

    logger.debug("Served SBT metadata for credential %s", credential_id)
    # Return with explicit content-type so wallets that check the header are happy.
    return JSONResponse(
        content=metadata,
        headers={"Content-Type": "application/json; charset=utf-8"},
    )
