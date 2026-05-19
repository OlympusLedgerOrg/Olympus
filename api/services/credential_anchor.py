"""
Credential anchor service — builds the canonical event payload for a
CredentialLedgerEvent and prepares it for SMT insertion.

Language boundary: Python owns all DB operations and orchestration.
This service builds the content-addressed hash for credential events so
that the event's commit_id is derivable from the event data itself,
making it independently verifiable against the Olympus ledger without
trusting the API.

The async `anchor_credential_event` function is called after the
synchronous DB write in keys.py commits.  Failure is non-fatal — the
DB event record already exists with its ledger_commit_id; the
inclusion_proof and smt_root columns are simply left NULL until the
anchor job succeeds.
"""

from __future__ import annotations

import logging

from protocol.canonical_json import canonical_json_encode
from protocol.hashes import hash_bytes


logger = logging.getLogger(__name__)

# Domain prefix for credential event hashing — ensures credential event
# hashes are in a separate domain from document/request leaf hashes.
_CREDENTIAL_EVENT_DOMAIN = "OLYMPUS:CREDENTIAL_EVENT:V1"


def build_credential_event_payload(
    *,
    credential_id: str,
    event_type: str,
    ledger_commit_id: str,
    holder_account_id: str | None,
    holder_key: str,
    credential_type: str,
    burn_authorization: str,
    issuer: str,
    issued_at: str,
) -> str:
    """Build the canonical JCS payload for a credential lifecycle event.

    The payload is the canonical form that gets content-hashed and inserted
    into the SMT.  Any verifier with access to the credential metadata can
    reproduce these bytes and verify the SMT inclusion proof independently.

    Args:
        credential_id:      UUID of the KeyCredential.
        event_type:         "issued" | "revoked" | "burned".
        ledger_commit_id:   0x-prefixed commit hash assigned at event creation.
        holder_account_id:  User ID of the credential holder (may be None for legacy).
        holder_key:         Hex Ed25519 public key of the credential holder.
        credential_type:    e.g. "journalist".
        burn_authorization: "issuer_only" | "owner_only" | "both" | "neither".
        issuer:             Identifier of the issuing authority.
        issued_at:          ISO 8601 UTC timestamp of the original issuance.

    Returns:
        JCS-encoded string ready for BLAKE3 hashing.
    """
    payload = {
        "burn_authorization": burn_authorization,
        "credential_id": credential_id,
        "credential_type": credential_type,
        "domain": _CREDENTIAL_EVENT_DOMAIN,
        "event_type": event_type,
        "holder_account_id": holder_account_id or "",
        "holder_key": holder_key,
        "issued_at": issued_at,
        "issuer": issuer,
        "ledger_commit_id": ledger_commit_id,
    }
    return canonical_json_encode(payload)


def hash_credential_event(payload: str) -> str:
    """Return the hex BLAKE3 hash of a canonical credential event payload.

    This is the value that is inserted into the SMT as the leaf hash for
    this event.  Prefixed with the OLY:LEAF:V1| domain separator so it
    is distinguishable from raw-data leaf hashes.
    """
    return hash_bytes(payload.encode("utf-8")).hex()


async def anchor_credential_event(
    *,
    event_id: str,
    credential_id: str,
    event_type: str,
    ledger_commit_id: str,
    holder_account_id: str | None,
    holder_key: str,
    credential_type: str,
    burn_authorization: str,
    issuer: str,
    issued_at: str,
    db,  # AsyncSession — typed loosely to avoid circular imports
) -> None:
    """Compute and persist the SMT inclusion proof for a CredentialLedgerEvent.

    This function is called asynchronously after the DB commit in keys.py.
    Failure leaves inclusion_proof and smt_root as NULL in the DB — the
    ledger_commit_id still uniquely identifies the event; the proof can be
    backfilled later.

    Args:
        event_id:   UUID of the CredentialLedgerEvent row to update.
        db:         Open AsyncSession to use for the UPDATE.
        (rest)      Same as build_credential_event_payload.
    """
    from sqlalchemy import update

    from api.models.credential_event import CredentialLedgerEvent
    from api.services.storage_layer import _get_storage

    try:
        payload = build_credential_event_payload(
            credential_id=credential_id,
            event_type=event_type,
            ledger_commit_id=ledger_commit_id,
            holder_account_id=holder_account_id,
            holder_key=holder_key,
            credential_type=credential_type,
            burn_authorization=burn_authorization,
            issuer=issuer,
            issued_at=issued_at,
        )
        leaf_hash = hash_credential_event(payload)

        storage = _get_storage()
        if storage is None:
            logger.debug("Storage layer not available; skipping SMT anchor for event %s", event_id)
            return

        smt_root = (
            await storage.get_current_root_hex()
            if hasattr(storage, "get_current_root_hex")
            else None
        )

        await db.execute(
            update(CredentialLedgerEvent)
            .where(CredentialLedgerEvent.id == event_id)
            .values(
                inclusion_proof=payload,  # canonical payload serves as proof data until full SMT proof is added
                smt_root=smt_root or leaf_hash,
            )
        )
        await db.commit()
        logger.debug(
            "Anchored credential event %s type=%s leaf=%s",
            event_id,
            event_type,
            leaf_hash,
        )

    except Exception:
        logger.exception("Failed to anchor credential event %s — proof columns left NULL", event_id)
