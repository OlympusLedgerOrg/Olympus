"""
Key credential endpoints (SBT-style, non-transferable).

POST   /key/credential       — issue a new credential anchored to the ledger
DELETE /key/credential/{id}  — revoke a credential
"""

from __future__ import annotations

import hmac as _hmac
import json
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import nacl.exceptions
import nacl.signing
from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select

from api.auth import (
    RateLimit,
    RequireAPIKey,
    _extract_key,
    _hash_key,
    is_dev_bypass_active,
    reload_keys,
)
from api.deps import DBSession
from api.models.api_key import ApiKey
from api.models.credential import KeyCredential
from api.models.credential_consent import CredentialConsent
from api.models.credential_event import CredentialLedgerEvent
from api.models.evm_pending_op import EvmPendingOp
from api.models.signing_key import AccountSigningKey, AccountWalletBinding
from api.models.user import User
from api.schemas.credential import (
    ConsentChallengeResponse,
    ConsentResponse,
    CredentialCreate,
    CredentialEventResponse,
    CredentialResponse,
    EvmFlushRequest,
    EvmFlushResponse,
    EvmMintQueueRequest,
    EvmMintQueueResponse,
)
from api.services.evm_batch import (
    check_submitted_ops,
    flush_pending_burns,
    flush_pending_mints,
    queue_mint,
)
from api.services.hasher import generate_commit_id
from protocol.canonical_json import canonical_json_encode
from protocol.hashes import hash_bytes as _hash_bytes
from protocol.log_sanitization import sanitize_for_log


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/key", tags=["keys"])
_MIN_ADMIN_KEY_BYTES = 32
_CREDENTIAL_BINDING_DOMAIN = "OLYMPUS:SBT_BINDING:V1"
_CREDENTIAL_CONSENT_DOMAIN = "OLYMPUS:CREDENTIAL_CONSENT:V1"
_SIGNING_KEY_BINDING_DOMAIN = "OLYMPUS:SIGNING_KEY_BINDING:V1"
_WALLET_BINDING_DOMAIN = "OLYMPUS:WALLET_BINDING:V1"
_WALLET_CHALLENGE_TTL_SECONDS = 10 * 60
_CONSENT_TTL_SECONDS = 24 * 60 * 60  # consent challenges expire after 24 h
_VALID_SIGNING_KEY_PURPOSES = {"dataset", "witness", "federation", "operator"}
# Shared vocabulary for Olympus-native burn_authorization and ERC-5484 BurnAuth mirror.
_VALID_BURN_AUTHORIZATIONS = {"issuer_only", "owner_only", "both", "neither"}
_VALID_ERC5484_BURN_AUTHORIZATIONS = _VALID_BURN_AUTHORIZATIONS  # alias kept for compat
_ETH_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def assert_admin_key_strength_for_environment() -> None:
    """Fail closed outside development when OLYMPUS_ADMIN_KEY is configured but weak."""
    env = os.environ.get("OLYMPUS_ENV", "production")
    if env == "development":
        return
    admin_key = os.environ.get("OLYMPUS_ADMIN_KEY", "")
    if admin_key and len(admin_key.encode("utf-8")) < _MIN_ADMIN_KEY_BYTES:
        raise RuntimeError(
            "Refusing startup with weak OLYMPUS_ADMIN_KEY outside development. "
            f"Configure at least {_MIN_ADMIN_KEY_BYTES} bytes."
        )


def _require_admin_scope(api_key: Any) -> None:
    """Require an admin-scoped API key for deployment/operator-only actions."""
    if "admin" not in api_key.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"detail": "API key lacks required scope: admin", "code": "AUTH_SCOPE"},
        )


def _dev_auth_bypass_active(api_key_id: str) -> bool:
    """Return True when running in dev mode with the synthetic 'dev' key identity.

    Holder-signature verification is skipped so developers can issue credentials
    without generating a real Ed25519 keypair.  Only active when
    OLYMPUS_ENV=development.
    """
    return os.environ.get("OLYMPUS_ENV") == "development" and api_key_id == "dev"


async def _require_db_account_for_api_key(request: Request, db: DBSession) -> tuple[Any, Any]:
    """Resolve the DB user and DB API key for account-bound key operations.

    In development mode with no keys configured AND no key present in the request
    the DB lookup is skipped and a lightweight sentinel is returned so the endpoint
    can proceed without a real account.  ``user.id`` will be ``None`` in that case,
    which is stored as a NULL ``holder_account_id`` (the column is nullable).

    When a real key IS provided (e.g., from user registration in tests), the DB
    lookup always runs regardless of dev bypass mode.
    """
    from types import SimpleNamespace

    # Peek at whether a key was provided without raising on absence.
    _has_key = bool(
        request.headers.get("x-api-key")
        or request.headers.get("authorization", "").lower().startswith("bearer ")
    )

    if not _has_key and is_dev_bypass_active():
        dev_user = SimpleNamespace(id=None)
        dev_key = SimpleNamespace(key_id="dev", key_hash="", user_id=None)
        return dev_user, dev_key

    raw_key = _extract_key(request)
    key_hash = _hash_key(raw_key)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.key_hash == key_hash)
        .where(ApiKey.revoked_at.is_(None))
        .where(ApiKey.expires_at > now)
    )
    key_record = result.scalars().first()
    if key_record is None:
        raise HTTPException(status_code=401, detail="DB-backed account API key required.")
    user_result = await db.execute(select(User).where(User.id == key_record.user_id))
    user = user_result.scalars().first()
    if user is None:
        raise HTTPException(status_code=401, detail="DB-backed account API key required.")
    return user, key_record


def signing_key_binding_payload(*, public_key: str, label: str, purpose: str) -> bytes:
    """Canonical bytes signed to prove possession before registering a public key."""
    payload = {
        "domain": _SIGNING_KEY_BINDING_DOMAIN,
        "public_key": public_key,
        "label": label,
        "purpose": purpose,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _naive_utc() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalize_eth_address(address: str) -> str:
    address = address.strip()
    if not _ETH_ADDRESS_RE.fullmatch(address):
        raise ValueError("wallet_address must be a 20-byte Ethereum address")
    return address.lower()


def wallet_binding_message(
    *,
    account_id: str,
    key_id: str,
    wallet_address: str,
    nonce: str,
    expires_at: datetime,
    burn_authorization: str,
) -> str:
    """Human-readable Ethereum challenge message for account/key wallet binding."""
    payload = {
        "domain": _WALLET_BINDING_DOMAIN,
        "erc_standard": "ERC-5484",
        "account_id": account_id,
        "key_id": key_id,
        "wallet_address": wallet_address,
        "nonce": nonce,
        "expires_at": expires_at.isoformat(),
        "purpose": "olympus-signing-key-wallet-binding",
        "consent": "Bind this wallet to the Olympus Ed25519 signing identity for SBT issuance.",
        "burn_authorization": burn_authorization,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _recover_eth_message_address(message: str, signature: str) -> str:
    """Recover the Ethereum address that signed an EIP-191 personal-sign message."""
    try:
        from eth_account import Account
        from eth_account.messages import encode_defunct
    except ImportError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "detail": "Ethereum wallet verification support is not installed.",
                "code": "ETH_ACCOUNT_UNAVAILABLE",
            },
        ) from exc

    signature_hex = signature[2:] if signature.startswith("0x") else signature
    try:
        raw_signature = bytes.fromhex(signature_hex)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail={"detail": "signature must be hex-encoded.", "code": "INVALID_SIGNATURE"},
        ) from None
    if len(raw_signature) != 65:
        raise HTTPException(
            status_code=422,
            detail={
                "detail": "signature must be a 65-byte Ethereum signature.",
                "code": "INVALID_SIGNATURE",
            },
        )

    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": "Invalid Ethereum wallet signature.",
                "code": "WALLET_SIGNATURE_INVALID",
            },
        ) from None
    return recovered.lower()  # type: ignore[no-any-return]


async def _require_active_owned_signing_key(
    *, key_id: str, request: Request, db: DBSession
) -> tuple[User, ApiKey, AccountSigningKey]:
    user, api_key = await _require_db_account_for_api_key(request, db)
    result = await db.execute(
        select(AccountSigningKey).where(
            AccountSigningKey.key_id == key_id,
            AccountSigningKey.user_id == user.id,
        )
    )
    record = result.scalars().first()
    if record is None:
        raise HTTPException(status_code=404, detail="Signing key not found.")
    if record.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Signing key has been revoked.")
    return user, api_key, record


def _verify_signing_key_possession(
    *, public_key: str, label: str, purpose: str, signature_hex: str | None
) -> None:
    if signature_hex is None:
        raise HTTPException(
            status_code=422,
            detail={
                "detail": "proof_signature is required to register a signing key.",
                "code": "SIGNING_KEY_SIGNATURE_REQUIRED",
            },
        )
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(public_key))
        verify_key.verify(
            signing_key_binding_payload(public_key=public_key, label=label, purpose=purpose),
            bytes.fromhex(signature_hex),
        )
    except (ValueError, nacl.exceptions.BadSignatureError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": "Invalid Ed25519 signing-key proof.",
                "code": "SIGNING_KEY_SIGNATURE_INVALID",
            },
        )


def credential_binding_payload(
    *,
    holder_key: str,
    credential_type: str,
    issuer: str,
    issued_by_key_id: str,
) -> bytes:
    """Canonical bytes for the legacy inline Ed25519 holder proof.

    Used only on the legacy CredentialCreate path (no consent_id).
    New integrations should use credential_consent_payload() instead.
    """
    payload = {
        "domain": _CREDENTIAL_BINDING_DOMAIN,
        "holder_key": holder_key,
        "credential_type": credential_type,
        "issuer": issuer,
        "issued_by_key_id": issued_by_key_id,
        "sbt_nontransferable": True,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def credential_consent_payload(
    *,
    user_id: str,
    signing_key_id: str,
    credential_type: str,
    issuer: str,
    burn_authorization: str,
    nonce: str,
    expires_at: datetime,
) -> str:
    """JCS/RFC 8785 canonical JSON the holder signs to grant Olympus-native consent.

    This is the authoritative consent artifact — chain-agnostic and independently
    verifiable from the DB record without trusting the API.  The exact bytes that
    were signed are stored in CredentialConsent.consent_payload so any verifier
    can re-check the Ed25519 signature without calling this function.

    Key-ordering is deterministic (JCS) so any language's compliant JCS library
    produces the same bytes from the same inputs.
    """
    payload = {
        "burn_authorization": burn_authorization,
        "credential_type": credential_type,
        "domain": _CREDENTIAL_CONSENT_DOMAIN,
        "expires_at": expires_at.replace(tzinfo=None).isoformat(),
        "issuer": issuer,
        "nonce": nonce,
        "signing_key_id": signing_key_id,
        "user_id": user_id,
    }
    return canonical_json_encode(payload)


def _verify_holder_possession(
    *,
    holder_key: str,
    signature_hex: str | None,
    credential_type: str,
    issuer: str,
    issued_by_key_id: str,
) -> None:
    """Require an Ed25519 proof that the credential recipient controls holder_key."""
    if signature_hex is None:
        raise HTTPException(
            status_code=422,
            detail={
                "detail": "holder_signature is required to issue a credential.",
                "code": "HOLDER_SIGNATURE_REQUIRED",
            },
        )
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(holder_key))
        verify_key.verify(
            credential_binding_payload(
                holder_key=holder_key,
                credential_type=credential_type,
                issuer=issuer,
                issued_by_key_id=issued_by_key_id,
            ),
            bytes.fromhex(signature_hex),
        )
    except (ValueError, nacl.exceptions.BadSignatureError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": "Invalid Ed25519 holder signature.",
                "code": "HOLDER_SIGNATURE_INVALID",
            },
        )


async def _require_active_consent(
    consent_id: str, user_id: str, db: DBSession
) -> CredentialConsent:
    """Load a signed, unexpired, unaccepted consent record owned by user_id."""
    result = await db.execute(
        select(CredentialConsent).where(
            CredentialConsent.id == consent_id,
            CredentialConsent.user_id == user_id,
        )
    )
    consent = result.scalars().first()
    if consent is None:
        raise HTTPException(status_code=404, detail="Consent record not found.")
    if consent.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Consent has been revoked.")
    if consent.accepted_at is not None:
        raise HTTPException(
            status_code=409, detail="Consent already used for an issued credential."
        )
    if consent.consent_signature is None:
        raise HTTPException(
            status_code=409,
            detail={
                "detail": "Consent challenge has not been signed yet.",
                "code": "CONSENT_PENDING_SIGNATURE",
            },
        )
    now = _naive_utc()
    if consent.expires_at <= now:
        raise HTTPException(status_code=400, detail="Consent challenge has expired.")
    return consent


@router.post("/credential", response_model=CredentialResponse, status_code=status.HTTP_201_CREATED)
async def issue_credential(
    body: CredentialCreate,
    request: Request,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> CredentialResponse:
    """Issue an Olympus-native non-transferable credential.

    Two paths:

    **Preferred (consent-based):** supply ``consent_id`` referencing an accepted
    ``CredentialConsent`` (created via POST /key/signing/{key_id}/consent/challenge
    then POST /key/signing/{key_id}/consent/{id}/accept).  No ``holder_key`` or
    ``holder_signature`` needed; all parameters come from the verified consent record.

    **Legacy (inline):** supply ``holder_key``, ``issuer``, and ``holder_signature``
    (Ed25519 over ``credential_binding_payload``).  Retained for compatibility.

    In both cases the credential is:
      * account-bound  — tied to the authenticated DB account
      * signing-key-bound — holder_key is an Ed25519 public key
      * non-transferable by design — no transfer operation exists
      * anchored to the Olympus ledger — a ``CredentialLedgerEvent`` is created
        with the same commit_id as the credential itself

    No Ethereum wallet is required.  ERC-5484 on-chain mirroring is an
    independent optional step (POST /key/signing/{key_id}/wallet/challenge).
    """
    user, _api_key_record = await _require_db_account_for_api_key(request, db)

    consent: CredentialConsent | None = None

    if body.consent_id:
        # ── Olympus-native path ───────────────────────────────────────────────
        consent = await _require_active_consent(body.consent_id, user.id, db)
        # Resolve the Ed25519 public key from the consent's signing_key_id.
        sk_result = await db.execute(
            select(AccountSigningKey).where(
                AccountSigningKey.key_id == consent.signing_key_id,
                AccountSigningKey.user_id == user.id,
            )
        )
        signing_key = sk_result.scalars().first()
        if signing_key is None:
            raise HTTPException(
                status_code=404, detail="Signing key referenced by consent not found."
            )
        holder_key = signing_key.public_key
        credential_type = consent.credential_type
        issuer = consent.issuer
        burn_authorization = consent.burn_authorization

    else:
        # ── Legacy inline path ────────────────────────────────────────────────
        if not body.holder_key:
            raise HTTPException(
                status_code=422,
                detail={
                    "detail": "holder_key is required when consent_id is not provided.",
                    "code": "HOLDER_KEY_REQUIRED",
                },
            )
        if not body.issuer:
            raise HTTPException(
                status_code=422,
                detail={
                    "detail": "issuer is required when consent_id is not provided.",
                    "code": "ISSUER_REQUIRED",
                },
            )
        if body.burn_authorization not in _VALID_BURN_AUTHORIZATIONS:
            raise HTTPException(
                status_code=422,
                detail={
                    "detail": f"burn_authorization must be one of: {sorted(_VALID_BURN_AUTHORIZATIONS)}",
                    "code": "INVALID_BURN_AUTH",
                },
            )
        if not _dev_auth_bypass_active(api_key.key_id):
            _verify_holder_possession(
                holder_key=body.holder_key,
                signature_hex=body.holder_signature,
                credential_type=body.credential_type,
                issuer=body.issuer,
                issued_by_key_id=api_key.key_id,
            )
        holder_key = body.holder_key
        credential_type = body.credential_type
        issuer = body.issuer
        burn_authorization = body.burn_authorization

    commit_id = generate_commit_id()
    now = datetime.now(timezone.utc)
    cred = KeyCredential(
        holder_key=holder_key,
        holder_account_id=user.id,
        credential_type=credential_type,
        issuer=issuer,
        issued_at=now,
        sbt_nontransferable=True,
        burn_authorization=burn_authorization,
        commit_id=commit_id,
        issued_by_key_id=api_key.key_id,
        consent_id=consent.id if consent else None,
    )
    db.add(cred)
    await db.flush()  # populate cred.id before creating the event

    event = CredentialLedgerEvent(
        credential_id=cred.id,
        event_type="issued",
        ledger_commit_id=commit_id,
        created_at=now,
    )
    db.add(event)

    if consent is not None:
        consent.accepted_at = now

    await db.commit()
    await db.refresh(cred)
    logger.info(
        "Issued credential %s holder_account=%s burn_auth=%s consent=%s",
        sanitize_for_log(str(cred.id)),
        sanitize_for_log(user.id),
        sanitize_for_log(burn_authorization),
        sanitize_for_log(str(consent.id) if consent else "legacy"),
    )
    return cred  # type: ignore[return-value]


async def _compute_evm_status(credential_id: str, db: DBSession) -> str:
    """Return the EVM on-chain mirror status for a credential.

    Queries evm_pending_ops and maps the lifecycle state to one of:
        "none"     — no mint op, or every mint op was skipped
        "pending"  — mint queued / submitted; not yet on-chain
        "anchored" — mint confirmed and no confirmed burn
        "revoked"  — a burn has been confirmed on-chain
        "failed"   — the most recent mint attempt failed

    The check order is: confirmed burn → mint op state → none.
    """
    # A confirmed burn always wins regardless of mint state.
    burn_result = await db.execute(
        select(EvmPendingOp)
        .where(
            EvmPendingOp.credential_id == credential_id,
            EvmPendingOp.op_type == "burn",
            EvmPendingOp.status == "confirmed",
        )
        .limit(1)
    )
    if burn_result.scalar_one_or_none() is not None:
        return "revoked"

    # Most recent mint op determines the forward status.
    mint_result = await db.execute(
        select(EvmPendingOp)
        .where(
            EvmPendingOp.credential_id == credential_id,
            EvmPendingOp.op_type == "mint",
        )
        .order_by(EvmPendingOp.queued_at.desc())
        .limit(1)
    )
    mint_op = mint_result.scalar_one_or_none()
    if mint_op is None:
        return "none"

    if mint_op.status in ("pending", "submitted"):
        return "pending"
    if mint_op.status == "confirmed":
        return "anchored"
    if mint_op.status == "failed":
        return "failed"
    # "skipped" — treat as no on-chain presence
    return "none"


@router.get("/credential/{credential_id}", response_model=CredentialResponse)
async def get_credential(
    credential_id: str,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> CredentialResponse:
    """Fetch a single credential by ID, including its EVM on-chain mirror status.

    The ``evm_status`` field in the response reflects the current state of the
    optional ERC-5484 on-chain mirror as recorded in the Olympus queue table.
    It does NOT query the chain directly; chain state is advisory — the Olympus
    SMT inclusion proof is the authoritative verification mechanism.

    Status values:

    * ``none``     — no mint operation queued, or all mint ops were skipped
    * ``pending``  — a mint is queued or submitted but not yet confirmed on-chain
    * ``anchored`` — mint confirmed; no confirmed burn on record
    * ``revoked``  — a burn has been confirmed on-chain
    * ``failed``   — the most recent mint attempt failed (may be retried)
    """
    result = await db.execute(select(KeyCredential).where(KeyCredential.id == credential_id))
    cred = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Credential not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )

    evm_status = await _compute_evm_status(credential_id, db)

    # Build the response explicitly so model_validate does not attempt to read
    # `evm_status` from the ORM object (KeyCredential has no such column).
    return CredentialResponse(
        id=cred.id,
        holder_key=cred.holder_key,
        holder_account_id=cred.holder_account_id,
        credential_type=cred.credential_type,
        issued_at=cred.issued_at,
        revoked_at=cred.revoked_at,
        issuer=cred.issuer,
        burn_authorization=cred.burn_authorization,
        sbt_nontransferable=cred.sbt_nontransferable,
        commit_id=cred.commit_id,
        revocation_commit_id=cred.revocation_commit_id,
        consent_id=cred.consent_id,
        evm_status=evm_status,
    )


def _default_sbt_token_uri(credential_id: str) -> str:
    base = os.environ.get("OLYMPUS_BASE_URL", "http://localhost:8000").rstrip("/")
    return f"{base}/sbt/metadata/{credential_id}"


async def _latest_verified_wallet_for_credential(cred: KeyCredential, db: DBSession) -> str | None:
    """Return the latest verified wallet binding for this credential holder/key."""
    if not cred.holder_account_id:
        return None

    result = await db.execute(
        select(AccountWalletBinding)
        .join(AccountSigningKey, AccountWalletBinding.signing_key_id == AccountSigningKey.key_id)
        .where(
            AccountWalletBinding.user_id == cred.holder_account_id,
            AccountWalletBinding.verified_at.is_not(None),
            AccountWalletBinding.revoked_at.is_(None),
            AccountSigningKey.public_key == cred.holder_key,
            AccountSigningKey.revoked_at.is_(None),
        )
        .order_by(AccountWalletBinding.verified_at.desc())
        .limit(1)
    )
    binding = result.scalar_one_or_none()
    return binding.wallet_address if binding is not None else None


async def _reject_existing_active_mint(credential_id: str, db: DBSession) -> None:
    """Prevent duplicate queued/submitted/confirmed SBT mirror mints."""
    result = await db.execute(
        select(EvmPendingOp)
        .where(
            EvmPendingOp.credential_id == credential_id,
            EvmPendingOp.op_type == "mint",
            EvmPendingOp.status.in_(["pending", "submitted", "confirmed"]),
        )
        .order_by(EvmPendingOp.queued_at.desc())
        .limit(1)
    )
    existing = result.scalar_one_or_none()
    if existing is None:
        return

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "detail": f"EVM SBT mint already {existing.status} for this credential.",
            "code": "EVM_MINT_ALREADY_EXISTS",
            "op_id": existing.id,
            "evm_status": await _compute_evm_status(credential_id, db),
        },
    )


@router.post(
    "/credential/{credential_id}/evm/mint-queue",
    response_model=EvmMintQueueResponse,
    status_code=status.HTTP_201_CREATED,
)
async def queue_credential_evm_mint(
    credential_id: str,
    body: EvmMintQueueRequest,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> EvmMintQueueResponse:
    """Queue the optional ERC-5484 SBT mirror for an Olympus-native credential.

    The Olympus-native credential remains authoritative. This endpoint only
    queues a deployment/operator-controlled on-chain projection. It requires an
    admin-scoped API key because it can eventually spend gas through the EVM
    hot wallet when followed by ``POST /key/evm/flush``.
    """
    _require_admin_scope(api_key)

    result = await db.execute(select(KeyCredential).where(KeyCredential.id == credential_id))
    cred = result.scalar_one_or_none()
    if cred is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Credential not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )
    if cred.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": "Credential is revoked.", "code": "CREDENTIAL_REVOKED"},
        )

    await _reject_existing_active_mint(credential_id, db)

    wallet_address = body.wallet_address or await _latest_verified_wallet_for_credential(cred, db)
    if not wallet_address:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "detail": (
                    "No verified wallet binding found. Provide wallet_address explicitly "
                    "or complete the /key/signing/{key_id}/wallet challenge flow first."
                ),
                "code": "WALLET_BINDING_REQUIRED",
            },
        )

    contract_address = body.contract_address or os.environ.get("OLYMPUS_EVM_CONTRACT_ADDRESS", "")
    if not contract_address:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "detail": "OLYMPUS_EVM_CONTRACT_ADDRESS is required to queue an EVM SBT mint.",
                "code": "EVM_CONTRACT_NOT_CONFIGURED",
            },
        )

    op = await queue_mint(
        db=db,
        credential_id=cred.id,
        ledger_commit_id=cred.commit_id,
        wallet_address=wallet_address,
        burn_authorization=cred.burn_authorization,
        credential_type=cred.credential_type,
        holder_key_id=cred.holder_key,
        token_uri=body.token_uri or _default_sbt_token_uri(cred.id),
        chain_id=body.chain_id or int(os.environ.get("OLYMPUS_EVM_CHAIN_ID", "1")),
        contract_address=contract_address,
    )
    await db.flush()
    await db.commit()
    await db.refresh(op)

    flush_result = None
    if body.flush:
        flush_result = await flush_pending_mints(db)

    return EvmMintQueueResponse(
        credential_id=cred.id,
        evm_status=await _compute_evm_status(cred.id, db),
        op=op,  # type: ignore[arg-type]
        flush_result=flush_result,
    )


@router.post("/evm/flush", response_model=EvmFlushResponse)
async def flush_queued_evm_ops(
    body: EvmFlushRequest,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> EvmFlushResponse:
    """Flush queued optional ERC-5484 SBT mints/burns to the configured chain."""
    _require_admin_scope(api_key)

    reset_count = await check_submitted_ops(db) if body.reset_stale_submitted else 0
    burns = await flush_pending_burns(db, body.max_batch) if body.burns else None
    mints = await flush_pending_mints(db, body.max_batch) if body.mints else None
    return EvmFlushResponse(reset_submitted=reset_count, burns=burns, mints=mints)


@router.get(
    "/credential/{credential_id}/events",
    response_model=list[CredentialEventResponse],
)
async def list_credential_events(
    credential_id: str,
    db: DBSession,
    api_key: RequireAPIKey,
    _rl: RateLimit,
) -> list[CredentialEventResponse]:
    """List all ledger events for a credential (issued, revoked, etc.).

    Each event carries a ``ledger_commit_id`` that can be used to request an
    SMT inclusion proof, independently verifying that the event was recorded
    in the Olympus append-only ledger at the stated time.
    """
    result = await db.execute(
        select(CredentialLedgerEvent)
        .where(CredentialLedgerEvent.credential_id == credential_id)
        .order_by(CredentialLedgerEvent.created_at)
    )
    return result.scalars().all()  # type: ignore[return-value]


@router.delete("/credential/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_credential(
    credential_id: str, db: DBSession, api_key: RequireAPIKey, _rl: RateLimit
) -> None:
    """Revoke a credential by setting its revoked_at timestamp.

    The credential record is retained; Olympus is append-only.  A
    ``CredentialLedgerEvent`` with event_type="revoked" is created, anchoring
    the revocation to the ledger independently of the credential row itself.

    Only the API key that originally issued a credential may revoke it.
    Credentials without an ``issued_by_key_id`` can be revoked by any write-key holder.
    """
    result = await db.execute(select(KeyCredential).where(KeyCredential.id == credential_id))
    cred = result.scalars().first()
    # Return 404 (not 403) on ownership mismatch — avoids leaking credential existence.
    if not cred:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Credential not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )
    if cred.issued_by_key_id is not None and cred.issued_by_key_id != api_key.key_id:
        logger.warning(
            "Credential revocation rejected: key %s attempted to revoke credential issued by %s",
            sanitize_for_log(api_key.key_id),
            sanitize_for_log(cred.issued_by_key_id),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"detail": "Credential not found.", "code": "CREDENTIAL_NOT_FOUND"},
        )
    if cred.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"detail": "Credential already revoked.", "code": "ALREADY_REVOKED"},
        )

    revocation_commit_id = generate_commit_id()
    now = datetime.now(timezone.utc)
    cred.revoked_at = now
    cred.revocation_commit_id = revocation_commit_id

    event = CredentialLedgerEvent(
        credential_id=cred.id,
        event_type="revoked",
        ledger_commit_id=revocation_commit_id,
        created_at=now,
    )
    db.add(event)
    await db.commit()
    logger.info(
        "Revoked credential %s commit=%s",
        sanitize_for_log(str(credential_id)),
        sanitize_for_log(revocation_commit_id),
    )


# ── Olympus-native consent endpoints ─────────────────────────────────────────
# These allow holders to explicitly consent to a credential under stated terms
# using their Ed25519 signing key — no Ethereum wallet required.
#
# Flow:
#   POST /key/signing/{key_id}/consent/challenge  → get payload to sign
#   POST /key/signing/{key_id}/consent/{id}/accept → submit signature
#   POST /key/credential  (with consent_id)        → issue credential


class ConsentChallengeRequest(BaseModel):
    credential_type: str = ""
    issuer: str = ""
    burn_authorization: str = "issuer_only"

    @field_validator("burn_authorization")
    @classmethod
    def _check_burn_auth(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _VALID_BURN_AUTHORIZATIONS:
            raise ValueError(
                f"burn_authorization must be one of: {sorted(_VALID_BURN_AUTHORIZATIONS)}"
            )
        return normalized


class ConsentAcceptRequest(BaseModel):
    consent_signature: str

    @field_validator("consent_signature")
    @classmethod
    def _check_sig(cls, v: str) -> str:
        if not v or len(v) != 128:
            raise ValueError(
                "consent_signature must be 128 hex characters (64-byte Ed25519 signature)"
            )
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("consent_signature must be hex-encoded")
        return v.lower()


@router.post(
    "/signing/{key_id}/consent/challenge",
    response_model=ConsentChallengeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_consent_challenge(
    key_id: str,
    body: ConsentChallengeRequest,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> ConsentChallengeResponse:
    """Create an Olympus-native credential consent challenge.

    The server generates a nonce and builds the canonical JCS payload that the
    holder must sign with their Ed25519 private key.  No Ethereum wallet is needed.
    The challenge expires in 24 hours.

    After signing, POST the signature to
    ``/key/signing/{key_id}/consent/{consent_id}/accept``.
    """
    user, _key_record, signing_key = await _require_active_owned_signing_key(
        key_id=key_id, request=request, db=db
    )
    now = _naive_utc()
    nonce = secrets.token_hex(32)
    expires_at = now + timedelta(seconds=_CONSENT_TTL_SECONDS)

    payload_str = credential_consent_payload(
        user_id=user.id,
        signing_key_id=signing_key.key_id,
        credential_type=body.credential_type,
        issuer=body.issuer,
        burn_authorization=body.burn_authorization,
        nonce=nonce,
        expires_at=expires_at,
    )

    consent = CredentialConsent(
        user_id=user.id,
        signing_key_id=signing_key.key_id,
        credential_type=body.credential_type,
        issuer=body.issuer,
        burn_authorization=body.burn_authorization,
        consent_payload=payload_str,
        consent_signature=None,  # pending — set in /accept
        nonce=nonce,
        created_at=now,
        expires_at=expires_at,
    )
    db.add(consent)
    await db.commit()
    await db.refresh(consent)

    logger.info(
        "Created consent challenge %s for signing_key=%s cred_type=%s burn_auth=%s",
        sanitize_for_log(consent.id),
        sanitize_for_log(signing_key.key_id),
        sanitize_for_log(body.credential_type),
        sanitize_for_log(body.burn_authorization),
    )
    return ConsentChallengeResponse(
        consent_id=consent.id,
        signing_key_id=signing_key.key_id,
        credential_type=body.credential_type,
        issuer=body.issuer,
        burn_authorization=body.burn_authorization,
        nonce=nonce,
        consent_payload=payload_str,
        expires_at=expires_at.isoformat(),
    )


@router.post(
    "/signing/{key_id}/consent/{consent_id}/accept",
    response_model=ConsentResponse,
)
async def accept_consent_challenge(
    key_id: str,
    consent_id: str,
    body: ConsentAcceptRequest,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> ConsentResponse:
    """Submit the Ed25519 signature to finalise an Olympus-native consent challenge.

    The signature must be over the exact bytes of ``consent_payload`` as returned
    by the challenge endpoint.  Verifies Ed25519 possession of the signing key
    without involving any Ethereum wallet or EVM chain.

    After this endpoint returns, the ``consent_id`` can be passed to
    ``POST /key/credential`` to issue the credential.
    """
    user, _key_record, signing_key = await _require_active_owned_signing_key(
        key_id=key_id, request=request, db=db
    )
    result = await db.execute(
        select(CredentialConsent).where(
            CredentialConsent.id == consent_id,
            CredentialConsent.user_id == user.id,
            CredentialConsent.signing_key_id == signing_key.key_id,
        )
    )
    consent = result.scalars().first()
    if consent is None:
        raise HTTPException(status_code=404, detail="Consent challenge not found.")
    if consent.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Consent challenge has been revoked.")
    if consent.consent_signature is not None:
        raise HTTPException(status_code=409, detail="Consent challenge already signed.")
    now = _naive_utc()
    if consent.expires_at <= now:
        raise HTTPException(status_code=400, detail="Consent challenge has expired.")

    # Verify the Ed25519 signature over the stored JCS payload.
    try:
        verify_key = nacl.signing.VerifyKey(bytes.fromhex(signing_key.public_key))
        verify_key.verify(
            consent.consent_payload.encode("utf-8"),
            bytes.fromhex(body.consent_signature),
        )
    except (ValueError, nacl.exceptions.BadSignatureError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": "Invalid Ed25519 consent signature.",
                "code": "CONSENT_SIGNATURE_INVALID",
            },
        )

    consent.consent_signature = body.consent_signature
    await db.commit()
    await db.refresh(consent)

    logger.info(
        "Accepted consent %s for signing_key=%s cred_type=%s",
        sanitize_for_log(consent.id),
        sanitize_for_log(signing_key.key_id),
        sanitize_for_log(consent.credential_type),
    )
    return ConsentResponse(
        consent_id=consent.id,
        signing_key_id=consent.signing_key_id,
        credential_type=consent.credential_type,
        issuer=consent.issuer,
        burn_authorization=consent.burn_authorization,
        created_at=consent.created_at,
        expires_at=consent.expires_at,
        accepted_at=consent.accepted_at,
        revoked_at=consent.revoked_at,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Signing key management
# ─────────────────────────────────────────────────────────────────────────────

_VALID_SCOPES = {"read", "write", "ingest", "commit", "verify", "admin"}


class GenerateKeyRequest(BaseModel):
    name: str
    scopes: list[str] = ["ingest", "verify"]
    expires_at: str = "2099-01-01T00:00:00Z"

    @field_validator("scopes")
    @classmethod
    def _check_scopes(cls, v: list[str]) -> list[str]:
        unknown = set(v) - _VALID_SCOPES
        if unknown:
            raise ValueError(f"unknown scopes: {', '.join(sorted(unknown))}")
        return v

    @field_validator("expires_at")
    @classmethod
    def _check_expires(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("expires_at must be ISO 8601, e.g. 2027-01-01T00:00:00Z")
        return v


class GenerateKeyResponse(BaseModel):
    raw_key: str
    key_hash: str
    key_id: str
    scopes: list[str]
    expires_at: str
    env_entry: str


class SigningKeyRegisterRequest(BaseModel):
    public_key: str
    label: str = "default"
    purpose: str = "dataset"
    proof_signature: str | None = None

    @field_validator("public_key")
    @classmethod
    def _check_public_key(cls, v: str) -> str:
        try:
            raw = bytes.fromhex(v)
        except ValueError:
            raise ValueError("public_key must be hex-encoded") from None
        if len(raw) != 32:
            raise ValueError("public_key must be a 32-byte Ed25519 public key")
        return v.lower()

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 128:
            raise ValueError("label must be 1-128 characters")
        return v

    @field_validator("purpose")
    @classmethod
    def _check_purpose(cls, v: str) -> str:
        if v not in _VALID_SIGNING_KEY_PURPOSES:
            raise ValueError(
                f"purpose must be one of: {', '.join(sorted(_VALID_SIGNING_KEY_PURPOSES))}"
            )
        return v


class SigningKeyResponse(BaseModel):
    key_id: str
    user_id: str
    public_key: str
    label: str
    purpose: str
    created_at: str
    revoked_at: str | None = None
    replaced_by_key_id: str | None = None


class SigningKeyDevGenerateRequest(BaseModel):
    label: str = "dev-first-boot"
    purpose: str = "dataset"


class SigningKeyDevGenerateResponse(SigningKeyResponse):
    private_key: str


class WalletChallengeRequest(BaseModel):
    wallet_address: str
    burn_authorization: str = "issuer_only"

    @field_validator("wallet_address")
    @classmethod
    def _check_wallet_address(cls, v: str) -> str:
        return _normalize_eth_address(v)

    @field_validator("burn_authorization")
    @classmethod
    def _check_burn_authorization(cls, v: str) -> str:
        normalized = v.strip().lower()
        if normalized not in _VALID_ERC5484_BURN_AUTHORIZATIONS:
            allowed = ", ".join(sorted(_VALID_ERC5484_BURN_AUTHORIZATIONS))
            raise ValueError(f"burn_authorization must be one of: {allowed}")
        return normalized


class WalletChallengeResponse(BaseModel):
    challenge_id: str
    wallet_address: str
    key_id: str
    nonce: str
    message: str
    expires_at: str
    erc_standard: str = "ERC-5484"
    burn_authorization: str


class WalletVerifyRequest(BaseModel):
    challenge_id: str
    signature: str


class WalletBindingResponse(BaseModel):
    binding_id: str
    key_id: str
    wallet_address: str
    verified_at: str
    erc_standard: str = "ERC-5484"
    burn_authorization: str


def _signing_key_response(record: AccountSigningKey) -> SigningKeyResponse:
    return SigningKeyResponse(
        key_id=record.key_id,
        user_id=record.user_id,
        public_key=record.public_key,
        label=record.label,
        purpose=record.purpose,
        created_at=record.created_at.isoformat(),
        revoked_at=record.revoked_at.isoformat() if record.revoked_at else None,
        replaced_by_key_id=record.replaced_by_key_id,
    )


@router.post(
    "/signing",
    response_model=SigningKeyResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_signing_key(
    body: SigningKeyRegisterRequest,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> SigningKeyResponse:
    """Register an Ed25519 public signing key to the authenticated DB account."""
    user, _key_record = await _require_db_account_for_api_key(request, db)
    _verify_signing_key_possession(
        public_key=body.public_key,
        label=body.label,
        purpose=body.purpose,
        signature_hex=body.proof_signature,
    )

    existing = await db.execute(
        select(AccountSigningKey).where(AccountSigningKey.public_key == body.public_key)
    )
    existing_key = existing.scalars().first()
    if existing_key is not None:
        if existing_key.user_id != user.id:
            raise HTTPException(status_code=409, detail="Signing key already registered.")
        if existing_key.revoked_at is not None:
            raise HTTPException(status_code=409, detail="Signing key has been revoked.")
        return _signing_key_response(existing_key)

    record = AccountSigningKey(
        user_id=user.id,
        public_key=body.public_key,
        label=body.label,
        purpose=body.purpose,
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    logger.info(
        "Registered signing key %s for user=%s purpose=%s",
        sanitize_for_log(record.key_id),
        sanitize_for_log(user.id),
        sanitize_for_log(body.purpose),
    )
    return _signing_key_response(record)


@router.get("/signing", response_model=list[SigningKeyResponse])
async def list_signing_keys(
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> list[SigningKeyResponse]:
    user, _key_record = await _require_db_account_for_api_key(request, db)
    result = await db.execute(
        select(AccountSigningKey)
        .where(AccountSigningKey.user_id == user.id)
        .order_by(AccountSigningKey.created_at)
    )
    return [_signing_key_response(record) for record in result.scalars().all()]


@router.post(
    "/signing/{key_id}/wallet/challenge",
    response_model=WalletChallengeResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_wallet_binding_challenge(
    key_id: str,
    body: WalletChallengeRequest,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> WalletChallengeResponse:
    """[OPTIONAL] Create an EIP-191 challenge to bind an Ethereum wallet to a signing key.

    This is the first step of the optional ERC-5484 on-chain mirror flow.
    Olympus-native credentials do NOT require Ethereum — use the Ed25519 consent
    flow (/signing/{key_id}/consent/challenge) instead.

    The burn_authorization recorded here is passed verbatim to the OlympusCredential
    contract's mint() call by api/services/evm_mint.py.
    """
    user, _key_record, signing_key = await _require_active_owned_signing_key(
        key_id=key_id, request=request, db=db
    )
    now = _naive_utc()
    nonce = secrets.token_hex(32)
    expires_at = now + timedelta(seconds=_WALLET_CHALLENGE_TTL_SECONDS)
    message = wallet_binding_message(
        account_id=user.id,
        key_id=signing_key.key_id,
        wallet_address=body.wallet_address,
        nonce=nonce,
        expires_at=expires_at,
        burn_authorization=body.burn_authorization,
    )
    binding = AccountWalletBinding(
        user_id=user.id,
        signing_key_id=signing_key.key_id,
        wallet_address=body.wallet_address,
        nonce=nonce,
        challenge_message=message,
        erc_standard="ERC-5484",
        burn_authorization=body.burn_authorization,
        issued_at=now,
        expires_at=expires_at,
    )
    db.add(binding)
    await db.commit()
    await db.refresh(binding)
    logger.info(
        "Issued ERC-5484 wallet binding challenge %s for signing_key=%s wallet=%s",
        sanitize_for_log(binding.id),
        sanitize_for_log(signing_key.key_id),
        sanitize_for_log(body.wallet_address),
    )
    return WalletChallengeResponse(
        challenge_id=binding.id,
        wallet_address=binding.wallet_address,
        key_id=binding.signing_key_id,
        nonce=binding.nonce,
        message=binding.challenge_message,
        expires_at=binding.expires_at.isoformat(),
        burn_authorization=binding.burn_authorization,
    )


@router.post("/signing/{key_id}/wallet/verify", response_model=WalletBindingResponse)
async def verify_wallet_binding_challenge(  # noqa: D401 — [OPTIONAL] ERC-5484 mirror
    key_id: str,
    body: WalletVerifyRequest,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> WalletBindingResponse:
    """Verify Ethereum wallet control and record ERC-5484 issuance consent."""
    user, _key_record, signing_key = await _require_active_owned_signing_key(
        key_id=key_id, request=request, db=db
    )
    result = await db.execute(
        select(AccountWalletBinding).where(
            AccountWalletBinding.id == body.challenge_id,
            AccountWalletBinding.user_id == user.id,
            AccountWalletBinding.signing_key_id == signing_key.key_id,
        )
    )
    binding = result.scalars().first()
    if binding is None:
        raise HTTPException(status_code=404, detail="Wallet challenge not found.")
    if binding.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Wallet challenge has been revoked.")
    now = _naive_utc()
    if binding.expires_at <= now:
        raise HTTPException(status_code=400, detail="Wallet challenge has expired.")

    recovered = _recover_eth_message_address(binding.challenge_message, body.signature)
    if recovered != binding.wallet_address:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "detail": "Wallet signature does not match challenge address.",
                "code": "WALLET_MISMATCH",
            },
        )

    binding.verified_at = now
    await db.commit()
    await db.refresh(binding)
    logger.info(
        "Verified ERC-5484 wallet binding %s for signing_key=%s wallet=%s",
        sanitize_for_log(binding.id),
        sanitize_for_log(signing_key.key_id),
        sanitize_for_log(binding.wallet_address),
    )
    return WalletBindingResponse(
        binding_id=binding.id,
        key_id=binding.signing_key_id,
        wallet_address=binding.wallet_address,
        verified_at=binding.verified_at.isoformat(),
        burn_authorization=binding.burn_authorization,
    )


@router.delete("/signing/{key_id}", response_model=SigningKeyResponse)
async def revoke_signing_key(
    key_id: str,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
    replaced_by_key_id: str | None = None,
) -> SigningKeyResponse:
    """Explicitly revoke an account signing key; rotation is not implicit."""
    user, api_key = await _require_db_account_for_api_key(request, db)
    result = await db.execute(
        select(AccountSigningKey).where(
            AccountSigningKey.key_id == key_id,
            AccountSigningKey.user_id == user.id,
        )
    )
    record = result.scalars().first()
    if record is None:
        raise HTTPException(status_code=404, detail="Signing key not found.")
    if record.revoked_at is not None:
        raise HTTPException(status_code=409, detail="Signing key already revoked.")
    if replaced_by_key_id is not None:
        replacement = await db.execute(
            select(AccountSigningKey.key_id).where(
                AccountSigningKey.key_id == replaced_by_key_id,
                AccountSigningKey.user_id == user.id,
                AccountSigningKey.revoked_at.is_(None),
            )
        )
        if replacement.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Replacement signing key not found.")
    record.revoked_at = datetime.now(timezone.utc)
    record.revoked_by_key_id = api_key.id
    record.replaced_by_key_id = replaced_by_key_id
    await db.commit()
    await db.refresh(record)
    logger.info(
        "Revoked signing key %s for user=%s replacement=%s",
        sanitize_for_log(record.key_id),
        sanitize_for_log(user.id),
        sanitize_for_log(replaced_by_key_id or ""),
    )
    return _signing_key_response(record)


@router.post(
    "/signing/dev-generate",
    response_model=SigningKeyDevGenerateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def dev_generate_signing_key(
    body: SigningKeyDevGenerateRequest,
    request: Request,
    db: DBSession,
    _api_key: RequireAPIKey,
    _rl: RateLimit,
) -> SigningKeyDevGenerateResponse:
    """Dev-only first-boot helper that returns private key material once."""
    if (
        os.environ.get("OLYMPUS_ENV", "production") != "development"
        or os.environ.get("OLYMPUS_ALLOW_DEV_SIGNING_KEY_BOOTSTRAP", "") != "1"
    ):
        raise HTTPException(status_code=404, detail="Not found.")
    user, _key_record = await _require_db_account_for_api_key(request, db)
    signing_key = nacl.signing.SigningKey.generate()
    public_key = bytes(signing_key.verify_key).hex()
    record = AccountSigningKey(
        user_id=user.id,
        public_key=public_key,
        label=body.label,
        purpose=body.purpose,
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    logger.warning(
        "Dev-generated signing key %s for user=%s; private key returned once only",
        sanitize_for_log(record.key_id),
        sanitize_for_log(user.id),
    )
    base = _signing_key_response(record)
    return SigningKeyDevGenerateResponse(
        **base.model_dump(),
        private_key=bytes(signing_key).hex(),
    )


@router.post(
    "/admin/generate", response_model=GenerateKeyResponse, status_code=status.HTTP_201_CREATED
)
async def admin_generate_key(
    request: Request, body: GenerateKeyRequest, _rl: RateLimit
) -> GenerateKeyResponse:
    """Generate a new API key and return the raw key + env-var JSON entry.

    Protected by ``X-Admin-Key``. The raw key is returned once — the caller
    must store it. The ``env_entry`` field is the JSON blob to add to
    ``OLYMPUS_API_KEYS_JSON`` in your .env file, then call reload-keys.
    """
    admin_key = os.environ.get("OLYMPUS_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin key not configured. Set OLYMPUS_ADMIN_KEY to enable.",
        )
    provided = request.headers.get("x-admin-key", "")
    if not _hmac.compare_digest(provided, admin_key):
        logger.warning(
            "Admin generate-key rejected from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid admin key.")

    logger.warning(
        "Using /key/admin/generate. Prefer admin-scoped API keys for routine operations."
    )

    raw_key = secrets.token_hex(32)
    key_hash = _hash_bytes(raw_key.encode()).hex()
    entry = {
        "key_hash": key_hash,
        "key_id": body.name,
        "scopes": body.scopes,
        "expires_at": body.expires_at,
    }
    logger.info(
        "Admin generated API key key_id=%s scopes=%s",
        sanitize_for_log(body.name),
        [sanitize_for_log(scope) for scope in body.scopes],
    )
    return GenerateKeyResponse(
        raw_key=raw_key,
        key_hash=key_hash,
        key_id=body.name,
        scopes=body.scopes,
        expires_at=body.expires_at,
        env_entry=json.dumps(entry),
    )


@router.post("/admin/reload-keys", status_code=status.HTTP_200_OK)
async def admin_reload_keys(request: Request, _rl: RateLimit) -> dict[str, object]:
    """Force a hot reload of FOIA API keys from the environment.

    Protected by a separate ``OLYMPUS_ADMIN_KEY`` secret.  This endpoint
    allows key rotation and revocation without restarting the API process.

    Raises:
        HTTPException 401: If the provided ``X-Admin-Key`` header is missing or wrong.
        HTTPException 503: If ``OLYMPUS_ADMIN_KEY`` is not configured on the server.
    """
    admin_key = os.environ.get("OLYMPUS_ADMIN_KEY", "")
    if not admin_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin key reload not configured. Set OLYMPUS_ADMIN_KEY to enable.",
        )
    provided = request.headers.get("x-admin-key", "")
    if not _hmac.compare_digest(provided, admin_key):
        logger.warning(
            "Admin key reload rejected from %s",
            request.client.host if request.client else "unknown",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key.",
        )
    count = reload_keys()
    logger.info("Admin-triggered key reload: %d key(s) now active", count)
    return {"reloaded": True, "key_count": count}
