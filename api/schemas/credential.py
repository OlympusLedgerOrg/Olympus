"""
Pydantic v2 schemas for credential endpoints.

Olympus-native credentials are account-bound and signing-key-bound.  No
Ethereum wallet is required.  The burn_authorization field is a chain-agnostic
vocabulary shared with ERC-5484 so values can be passed directly to the
optional on-chain mirror without translation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, field_validator


# Valid burn_authorization values — mirrors IERC5484.BurnAuth enum ordering.
BURN_AUTH_VALUES = frozenset({"issuer_only", "owner_only", "both", "neither"})


# ── Consent ────────────────────────────────────────────────────────────────────


class ConsentRequest(BaseModel):
    """Request body for POST /key/signing/{key_id}/consent.

    The caller submits the Ed25519 signature that proves the holder controls
    signing_key_id and explicitly agrees to receive a credential under the
    stated burn_authorization.  No Ethereum wallet is involved.
    """

    credential_type: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    issuer: str = Field(..., min_length=1, max_length=500)
    burn_authorization: str = Field(
        "issuer_only",
        description=(
            "Who may burn this credential: issuer_only | owner_only | both | neither. "
            "Mirrors ERC-5484 BurnAuth for optional on-chain mirror compatibility."
        ),
    )
    # Hex Ed25519 signature over the JCS-encoded consent_payload.
    # The payload is built server-side and returned in the challenge response,
    # so the client signs exactly what the server will store.
    consent_signature: str = Field(
        ...,
        pattern=r"^[0-9a-f]{128}$",
        description="Hex Ed25519 signature proving holder controls the signing key.",
    )
    # Random nonce chosen by the server in the challenge step; echoed back here
    # so the server can match signature → challenge without a separate lookup.
    nonce: str = Field(..., min_length=32, max_length=64)


class ConsentChallengeResponse(BaseModel):
    """Returned by GET /key/signing/{key_id}/consent/challenge.

    The client must sign `consent_payload` with the Ed25519 private key
    corresponding to signing_key_id, then POST the signature to
    /key/signing/{key_id}/consent to complete the consent flow.
    """

    consent_id: str
    signing_key_id: str
    credential_type: str
    issuer: str
    burn_authorization: str
    nonce: str
    consent_payload: str  # JCS-encoded JSON the client must sign
    expires_at: str


class ConsentResponse(BaseModel):
    """Returned after a consent record is created or queried."""

    consent_id: str
    signing_key_id: str
    credential_type: str
    issuer: str
    burn_authorization: str
    created_at: datetime
    expires_at: datetime
    accepted_at: datetime | None = None
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}


# ── Credential ────────────────────────────────────────────────────────────────


class CredentialCreate(BaseModel):
    """Request body for POST /key/credential.

    Two paths are supported:

    1. Olympus-native (preferred): supply ``consent_id`` referencing an accepted
       ``CredentialConsent`` record.  The burn_authorization, holder_key, and
       issuer are taken from the consent record; the caller does not repeat them.

    2. Legacy inline: supply ``holder_key``, ``issuer``, and ``holder_signature``
       directly.  burn_authorization defaults to "issuer_only".  This path is
       retained for API compatibility and for the development bypass mode.
    """

    # ── Path 1: consent-based (preferred) ─────────────────────────────────────
    consent_id: str | None = Field(
        None,
        description="UUID of an accepted CredentialConsent.  When provided, "
        "holder_key / issuer / burn_authorization are sourced from the consent record.",
    )

    # ── Path 2: legacy inline ──────────────────────────────────────────────────
    holder_key: str | None = Field(None, max_length=512)

    @field_validator("holder_key")
    @classmethod
    def holder_key_not_blank(cls, v: str | None) -> str | None:
        if v is not None and not v.strip():
            raise ValueError("holder_key must not be empty or whitespace-only")
        return v

    credential_type: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    issuer: str = Field("", min_length=0, max_length=500)
    burn_authorization: str = Field(
        "issuer_only",
        description="Chain-agnostic burn authority: issuer_only | owner_only | both | neither.",
    )
    holder_signature: str | None = Field(
        None,
        pattern=r"^[0-9a-f]{128}$",
        description=(
            "Hex Ed25519 signature proving possession of holder_key. "
            "Required on the legacy path outside development bypass mode."
        ),
    )


class CredentialResponse(BaseModel):
    """Response representation of a KeyCredential."""

    id: str
    holder_key: str
    holder_account_id: str | None = None
    credential_type: str
    issued_at: datetime
    revoked_at: datetime | None = None
    issuer: str
    burn_authorization: str
    sbt_nontransferable: bool
    commit_id: str
    revocation_commit_id: str | None = None
    consent_id: str | None = None

    # ── EVM on-chain mirror status ─────────────────────────────────────────────
    # Reflects the state of the optional ERC-5484 on-chain mirror.
    # This field is computed at query time from the evm_pending_ops table and is
    # NOT stored on the credential row itself — it is advisory only.
    #
    # Values:
    #   "none"     — no mint op exists, or all mint ops were skipped
    #   "pending"  — a mint op is queued or submitted but not yet confirmed
    #   "anchored" — the most recent mint is confirmed and no confirmed burn exists
    #   "revoked"  — a burn op has been confirmed on-chain
    #   "failed"   — the last mint attempt failed; no confirmed mint on record
    evm_status: str = "none"

    model_config = {"from_attributes": True}


# ── Ledger event ──────────────────────────────────────────────────────────────


class CredentialEventResponse(BaseModel):
    """A single lifecycle event for a credential, as recorded in the ledger."""

    id: str
    credential_id: str
    event_type: str  # "issued" | "revoked" | "burned"
    ledger_commit_id: str
    created_at: datetime
    inclusion_proof: str | None = None  # JSON string or None if not yet anchored
    smt_root: str | None = None

    model_config = {"from_attributes": True}
