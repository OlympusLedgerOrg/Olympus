"""
Pydantic v2 schemas for operator identity endpoints.

Operators are Ed25519 identities that hold SBT/role credentials.  API keys
are minted per-operator so every request carries a cryptographic identity.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


# Well-known roles.  Custom values are accepted; authorisation is scope-based.
OPERATOR_ROLES = frozenset({"node_operator", "agency_operator", "admin", "auditor"})

# Default scopes granted to a freshly-bootstrapped operator key.
OPERATOR_DEFAULT_SCOPES = ["read", "write", "ingest", "commit", "verify"]


# ── Operator responses ────────────────────────────────────────────────────────


class OperatorResponse(BaseModel):
    """Public representation of an operator identity."""

    id: str
    ed25519_public_key: str
    credential_id: str | None = None
    role: str
    label: str
    created_at: datetime
    activated_at: datetime | None = None
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}


# ── Bootstrap (first-boot operator creation) ──────────────────────────────────


class OperatorBootstrapRequest(BaseModel):
    """Body for POST /auth/operator/bootstrap.

    Creates the first operator identity from an Ed25519 public key.
    The bootstrap key (``X-Bootstrap-Key`` header) must match
    ``OLYMPUS_BOOTSTRAP_KEY`` env var (auto-printed at startup in dev mode).
    """

    ed25519_public_key: str = Field(
        ...,
        pattern=r"^[0-9a-f]{64}$",
        description=(
            "Hex-encoded 32-byte Ed25519 public key.  "
            "This becomes the permanent cryptographic identity of this operator."
        ),
    )
    label: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Human-readable name for this operator (node hostname, agency name, etc.)",
    )
    role: str = Field(
        "node_operator",
        min_length=3,
        max_length=64,
        pattern=r"^[a-z][a-z0-9_]{2,63}$",
        description="Role string.  Well-known: node_operator | agency_operator | admin | auditor",
    )
    key_name: str = Field(
        "bootstrap-key",
        min_length=1,
        max_length=128,
        description="Label for the minted API key.",
    )


class OperatorBootstrapResponse(BaseModel):
    """Returned by POST /auth/operator/bootstrap.

    ``api_key`` is the raw key — shown exactly once, never again.
    Store it securely immediately.
    """

    operator: OperatorResponse
    api_key: str = Field(description="Raw API key — copy this now.  It will not be shown again.")
    key_id: str
    scopes: list[str]
    expires_at: str
    message: str


# ── Operator key management ───────────────────────────────────────────────────


class OperatorKeyMintRequest(BaseModel):
    """Body for POST /auth/operator/keys — mint an additional key for this operator."""

    name: str = Field(..., min_length=1, max_length=128)
    scopes: list[str] = Field(
        default_factory=lambda: list(OPERATOR_DEFAULT_SCOPES),
        description="Scopes for the new key.  Defaults to full operator scopes.",
    )
    expires_at: str = Field(
        "2099-01-01T00:00:00Z",
        description="ISO-8601 expiry timestamp (UTC).",
    )


class OperatorKeyResponse(BaseModel):
    """Returned when a new operator API key is minted."""

    api_key: str = Field(description="Raw API key — copy this now.")
    key_id: str
    operator_id: str
    ed25519_public_key: str
    name: str
    scopes: list[str]
    expires_at: str
    message: str


# ── /me — current operator identity ──────────────────────────────────────────


class OperatorMeResponse(BaseModel):
    """Returned by GET /auth/operator/me."""

    operator: OperatorResponse
    # The key used to make this request
    current_key_id: str
    current_key_name: str
    current_key_scopes: list[str]
    active_key_count: int
