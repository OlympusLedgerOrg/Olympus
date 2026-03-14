"""
Identity attestation verification for Olympus.

This module adds a wallet-bound attestation layer so Olympus can verify
signed credentials without storing sensitive identity documents. An
attestation binds an issuer, a subject wallet, and structured claims to
an Ed25519 signature. Verifiers check the signature, wallet binding, and
expiration before accepting a credential.

Issuer Identifier Strategy:
    - The issuer field is a string identifier for the attestation issuer.
    - For human-readable contexts, use domain names like "notary.example".
    - For federation contexts, use the issuer's public key as the identifier
      via :func:`issuer_id_from_pubkey` to bind issuer identity cryptographically.
    - Both patterns are supported; the choice is a policy decision.

Credential Binding:
    - The credential_id field is included in the signed payload (via _payload())
      to cryptographically bind the credential identifier to the attestation.
    - This prevents an attacker from reusing a signature with a different credential_id.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import nacl.exceptions
import nacl.signing

from .canonical_json import canonical_json_bytes
from .hashes import ATTESTATION_PREFIX, HASH_SEPARATOR, blake3_hash
from .timestamps import current_timestamp


_SEP = HASH_SEPARATOR.encode("utf-8")


def issuer_id_from_pubkey(pubkey: bytes | nacl.signing.VerifyKey) -> str:
    """
    Derive an issuer identifier from a public key.

    In federation contexts, using the issuer's public key as the identifier
    provides cryptographic binding of issuer identity. This function returns
    the hex-encoded representation of the public key for use as an issuer field.

    Args:
        pubkey: Ed25519 public key (raw bytes or VerifyKey).

    Returns:
        Hex-encoded public key string suitable for use as an issuer identifier.

    Example:
        >>> verify_key = signing_key.verify_key
        >>> issuer = issuer_id_from_pubkey(verify_key)
        >>> attestation = sign_attestation(
        ...     issuer=issuer,
        ...     subject_wallet="wallet-123",
        ...     claims={"resident": True},
        ...     signing_key=signing_key,
        ... )
    """
    if isinstance(pubkey, nacl.signing.VerifyKey):
        return bytes(pubkey).hex()
    return pubkey.hex()


def _normalize_timestamp(value: str | None) -> str | None:
    """Validate and normalize ISO 8601 timestamps with Z suffix."""
    if value is None:
        return None
    ts = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(ts)
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp: {value}") from exc
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utcnow() -> datetime:
    """Return timezone-aware UTC now (isolated for testing)."""
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Attestation:
    """
    Wallet-bound identity attestation issued by an external provider.

    Attributes:
        issuer: Attestation issuer identifier.
        subject_wallet: Wallet address or public key binding for the subject.
        claims: Structured claims asserted by the issuer.
        issued_at: ISO 8601 timestamp when the attestation was issued.
        expires_at: Optional ISO 8601 expiry timestamp.
        signature: Hex-encoded Ed25519 signature over the attestation payload.
        scheme: Signature scheme (currently ``ed25519``).
        credential_id: Optional stable identifier for the credential.
    """

    issuer: str
    subject_wallet: str
    claims: Mapping[str, Any]
    issued_at: str
    expires_at: str | None
    signature: str
    scheme: str = "ed25519"
    credential_id: str | None = None

    def _payload(self) -> dict[str, Any]:
        """Return the canonical payload used for hashing and signing."""
        return {
            "issuer": self.issuer,
            "subject_wallet": self.subject_wallet,
            "claims": self.claims,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "credential_id": self.credential_id,
            "scheme": self.scheme,
        }

    def payload_hash(self) -> bytes:
        """Return the domain-separated BLAKE3 hash of the attestation payload."""
        return blake3_hash([ATTESTATION_PREFIX, _SEP, canonical_json_bytes(self._payload())])

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Return True if the attestation is expired relative to ``now``."""
        if self.expires_at is None:
            return False
        parsed_expiry = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        reference = now or _utcnow()
        return reference > parsed_expiry


def sign_attestation(
    *,
    issuer: str,
    subject_wallet: str,
    claims: Mapping[str, Any],
    signing_key: nacl.signing.SigningKey,
    expires_at: str | None = None,
    issued_at: str | None = None,
    credential_id: str | None = None,
) -> Attestation:
    """
    Create and sign a wallet-bound attestation.

    Args:
        issuer: Issuer identifier.
        subject_wallet: Wallet binding for the subject (string form).
        claims: Structured claims asserted by the issuer.
        signing_key: Issuer Ed25519 signing key.
        expires_at: Optional expiry timestamp (ISO 8601 with ``Z``).
        issued_at: Optional issue timestamp; defaults to :func:`current_timestamp`.
        credential_id: Optional stable identifier for tracking.

    Returns:
        Signed :class:`Attestation`.
    """
    normalized_issued_at = _normalize_timestamp(issued_at or current_timestamp())
    normalized_expires_at = _normalize_timestamp(expires_at) if expires_at else None

    attestation = Attestation(
        issuer=issuer,
        subject_wallet=subject_wallet,
        claims=claims,
        issued_at=normalized_issued_at or current_timestamp(),
        expires_at=normalized_expires_at,
        signature="",  # Placeholder; populated after signing.
        credential_id=credential_id,
    )
    signature = signing_key.sign(attestation.payload_hash()).signature.hex()
    return Attestation(
        issuer=attestation.issuer,
        subject_wallet=attestation.subject_wallet,
        claims=attestation.claims,
        issued_at=attestation.issued_at,
        expires_at=attestation.expires_at,
        signature=signature,
        scheme=attestation.scheme,
        credential_id=attestation.credential_id,
    )


def verify_attestation(
    attestation: Attestation,
    issuer_verify_key: nacl.signing.VerifyKey,
    *,
    expected_wallet: str | None = None,
    now: datetime | None = None,
) -> bool:
    """
    Verify an attestation's signature, wallet binding, and freshness.

    Args:
        attestation: Attestation to verify.
        issuer_verify_key: Issuer Ed25519 verification key.
        expected_wallet: Optional wallet that must match the attested wallet.
        now: Optional reference time for expiry checks.

    Returns:
        True if the attestation is valid.
    """
    if attestation.scheme != "ed25519":
        return False
    if expected_wallet is not None and attestation.subject_wallet != expected_wallet:
        return False
    if attestation.is_expired(now=now):
        return False
    try:
        signature_bytes = bytes.fromhex(attestation.signature)
    except ValueError:
        return False
    try:
        issuer_verify_key.verify(attestation.payload_hash(), signature_bytes)
    except (nacl.exceptions.BadSignatureError, ValueError):
        return False
    return True
