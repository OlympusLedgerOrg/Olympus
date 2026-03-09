"""RFC 3161 trusted timestamping for Olympus ledger roots.

Anchors a ledger root hash to an independent Timestamp Authority (TSA),
providing cryptographic proof of existence at a specific time without
depending on trust in Olympus itself.  This is the spirit of the whole
project: even if Olympus were compromised, a valid RFC 3161 token issued
by any publicly trusted TSA proves that the hash existed no later than
the time shown in the token.

Protocol usage:
  1. Compute the ledger root hash (``entry_hash`` of the latest entry).
  2. Call :func:`request_timestamp` to get a :class:`TimestampToken`.
  3. Store ``TimestampToken.tst_bytes`` alongside the ledger entry.
  4. Later, call :func:`verify_timestamp_token` to verify independently.
"""

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rfc3161ng
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der import decoder  # type: ignore[import-untyped]
from pyasn1.type import univ as pyasn1_univ  # type: ignore[import-untyped]
from rfc3161ng.api import load_certificate


# Well-known public TSA endpoints (free, unauthenticated, publicly trusted)
DEFAULT_TSA_URL = "https://freetsa.org/tsr"
DIGICERT_TSA_URL = "https://timestamp.digicert.com"
SECTIGO_TSA_URL = "https://timestamp.sectigo.com"
DEFAULT_FINALIZATION_TSA_URLS = (DEFAULT_TSA_URL, DIGICERT_TSA_URL, SECTIGO_TSA_URL)
MAX_TSA_TOKENS = 3
TSA_QUORUM_THRESHOLD = 2
TRUST_MODE_DEV = "dev"
TRUST_MODE_PROD = "prod"


@dataclass
class TimestampToken:
    """An RFC 3161 timestamp token anchoring a ledger root hash.

    Attributes:
        hash_hex: Hex-encoded BLAKE3 ledger root hash that was timestamped.
        tsa_url: URL of the TSA that issued the token.
        tst_bytes: DER-encoded TimeStampToken; store this for later verification.
        timestamp: UTC timestamp from the TSA in ISO 8601 / RFC 3339 format.
    """

    hash_hex: str
    tsa_url: str
    tst_bytes: bytes
    timestamp: str
    tsa_cert_fingerprint: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        """Serialize to a JSON-safe dictionary (``tst_bytes`` encoded as hex).

        Returns:
            Dictionary with string values suitable for JSON serialisation.
        """
        return {
            "hash_hex": self.hash_hex,
            "tsa_url": self.tsa_url,
            "tst_hex": self.tst_bytes.hex(),
            "timestamp": self.timestamp,
            "tsa_cert_fingerprint": self.tsa_cert_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "TimestampToken":
        """Deserialize from a dictionary produced by :meth:`to_dict`.

        Args:
            data: Dictionary with keys ``hash_hex``, ``tsa_url``,
                  ``tst_hex``, ``timestamp``, and optional
                  ``tsa_cert_fingerprint``.

        Returns:
            A :class:`TimestampToken` instance.
        """
        return cls(
            hash_hex=data["hash_hex"],
            tsa_url=data["tsa_url"],
            tst_bytes=bytes.fromhex(data["tst_hex"]),
            timestamp=data["timestamp"],
            tsa_cert_fingerprint=data.get("tsa_cert_fingerprint"),
        )


def _extract_tsa_cert_fingerprint(tst_bytes: bytes) -> str | None:
    """Extract the TSA certificate fingerprint from a TimeStampToken, if present."""
    try:
        tst, substrate = decoder.decode(tst_bytes, asn1Spec=rfc3161ng.TimeStampToken())
        if substrate:
            return None
        signed_data = tst.content
        certificate: x509.Certificate = load_certificate(signed_data, certificate=b"")
        fingerprint = certificate.fingerprint(hashes.SHA256())
        return fingerprint.hex()
    except Exception:
        return None


def _load_trust_store_certificate(trust_store_path: str) -> bytes:
    """Load a TSA certificate from a configured trust store path."""
    path = Path(trust_store_path)
    if not path.exists():
        raise ValueError(f"Trust store path not found: {trust_store_path}")
    return path.read_bytes()


def _extract_message_imprint(tst_bytes: bytes) -> bytes | None:
    """Extract the hashedMessage bytes from a TimeStampToken's TSTInfo.

    Args:
        tst_bytes: DER-encoded TimeStampToken bytes.

    Returns:
        Raw bytes of the message imprint hash, or ``None`` if extraction fails.
    """
    try:
        tst, substrate = decoder.decode(tst_bytes, asn1Spec=rfc3161ng.TimeStampToken())
        if substrate:
            return None
        tstinfo_oct = (
            tst.getComponentByName("content").getComponentByPosition(2).getComponentByPosition(1)
        )
        tstinfo_oct, substrate = decoder.decode(
            bytes(tstinfo_oct), asn1Spec=pyasn1_univ.OctetString()
        )
        if substrate:
            return None
        tstinfo, substrate = decoder.decode(bytes(tstinfo_oct), asn1Spec=rfc3161ng.TSTInfo())
        if substrate:
            return None
        return bytes(tstinfo["messageImprint"]["hashedMessage"])
    except Exception:
        return None


def _enforce_trust_mode_environment(trust_mode: str) -> None:
    """Reject insecure trust-mode selections in production environments."""
    env = os.getenv("OLYMPUS_ENV", "").strip().lower()
    if env in {"prd", "prod", "production", "live"} and trust_mode == TRUST_MODE_DEV:
        raise RuntimeError("DEV trust mode forbidden in production")


def _sha256_of_hash(hash_hex: str) -> bytes:
    """Compute SHA-256 of the binary form of a hex-encoded BLAKE3 hash.

    RFC 3161 requires a standard hash algorithm.  We SHA-256 the raw bytes
    of the BLAKE3 ledger root hash, yielding a deterministic 32-byte digest
    suitable for the timestamp request.

    Args:
        hash_hex: Hex-encoded BLAKE3 hash (any even-length hex string).

    Returns:
        32-byte SHA-256 digest.

    Raises:
        ValueError: If ``hash_hex`` is not valid hexadecimal.
    """
    try:
        raw = bytes.fromhex(hash_hex)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Invalid hash_hex {hash_hex!r}: {exc}") from exc
    return hashlib.sha256(raw).digest()


def build_timestamp_request(hash_hex: str) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq for a ledger root hash.

    This can be used to inspect or audit the request independently of the
    :func:`request_timestamp` convenience function.

    Args:
        hash_hex: Hex-encoded BLAKE3 ledger root hash.

    Returns:
        DER-encoded TimeStampReq bytes ready to POST to a TSA endpoint.

    Raises:
        ValueError: If ``hash_hex`` is not valid hexadecimal.
    """
    digest = _sha256_of_hash(hash_hex)
    req = rfc3161ng.make_timestamp_request(
        digest=digest,
        hashname="sha256",
        include_tsa_certificate=True,
    )
    return bytes(rfc3161ng.encode_timestamp_request(req))


def request_timestamp(
    hash_hex: str,
    tsa_url: str = DEFAULT_TSA_URL,
) -> "TimestampToken":
    """Request an RFC 3161 timestamp from a TSA for a ledger root hash.

    Args:
        hash_hex: Hex-encoded BLAKE3 ledger root hash to timestamp.
        tsa_url: URL of the Timestamp Authority.  Defaults to FreeTSA
                 (``https://freetsa.org/tsr``).

    Returns:
        :class:`TimestampToken` containing the signed TSA response.

    Raises:
        ValueError: If ``hash_hex`` is invalid or the TSA response is malformed.
        rfc3161ng.TimestampingError: If the TSA request or validation fails.
    """
    digest = _sha256_of_hash(hash_hex)
    stamper = rfc3161ng.RemoteTimestamper(
        tsa_url,
        hashname="sha256",
        include_tsa_certificate=True,
    )
    tst_bytes: bytes = stamper(digest=digest, return_tsr=False)
    ts = rfc3161ng.get_timestamp(tst_bytes, naive=False).astimezone(timezone.utc)
    timestamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    tsa_cert_fingerprint = _extract_tsa_cert_fingerprint(tst_bytes)
    return TimestampToken(
        hash_hex=hash_hex,
        tsa_url=tsa_url,
        tst_bytes=tst_bytes,
        timestamp=timestamp,
        tsa_cert_fingerprint=tsa_cert_fingerprint,
    )


def _normalize_tsa_urls(tsa_urls: Sequence[str]) -> tuple[str, ...]:
    """Validate and normalize a sequence of TSA URLs for quorum operations."""
    normalized = tuple(url for url in tsa_urls if url)
    if len(normalized) < 2:
        raise ValueError("At least two independent TSA URLs are required")
    if len(set(normalized)) != len(normalized):
        raise ValueError("TSA URLs must be unique for quorum anchoring")
    return normalized


def _enforce_uniform_tsa_configuration(tsa_urls: Sequence[str]) -> tuple[str, ...]:
    """Require all nodes to use a prefix of the protocol-default TSA configuration.

    Accepts any prefix of ``DEFAULT_FINALIZATION_TSA_URLS`` of length >= 2 so
    callers can request exactly the subset of TSAs they intend to anchor to
    while preserving deterministic ordering across the federation.
    """
    normalized = _normalize_tsa_urls(tsa_urls)
    default_prefix = DEFAULT_FINALIZATION_TSA_URLS[: len(normalized)]
    if normalized != default_prefix:
        raise ValueError(
            "TSA quorum URLs must match DEFAULT_FINALIZATION_TSA_URLS for uniform federation finalization"
        )
    return normalized


def request_timestamp_quorum(
    hash_hex: str, tsa_urls: Sequence[str] = DEFAULT_FINALIZATION_TSA_URLS
) -> list[TimestampToken]:
    """
    Request timestamp tokens from multiple independent TSAs.

    Finalization requires one valid token from each configured TSA URL. This
    helper enforces a minimum quorum of two independent authorities and returns
    the collected tokens in caller-specified order.

    Args:
        hash_hex: Hex-encoded BLAKE3 hash to timestamp.
        tsa_urls: Independent RFC 3161 TSA endpoints to require for finalization.

    Returns:
        List of :class:`TimestampToken` instances, one per TSA URL.
    """
    return [
        request_timestamp(hash_hex, tsa_url=url)
        for url in _enforce_uniform_tsa_configuration(tsa_urls)
    ]


def verify_timestamp_token(
    tst_bytes: bytes,
    hash_hex: str,
    certificate: bytes | None = None,
    trust_mode: str = TRUST_MODE_DEV,
    trusted_fingerprints: set[str] | None = None,
    trust_store_path: str | None = None,
) -> bool:
    """Verify an RFC 3161 timestamp token against a ledger root hash.

    The token is valid when:
    * Its message imprint (SHA-256 of the BLAKE3 hash bytes) matches the
      supplied ``hash_hex``.
    * The TSA's signature over the TSTInfo is cryptographically correct.

    Args:
        tst_bytes: DER-encoded TimeStampToken bytes (from
                   :attr:`TimestampToken.tst_bytes`).
        hash_hex: Hex-encoded BLAKE3 ledger root hash that was timestamped.
        certificate: PEM/DER-encoded TSA signing certificate to pin explicitly.
        trust_mode: ``dev`` accepts embedded certificates; ``prod`` requires
            pinned fingerprints or an explicit trust store certificate.
        trusted_fingerprints: Set of SHA-256 TSA certificate fingerprints (hex)
            accepted in production mode.
        trust_store_path: Path to a PEM/DER TSA certificate for production mode.

    Returns:
        ``True`` if the token is valid.

    Raises:
        ValueError: If ``hash_hex`` is invalid, the token is malformed, or
                    the message imprint does not match.
    """
    if trust_mode not in {TRUST_MODE_DEV, TRUST_MODE_PROD}:
        raise ValueError(f"Unsupported trust_mode: {trust_mode}")
    _enforce_trust_mode_environment(trust_mode)

    tsa_fingerprint = _extract_tsa_cert_fingerprint(tst_bytes)

    if trust_mode == TRUST_MODE_PROD:
        if trusted_fingerprints:
            if tsa_fingerprint is None:
                raise ValueError("Missing TSA certificate fingerprint in timestamp token")
            normalized_fingerprints = {fp.lower() for fp in trusted_fingerprints}
            if tsa_fingerprint.lower() not in normalized_fingerprints:
                raise ValueError("TSA certificate fingerprint not trusted")
        elif trust_store_path:
            certificate = _load_trust_store_certificate(trust_store_path)
        elif certificate is None:
            raise ValueError(
                "Production trust_mode requires trusted_fingerprints or trust_store_path"
            )

    digest = _sha256_of_hash(hash_hex)

    actual_imprint = _extract_message_imprint(tst_bytes)
    if actual_imprint is not None and actual_imprint != digest:
        raise ValueError("Message imprint mismatch: token imprint does not match sha256(hash_hex)")

    return bool(
        rfc3161ng.check_timestamp(
            tst_bytes,
            certificate=certificate,
            digest=digest,
            hashname="sha256",
        )
    )


def verify_timestamp_quorum(
    tokens: Sequence[TimestampToken | dict[str, Any]],
    hash_hex: str,
    *,
    trust_mode: str = TRUST_MODE_DEV,
    required_tsa_urls: Sequence[str] = DEFAULT_FINALIZATION_TSA_URLS,
    trusted_fingerprints_by_tsa: dict[str, set[str]] | None = None,
    trust_store_paths_by_tsa: dict[str, str] | None = None,
) -> bool:
    """
    Verify that at least ``TSA_QUORUM_THRESHOLD`` of the required TSAs issued
    valid tokens for the same hash (2-of-3 quorum).

    Args:
        tokens: Timestamp tokens collected for the target hash.
        hash_hex: Hex-encoded BLAKE3 hash that was submitted to the TSAs.
        trust_mode: Timestamp trust mode passed through to token verification.
        required_tsa_urls: TSA URLs that form the quorum pool.
        trusted_fingerprints_by_tsa: Optional pinned fingerprint sets by TSA URL.
        trust_store_paths_by_tsa: Optional trust-store paths by TSA URL.

    Returns:
        ``True`` when at least ``TSA_QUORUM_THRESHOLD`` required TSAs each
        contribute a valid token.
    """
    token_map: dict[str, TimestampToken] = {}
    for token in tokens:
        parsed = token if isinstance(token, TimestampToken) else TimestampToken.from_dict(token)
        token_map[parsed.tsa_url] = parsed

    valid_count = 0
    for tsa_url in _enforce_uniform_tsa_configuration(required_tsa_urls):
        required_token = token_map.get(tsa_url)
        if required_token is None:
            continue
        if required_token.hash_hex != hash_hex:
            continue
        trusted_fingerprints = None
        if trusted_fingerprints_by_tsa is not None:
            trusted_fingerprints = trusted_fingerprints_by_tsa.get(tsa_url)
        trust_store_path = None
        if trust_store_paths_by_tsa is not None:
            trust_store_path = trust_store_paths_by_tsa.get(tsa_url)
        try:
            if verify_timestamp_token(
                required_token.tst_bytes,
                hash_hex,
                trust_mode=trust_mode,
                trusted_fingerprints=trusted_fingerprints,
                trust_store_path=trust_store_path,
            ):
                valid_count += 1
        except ValueError:
            pass
    return valid_count >= TSA_QUORUM_THRESHOLD


def timestamp_watchdog_status(
    tokens: Sequence[TimestampToken | dict[str, Any]],
    *,
    required_tsa_urls: Sequence[str] = DEFAULT_FINALIZATION_TSA_URLS,
    stale_after_seconds: int = 3600,
    now: datetime | None = None,
) -> dict[str, Any]:
    """
    Evaluate watchdog freshness for required TSA anchors.

    Args:
        tokens: Timestamp tokens available for the latest finalized header.
        required_tsa_urls: Exact TSA URLs that must remain fresh.
        stale_after_seconds: Maximum allowed age in seconds before a token is stale.
        now: Optional current time for deterministic testing.

    Returns:
        Dictionary containing per-TSA status and alert messages.
    """
    if stale_after_seconds < 0:
        raise ValueError("stale_after_seconds must be non-negative")

    if now is not None and (now.tzinfo is None or now.utcoffset() is None):
        raise ValueError("now must be timezone-aware")
    current_time = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
    token_map = {
        parsed.tsa_url: parsed
        for parsed in (
            token if isinstance(token, TimestampToken) else TimestampToken.from_dict(token)
            for token in tokens
        )
    }

    statuses: dict[str, dict[str, Any]] = {}
    alerts: list[str] = []
    for tsa_url in _enforce_uniform_tsa_configuration(required_tsa_urls):
        token = token_map.get(tsa_url)
        if token is None:
            statuses[tsa_url] = {"present": False, "stale": True, "age_seconds": None}
            alerts.append(f"missing timestamp token for {tsa_url}")
            continue
        issued_at = datetime.fromisoformat(token.timestamp.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
        age_seconds = int((current_time - issued_at).total_seconds())
        stale = age_seconds > stale_after_seconds
        statuses[tsa_url] = {"present": True, "stale": stale, "age_seconds": age_seconds}
        if stale:
            alerts.append(
                f"timestamp token for {tsa_url} is stale ({age_seconds}s > {stale_after_seconds}s)"
            )

    return {"healthy": not alerts, "alerts": alerts, "tsa_status": statuses}
