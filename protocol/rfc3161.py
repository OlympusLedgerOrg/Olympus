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
from dataclasses import dataclass
from datetime import UTC

import rfc3161ng


# Well-known public TSA endpoints (free, unauthenticated, publicly trusted)
DEFAULT_TSA_URL = "https://freetsa.org/tsr"
DIGICERT_TSA_URL = "https://timestamp.digicert.com"
SECTIGO_TSA_URL = "https://timestamp.sectigo.com"


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

    def to_dict(self) -> dict[str, str]:
        """Serialize to a JSON-safe dictionary (``tst_bytes`` encoded as hex).

        Returns:
            Dictionary with string values suitable for JSON serialisation.
        """
        return {
            "hash_hex": self.hash_hex,
            "tsa_url": self.tsa_url,
            "tst_hex": self.tst_bytes.hex(),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "TimestampToken":
        """Deserialize from a dictionary produced by :meth:`to_dict`.

        Args:
            data: Dictionary with keys ``hash_hex``, ``tsa_url``,
                  ``tst_hex``, and ``timestamp``.

        Returns:
            A :class:`TimestampToken` instance.
        """
        return cls(
            hash_hex=data["hash_hex"],
            tsa_url=data["tsa_url"],
            tst_bytes=bytes.fromhex(data["tst_hex"]),
            timestamp=data["timestamp"],
        )


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
    return rfc3161ng.encode_timestamp_request(req)


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
    ts = rfc3161ng.get_timestamp(tst_bytes, naive=False).astimezone(UTC)
    timestamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    return TimestampToken(
        hash_hex=hash_hex,
        tsa_url=tsa_url,
        tst_bytes=tst_bytes,
        timestamp=timestamp,
    )


def verify_timestamp_token(
    tst_bytes: bytes,
    hash_hex: str,
    certificate: bytes | None = None,
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
        certificate: PEM-encoded TSA signing certificate.  If ``None``, the
                     certificate embedded in the token (``certReq=True``) is
                     used for verification.

    Returns:
        ``True`` if the token is valid.

    Raises:
        ValueError: If ``hash_hex`` is invalid, the token is malformed, or
                    the message imprint does not match.
    """
    digest = _sha256_of_hash(hash_hex)
    return rfc3161ng.check_timestamp(
        tst_bytes,
        certificate=certificate,
        digest=digest,
        hashname="sha256",
    )
