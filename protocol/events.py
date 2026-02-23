"""
Canonical event container for Olympus.

This module defines :class:`CanonicalEvent`, a thin dataclass that packages
canonicalized event payloads together with their deterministic byte
representation and BLAKE3 hash.  Events are canonicalized using the same
rules as document ingestion to guarantee cross-machine reproducibility.
"""

from dataclasses import dataclass
from typing import Any

from .canonical import canonicalize_document, document_to_bytes
from .hashes import hash_bytes


@dataclass(frozen=True)
class CanonicalEvent:
    """
    Canonical representation of an event ready for hashing/commitment.

    Attributes:
        payload: Canonicalized event data (dict with sorted keys and normalized
            whitespace).
        canonical_bytes: UTF-8 bytes of the canonical JSON encoding.
        schema_version: Schema version identifier associated with the event.
        hash_hex: Hex-encoded BLAKE3 hash of ``canonical_bytes``.
    """

    payload: dict[str, Any]
    canonical_bytes: bytes
    schema_version: str
    hash_hex: str

    @classmethod
    def from_raw(cls, event: dict[str, Any], schema_version: str) -> "CanonicalEvent":
        """
        Canonicalize a raw event dictionary and compute its hash.

        Args:
            event: Raw event data.
            schema_version: Schema version identifier to attach to the event.

        Returns:
            CanonicalEvent instance containing canonical payload, bytes, and hash.

        Raises:
            ValueError: If the event is not a dictionary or schema_version is empty.
        """
        if not isinstance(event, dict):
            raise ValueError("CanonicalEvent payload must be a dictionary")
        if not schema_version:
            raise ValueError("schema_version must be a non-empty string")

        canonical_payload = canonicalize_document(event)
        canonical_bytes = document_to_bytes(canonical_payload)
        event_hash = hash_bytes(canonical_bytes)
        return cls(
            payload=canonical_payload,
            canonical_bytes=canonical_bytes,
            schema_version=schema_version,
            hash_hex=event_hash.hex(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize the canonical payload and schema version for bundles."""
        return {
            "schema_version": self.schema_version,
            "payload": self.payload,
            "hash_hex": self.hash_hex,
        }
