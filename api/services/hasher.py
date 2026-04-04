"""
BLAKE3 hashing utilities for the Olympus FOIA backend.

Olympus stores hashes, never files.  These helpers produce deterministic,
canonical BLAKE3 digests for requests, documents, and commit identifiers.
"""

from __future__ import annotations

import os
from datetime import datetime

from protocol.canonical_json import canonical_json_encode
from protocol.hashes import hash_bytes


def hash_request(
    subject: str,
    description: str,
    agency: str,
    filed_at: datetime,
) -> str:
    """Compute a deterministic BLAKE3 hash of a public-records request.

    The hash is computed over a canonical JSON representation of the core
    request fields, sorted by key and with no extraneous whitespace.  This
    ensures that semantically identical requests produce the same hash
    regardless of serialisation order.

    Args:
        subject: Subject line of the request.
        description: Full request description.
        agency: Agency name or identifier.
        filed_at: Filing timestamp (UTC).

    Returns:
        Hex-encoded BLAKE3 digest.
    """
    canonical = canonical_json_encode(
        {
            "agency": agency,
            "description": description,
            "filed_at": filed_at.isoformat(),
            "subject": subject,
        }
    )
    return hash_bytes(canonical.encode("utf-8")).hex()


def hash_document(file_bytes: bytes) -> str:
    """Compute the BLAKE3 hash of raw document bytes.

    Olympus stores this hash only — the underlying file is never retained.

    Args:
        file_bytes: Raw bytes of the document.

    Returns:
        Hex-encoded BLAKE3 digest.
    """
    return hash_bytes(file_bytes).hex()


def generate_commit_id() -> str:
    """Generate a unique commit identifier.

    Returns:
        ``0x`` followed by 20 random hex bytes (42 characters total).
    """
    return "0x" + os.urandom(20).hex()
