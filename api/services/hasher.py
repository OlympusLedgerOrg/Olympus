"""
BLAKE3 hashing utilities for the Olympus FOIA backend.

Olympus stores hashes, never files.  These helpers produce deterministic,
canonical BLAKE3 digests for requests, documents, and commit identifiers.
"""

from __future__ import annotations

import json
import os
from datetime import datetime

import blake3


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
    canonical = json.dumps(
        {
            "agency": agency,
            "description": description,
            "filed_at": filed_at.isoformat(),
            "subject": subject,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return blake3.blake3(canonical.encode("utf-8")).hexdigest()


def hash_document(file_bytes: bytes) -> str:
    """Compute the BLAKE3 hash of raw document bytes.

    Olympus stores this hash only — the underlying file is never retained.

    Args:
        file_bytes: Raw bytes of the document.

    Returns:
        Hex-encoded BLAKE3 digest.
    """
    return blake3.blake3(file_bytes).hexdigest()


def generate_commit_id() -> str:
    """Generate a unique commit identifier.

    Returns:
        ``0x`` followed by 20 random hex bytes (42 characters total).
    """
    return "0x" + os.urandom(20).hex()
