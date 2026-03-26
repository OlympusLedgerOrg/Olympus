"""
Upload validation helpers — magic-byte MIME type detection and enforcement.

Validates uploaded file content against an allowlist of safe MIME types
rather than trusting the client-supplied ``Content-Type`` header.
"""

from __future__ import annotations

import logging

import magic
from fastapi import HTTPException

logger = logging.getLogger(__name__)

ALLOWED_MIME_TYPES: set[str] = {
    "application/pdf",
    "text/plain",
    "text/html",
    "application/json",
    "image/png",
    "image/jpeg",
    "image/tiff",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/zip",
    "application/xml",
    "text/xml",
}


def validate_file_magic(content: bytes, declared_content_type: str) -> str:
    """Detect MIME type from file content and enforce the allowlist.

    Args:
        content: Raw file bytes (at least the first 2048 bytes are inspected).
        declared_content_type: The ``Content-Type`` header supplied by the client.

    Returns:
        The detected MIME type string.

    Raises:
        HTTPException 415: If the detected MIME type is not in :data:`ALLOWED_MIME_TYPES`.
    """
    detected = magic.from_buffer(content[:2048], mime=True)

    if detected not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"File type '{detected}' is not permitted.",
        )

    if detected != declared_content_type:
        logger.warning(
            "Content-Type mismatch: declared=%s detected=%s",
            declared_content_type,
            detected,
        )

    return detected
