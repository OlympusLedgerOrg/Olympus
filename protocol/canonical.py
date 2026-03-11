"""
Canonical document representation for Olympus

This module implements deterministic canonicalization of documents to ensure
consistent hashing regardless of superficial formatting differences.

This provides basic structural canonicalization: JSON key sorting, whitespace
normalization, and deterministic byte encoding. For multi-format artifact
ingestion (JCS/RFC 8785, HTML, DOCX, PDF) with version-pinned pipelines,
see protocol/canonicalizer.py instead.
"""

import unicodedata
from typing import Any

from .canonical_json import canonical_json_encode


# Unicode space-like characters that unicodedata.normalize("NFKC", ...) does NOT
# map to ASCII space but that are visually indistinguishable from a regular space
# (commonly found in PDFs and other document formats).
_RESIDUAL_UNICODE_SPACES = str.maketrans(
    {
        "\u00a0": " ",  # NO-BREAK SPACE
        "\u202f": " ",  # NARROW NO-BREAK SPACE
    }
)


# Canonical format version - DO NOT CHANGE
# Changing this breaks all historical document proofs
CANONICAL_VERSION = "canonical_v1"


def canonicalize_json(data: dict[str, Any]) -> str:
    """
    Canonicalize a JSON-serializable dictionary.

    Args:
        data: Dictionary to canonicalize

    Returns:
        Canonical JSON string representation
    """
    return canonical_json_encode(data)


def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text to ensure deterministic canonicalization.

    Handles non-standard Unicode whitespace commonly present in PDFs (e.g.,
    NO-BREAK SPACE U+00A0, NARROW NO-BREAK SPACE U+202F, THIN SPACE U+2009).

    Steps applied:
    1. NFC normalization to a single canonical Unicode form.
    2. Explicit replacement of residual NBSP-like characters not covered by NFKC.
    3. Collapse all remaining whitespace runs and strip leading/trailing whitespace.

    Args:
        text: Input text

    Returns:
        Text with normalized whitespace
    """
    # Step 1: NFC normalizes canonical-equivalent Unicode representations.
    text = unicodedata.normalize("NFC", text)
    # Step 2: Map residual non-breaking space characters that NFKC leaves intact.
    text = text.translate(_RESIDUAL_UNICODE_SPACES)
    # Step 3: Collapse all whitespace and strip.
    return " ".join(text.split())


def canonicalize_document(doc: dict[str, Any]) -> dict[str, Any]:
    """
    Canonicalize a document structure.

    This ensures deterministic ordering and formatting.

    Args:
        doc: Document to canonicalize

    Returns:
        Canonicalized document
    """
    if not isinstance(doc, dict):
        raise ValueError("Document must be a dictionary")

    def _canonicalize_value(value: Any) -> Any:
        if isinstance(value, dict):
            return canonicalize_document(value)
        if isinstance(value, list):
            return [_canonicalize_value(item) for item in value]
        if isinstance(value, str):
            return normalize_whitespace(value)
        return value

    canonical: dict[str, Any] = {}
    for key in sorted(doc.keys()):
        canonical[key] = _canonicalize_value(doc[key])

    return canonical


def document_to_bytes(doc: dict[str, Any]) -> bytes:
    """
    Convert document to canonical byte representation.

    Args:
        doc: Document to convert

    Returns:
        Canonical bytes
    """
    canonical = canonicalize_document(doc)
    json_str = canonicalize_json(canonical)
    return json_str.encode("utf-8")


def canonicalize_text(text: str) -> str:
    """
    Canonicalize text by normalizing whitespace and line endings.

    This ensures the same content produces the same canonical bytes
    regardless of whitespace or line ending differences.

    Args:
        text: Input text

    Returns:
        Canonicalized text with normalized whitespace and Unix line endings
    """
    # Normalize line endings to Unix style (\n)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Normalize multiple spaces to single space (handles Unicode whitespace too)
    lines = text.split("\n")
    normalized_lines = [normalize_whitespace(line) for line in lines]

    # Remove empty lines at start and end, preserve internal structure
    while normalized_lines and not normalized_lines[0]:
        normalized_lines.pop(0)
    while normalized_lines and not normalized_lines[-1]:
        normalized_lines.pop()

    return "\n".join(normalized_lines)
