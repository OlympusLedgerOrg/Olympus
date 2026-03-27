"""
Canonical document representation for Olympus

This module implements deterministic canonicalization of documents to ensure
consistent hashing regardless of superficial formatting differences.

This provides basic structural canonicalization: JSON key sorting, whitespace
normalization, and deterministic byte encoding. For multi-format artifact
ingestion (JCS/RFC 8785, HTML, DOCX, PDF) with version-pinned pipelines,
see protocol/canonicalizer.py instead.
"""

import math
import unicodedata
from decimal import Decimal
from typing import Any

from .canonical_json import canonical_json_encode
from .canonicalizer import CanonicalizationError


# Unicode space-like characters that unicodedata.normalize("NFKC", ...) does NOT
# map to ASCII space but that are visually indistinguishable from a regular space
# (commonly found in PDFs and other document formats).
_RESIDUAL_UNICODE_SPACES = str.maketrans(
    {
        "\u00a0": " ",  # NO-BREAK SPACE
        "\u202f": " ",  # NARROW NO-BREAK SPACE
    }
)


CANONICAL_VERSION = "canonical_v2"
"""Current canonical format version.

Version history:

- ``canonical_v1`` — original format.  Merkle trees used CT-style lone-node
  promotion (no rehash for odd-count levels) and numeric values in documents
  were passed through without normalization.
- ``canonical_v2`` — (current) lone Merkle nodes are self-paired instead of
  promoted, preventing batching-boundary root divergence.  Float values are
  normalised to ``int`` when whole, or to ``Decimal`` otherwise; NaN / Inf
  are rejected.  Homoglyph scrub collapses fullwidth Latin, mathematical
  alphanumerics, and enclosed alphanumerics to their ASCII equivalents.

Cross-version verification: the verifier accepts proofs generated under any
version listed in :data:`SUPPORTED_VERSIONS`.  ``canonical_v1`` proofs emit
a deprecation warning.  A full migration layer is tracked separately.
"""

SUPPORTED_VERSIONS = ["canonical_v1", "canonical_v2"]
"""All canonical versions the verifier is willing to accept."""


def _scrub_homoglyphs(text: str) -> str:
    """Replace Unicode characters whose NFKD form is a single ASCII printable char.

    This catches fullwidth Latin (U+FF01–U+FF5E), mathematical bold/italic/
    script/fraktur alphanumerics, and enclosed alphanumerics — all visually
    similar to ASCII but distinct under NFC.

    Legitimate non-ASCII content (Arabic, CJK, accented Latin such as ``é``)
    is left untouched because its NFKD decomposition either maps to multiple
    characters or to a codepoint outside the ASCII printable range.

    Args:
        text: Input string (should already be NFC-normalised).

    Returns:
        String with ASCII-equivalent homoglyphs replaced.
    """
    out: list[str] = []
    for ch in text:
        decomposed = unicodedata.normalize("NFKD", ch)
        if len(decomposed) == 1 and 0x20 <= ord(decomposed) <= 0x7E:
            out.append(decomposed)
        else:
            out.append(ch)
    return "".join(out)


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
    2. Explicit replacement of NBSP-like characters (which NFC preserves as semantically distinct).
    3. Collapse all remaining whitespace runs and strip leading/trailing whitespace.

    Args:
        text: Input text

    Returns:
        Text with normalized whitespace
    """
    # Step 1: NFC normalizes canonical-equivalent Unicode representations.
    text = unicodedata.normalize("NFC", text)
    # Step 2: Map non-breaking space characters (NFC preserves them as distinct).
    text = text.translate(_RESIDUAL_UNICODE_SPACES)
    # Step 3: Collapse all whitespace and strip.
    return " ".join(text.split())


def canonicalize_document(
    doc: dict[str, Any],
    *,
    scrub_homoglyphs: bool = True,
    sorted_list_keys: set[str] | None = None,
) -> dict[str, Any]:
    """
    Canonicalize a document structure.

    This ensures deterministic ordering and formatting.

    Args:
        doc: Document to canonicalize
        scrub_homoglyphs: If ``True`` (default), replace Unicode characters
            whose NFKD decomposition is a single ASCII printable character
            with that ASCII character.  Set to ``False`` only if the corpus
            intentionally uses fullwidth characters as data.
        sorted_list_keys: Optional set of field names whose array values
            should be sorted for canonical ordering.  Fields not in this set
            preserve their original order.  Sorting uses the canonical JSON
            representation of each element so it is deterministic across
            types.  Pass ``None`` (default) to skip all list sorting.

    Returns:
        Canonicalized document
    """
    if not isinstance(doc, dict):
        raise ValueError("Document must be a dictionary")

    _sorted_keys = sorted_list_keys or set()

    def _sort_key(item: Any) -> str:
        """Deterministic sort key for heterogeneous list elements."""
        if isinstance(item, dict):
            return canonical_json_encode(item)
        return canonical_json_encode({"": item})

    def _canonicalize_value(value: Any, *, field_name: str = "") -> Any:
        if isinstance(value, dict):
            return canonicalize_document(
                value,
                scrub_homoglyphs=scrub_homoglyphs,
                sorted_list_keys=sorted_list_keys,
            )
        if isinstance(value, list):
            items = [_canonicalize_value(item) for item in value]
            if field_name in _sorted_keys:
                items = sorted(items, key=_sort_key)
            return items
        if isinstance(value, str):
            normalized = normalize_whitespace(value)
            if scrub_homoglyphs:
                normalized = _scrub_homoglyphs(normalized)
            return normalized
        if isinstance(value, bool):
            # bool is a subclass of int; must be checked before int
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            if math.isnan(value):
                raise CanonicalizationError("NaN is not allowed in canonical documents")
            if math.isinf(value):
                raise CanonicalizationError("Infinity is not allowed in canonical documents")
            if value == int(value):
                return int(value)
            # Non-whole float: normalize via Decimal for deterministic representation
            return Decimal(str(value))
        return value

    if any(not isinstance(key, str) for key in doc.keys()):
        raise ValueError("Document keys must be strings")

    canonical: dict[str, Any] = {}
    for key in sorted(doc.keys()):
        canonical[key] = _canonicalize_value(doc[key], field_name=key)

    return canonical


def document_to_bytes(
    doc: dict[str, Any],
    *,
    scrub_homoglyphs: bool = True,
    sorted_list_keys: set[str] | None = None,
) -> bytes:
    """
    Convert document to canonical byte representation.

    Args:
        doc: Document to convert
        scrub_homoglyphs: Forwarded to :func:`canonicalize_document`.
        sorted_list_keys: Forwarded to :func:`canonicalize_document`.

    Returns:
        Canonical bytes
    """
    canonical = canonicalize_document(
        doc,
        scrub_homoglyphs=scrub_homoglyphs,
        sorted_list_keys=sorted_list_keys,
    )
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
