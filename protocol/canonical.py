"""
Canonical document representation for Olympus

This module implements deterministic canonicalization of documents to ensure
consistent hashing regardless of superficial formatting differences.

This provides basic structural canonicalization: JSON key sorting, whitespace
normalization, and deterministic byte encoding. For multi-format artifact
ingestion (JCS/RFC 8785, HTML, DOCX, PDF) with version-pinned pipelines,
see protocol/canonicalizer.py instead.

Extended format support (v2.1+):

- **Plain text**: line-ending normalization, Unicode NFC, homoglyph scrubbing,
  trailing-whitespace removal, BOM stripping.
- **XML**: Exclusive XML Canonicalization (C14N) subset — sorted attributes,
  self-closing tag normalization, comment/PI stripping, NFC normalization.
- **CSV/TSV**: deterministic delimiter, quoting, row ordering by canonical
  JSON key, NFC normalization, and BOM stripping.
"""

import csv
import io
import math
import re
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


# ---------------------------------------------------------------------------
# Extended format canonicalization (v2.1+)
# ---------------------------------------------------------------------------

# Maximum sizes to prevent resource exhaustion
_MAX_PLAINTEXT_BYTES: int = 64 * 1024 * 1024  # 64 MiB
_MAX_XML_BYTES: int = 64 * 1024 * 1024  # 64 MiB
_MAX_CSV_BYTES: int = 64 * 1024 * 1024  # 64 MiB
_MAX_CSV_ROWS: int = 1_000_000

# XML processing instruction / comment / DOCTYPE patterns
_XML_PI_RE = re.compile(r"<\?.*?\?>", re.DOTALL)
_XML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_XML_DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)
# Matches <tag ... /> or <tag .../> self-closing tags
_XML_SELF_CLOSE_RE = re.compile(r"<(\w[\w:.-]*)\s*/\s*>")
# Matches opening tags with attributes for sorting
_XML_TAG_ATTRS_RE = re.compile(
    r"<(\w[\w:.-]*)((?:\s+[\w:.-]+\s*=\s*\"[^\"]*\")*)\s*(/?)>"
)
_XML_SINGLE_ATTR_RE = re.compile(r'([\w:.-]+)\s*=\s*"([^"]*)"')


def _strip_bom(text: str) -> str:
    """Strip Unicode BOM (U+FEFF) from start of text."""
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def canonicalize_plaintext(text: str, *, scrub_homoglyphs: bool = True) -> str:
    """Canonicalize plain text for deterministic hashing.

    Produces a deterministic plain-text representation by:

    1. Stripping BOM (U+FEFF).
    2. Normalizing to Unicode NFC.
    3. Converting all line endings to Unix ``\\n``.
    4. Replacing Unicode space-like characters with ASCII space.
    5. Collapsing runs of spaces within each line.
    6. Stripping trailing whitespace from each line.
    7. Removing leading/trailing blank lines.
    8. Optionally scrubbing homoglyphs (default: on).

    Args:
        text: Input plain text.
        scrub_homoglyphs: If ``True`` (default), replace homoglyphs.

    Returns:
        Canonicalized plain text.

    Raises:
        CanonicalizationError: If text exceeds the size limit.
    """
    if len(text.encode("utf-8")) > _MAX_PLAINTEXT_BYTES:
        raise CanonicalizationError(
            f"Plain text exceeds maximum size ({_MAX_PLAINTEXT_BYTES} bytes)"
        )

    # Step 1: Strip BOM
    text = _strip_bom(text)

    # Step 2: NFC normalization
    text = unicodedata.normalize("NFC", text)

    # Step 3: Normalize line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Steps 4–6: per-line normalization
    lines: list[str] = []
    for line in text.split("\n"):
        # Replace Unicode spaces
        line = line.translate(_RESIDUAL_UNICODE_SPACES)
        # Collapse whitespace within line
        line = " ".join(line.split())
        lines.append(line)

    # Step 7: Homoglyph scrubbing (before trimming, to avoid changing structure)
    if scrub_homoglyphs:
        lines = [_scrub_homoglyphs(line) for line in lines]

    # Step 8: Remove leading/trailing blank lines
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()

    return "\n".join(lines)


def canonicalize_plaintext_bytes(
    data: bytes, *, encoding: str = "utf-8", scrub_homoglyphs: bool = True
) -> bytes:
    """Canonicalize plain text bytes for deterministic hashing.

    Args:
        data: Raw text bytes.
        encoding: Source encoding (default UTF-8).
        scrub_homoglyphs: Forwarded to :func:`canonicalize_plaintext`.

    Returns:
        Canonical UTF-8 bytes.
    """
    text = data.decode(encoding)
    return canonicalize_plaintext(text, scrub_homoglyphs=scrub_homoglyphs).encode("utf-8")


def _sort_xml_attributes(match: re.Match[str]) -> str:
    """Sort XML attributes alphabetically within a tag."""
    tag_name = match.group(1)
    attrs_str = match.group(2)
    self_close = match.group(3)

    if not attrs_str.strip():
        if self_close:
            return f"<{tag_name}/>"
        return f"<{tag_name}>"

    attrs = _XML_SINGLE_ATTR_RE.findall(attrs_str)
    sorted_attrs = sorted(attrs, key=lambda a: a[0])
    attr_str = " ".join(f'{name}="{value}"' for name, value in sorted_attrs)

    if self_close:
        return f"<{tag_name} {attr_str}/>"
    return f"<{tag_name} {attr_str}>"


def canonicalize_xml(text: str) -> str:
    """Canonicalize XML text for deterministic hashing.

    Applies a subset of Exclusive XML Canonicalization suitable for
    government document comparison:

    1. Strip BOM.
    2. NFC normalization.
    3. Remove XML processing instructions (``<?...?>``).
    4. Remove comments (``<!--...-->``).
    5. Remove DOCTYPE declarations.
    6. Normalize line endings to ``\\n``.
    7. Sort attributes within each element alphabetically by name.
    8. Normalize self-closing tags to ``<tag/>``.
    9. Collapse inter-tag whitespace to single spaces.
    10. Strip leading/trailing whitespace.

    .. note::
       This is *not* full C14N — it provides deterministic byte output
       for comparing government XML artifacts without requiring an XML
       parser dependency.  For W3C Exclusive XML Canonicalization, use
       lxml-based canonicalization in ``canonicalizer.py``.

    Args:
        text: XML text to canonicalize.

    Returns:
        Canonicalized XML text.

    Raises:
        CanonicalizationError: If text exceeds the size limit.
    """
    if len(text.encode("utf-8")) > _MAX_XML_BYTES:
        raise CanonicalizationError(
            f"XML text exceeds maximum size ({_MAX_XML_BYTES} bytes)"
        )

    # Step 1–2: BOM + NFC
    text = _strip_bom(text)
    text = unicodedata.normalize("NFC", text)

    # Step 3–5: Remove PIs, comments, DOCTYPE
    text = _XML_PI_RE.sub("", text)
    text = _XML_COMMENT_RE.sub("", text)
    text = _XML_DOCTYPE_RE.sub("", text)

    # Step 6: Line endings
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Step 7: Sort attributes within tags
    text = _XML_TAG_ATTRS_RE.sub(_sort_xml_attributes, text)

    # Step 8: Normalize self-closing tags (with internal whitespace)
    text = _XML_SELF_CLOSE_RE.sub(r"<\1/>", text)

    # Step 9: Collapse inter-element whitespace
    lines = [" ".join(line.split()) for line in text.split("\n")]
    text = "\n".join(line for line in lines if line)

    # Step 10: Strip leading/trailing whitespace
    return text.strip()


def canonicalize_xml_bytes(data: bytes, *, encoding: str = "utf-8") -> bytes:
    """Canonicalize XML bytes for deterministic hashing.

    Args:
        data: Raw XML bytes.
        encoding: Source encoding (default UTF-8).

    Returns:
        Canonical UTF-8 bytes.
    """
    text = data.decode(encoding)
    return canonicalize_xml(text).encode("utf-8")


def canonicalize_csv(
    text: str,
    *,
    delimiter: str = ",",
    sort_rows: bool = True,
    has_header: bool = True,
) -> str:
    """Canonicalize CSV/TSV text for deterministic hashing.

    Produces a deterministic CSV representation:

    1. Strip BOM (U+FEFF).
    2. NFC normalization of all cell values.
    3. Normalize line endings to ``\\n``.
    4. Parse with Python's csv module (handles quoting edge cases).
    5. Optionally sort data rows (header stays in place).
    6. Re-serialize with deterministic quoting (``QUOTE_MINIMAL``),
       comma delimiter, and Unix line endings.

    Args:
        text: Input CSV/TSV text.
        delimiter: Field delimiter (default: comma).
        sort_rows: Whether to sort data rows for deterministic ordering
            (default: ``True``). The sort key is the canonical JSON
            representation of each row.
        has_header: Whether the first row is a header (default: ``True``).
            If ``True`` and ``sort_rows`` is ``True``, the header stays
            in place and only data rows are sorted.

    Returns:
        Canonicalized CSV text.

    Raises:
        CanonicalizationError: If text exceeds size/row limits or is empty.
    """
    if len(text.encode("utf-8")) > _MAX_CSV_BYTES:
        raise CanonicalizationError(
            f"CSV text exceeds maximum size ({_MAX_CSV_BYTES} bytes)"
        )

    # Step 1–3: BOM, NFC, line endings
    text = _strip_bom(text)
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Step 4: Parse
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows: list[list[str]] = []
    for row in reader:
        if len(rows) >= _MAX_CSV_ROWS:
            raise CanonicalizationError(
                f"CSV exceeds maximum row count ({_MAX_CSV_ROWS})"
            )
        # NFC-normalize each cell and strip whitespace
        rows.append([unicodedata.normalize("NFC", cell.strip()) for cell in row])

    if not rows:
        raise CanonicalizationError("CSV is empty")

    # Step 5: Optionally sort data rows
    if sort_rows:
        if has_header and len(rows) > 1:
            header = rows[0]
            data = rows[1:]
            data.sort(key=lambda r: canonical_json_encode(r))
            rows = [header] + data
        elif not has_header:
            rows.sort(key=lambda r: canonical_json_encode(r))

    # Step 6: Re-serialize with deterministic settings
    output = io.StringIO()
    writer = csv.writer(
        output,
        delimiter=",",
        quoting=csv.QUOTE_MINIMAL,
        lineterminator="\n",
    )
    writer.writerows(rows)
    return output.getvalue().rstrip("\n")


def canonicalize_csv_bytes(
    data: bytes,
    *,
    encoding: str = "utf-8",
    delimiter: str = ",",
    sort_rows: bool = True,
    has_header: bool = True,
) -> bytes:
    """Canonicalize CSV/TSV bytes for deterministic hashing.

    Args:
        data: Raw CSV/TSV bytes.
        encoding: Source encoding (default UTF-8).
        delimiter: Forwarded to :func:`canonicalize_csv`.
        sort_rows: Forwarded to :func:`canonicalize_csv`.
        has_header: Forwarded to :func:`canonicalize_csv`.

    Returns:
        Canonical UTF-8 bytes.
    """
    text = data.decode(encoding)
    return canonicalize_csv(
        text, delimiter=delimiter, sort_rows=sort_rows, has_header=has_header
    ).encode("utf-8")
