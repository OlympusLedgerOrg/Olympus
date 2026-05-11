"""
Canonical document representation for Olympus

This module implements deterministic canonicalization of documents to ensure
consistent hashing regardless of superficial formatting differences.

This provides basic structural canonicalization: JSON key sorting, Unicode
normalization, numeric normalization, and deterministic byte encoding. String
whitespace is preserved in the cryptographic document hash path. For
multi-format artifact
ingestion (JCS/RFC 8785, HTML, DOCX, PDF) with version-pinned pipelines,
see protocol/canonicalizer.py instead.

Extended format support (v2.1+):

- **Plain text**: line-ending normalization, Unicode NFC, Unicode space
  separator normalization, trailing-whitespace removal, BOM stripping.
- **XML**: Canonical XML 2.0 via lxml (primary path) with a regex-based
  fallback — sorted attributes, comment/PI stripping, NFC normalization.
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


try:
    from lxml import etree as _lxml_etree

    _LXML_AVAILABLE = True
except ImportError:  # pragma: no cover
    _LXML_AVAILABLE = False
    _lxml_etree = None


# Unicode space separators that should be mapped to ASCII space.  These are
# Unicode space characters that NFC preserves as semantically distinct (and
# that NFKC would otherwise fold).  Defined at module scope so the canonical/
# hashing hot path does not allocate a new mapping per call.
#
# This table only normalizes whitespace.  It must NOT be extended with
# compatibility glyph folding (e.g. ``¹`` → ``1``, ``Ａ`` → ``A``,
# ``Ⅳ`` → ``IV``, ``№`` → ``No``); those characters must stay distinct in
# committed content hashes.
_UNICODE_SPACE_TRANSLATION = str.maketrans(
    {
        "\u00a0": " ",  # NO-BREAK SPACE
        "\u1680": " ",  # OGHAM SPACE MARK
        "\u2000": " ",  # EN QUAD
        "\u2001": " ",  # EM QUAD
        "\u2002": " ",  # EN SPACE
        "\u2003": " ",  # EM SPACE
        "\u2004": " ",  # THREE-PER-EM SPACE
        "\u2005": " ",  # FOUR-PER-EM SPACE
        "\u2006": " ",  # SIX-PER-EM SPACE
        "\u2007": " ",  # FIGURE SPACE
        "\u2008": " ",  # PUNCTUATION SPACE
        "\u2009": " ",  # THIN SPACE
        "\u200a": " ",  # HAIR SPACE
        "\u202f": " ",  # NARROW NO-BREAK SPACE
        "\u205f": " ",  # MEDIUM MATHEMATICAL SPACE
        "\u3000": " ",  # IDEOGRAPHIC SPACE
    }
)

# Backwards-compatible alias for the historical name.  Both names refer to
# the same translation table; prefer ``_UNICODE_SPACE_TRANSLATION`` in new
# code.
_RESIDUAL_UNICODE_SPACES = _UNICODE_SPACE_TRANSLATION


CANONICAL_VERSION = "canonical_v2"
"""Current canonical format version.

Version history:

- ``canonical_v1`` — original format.  Merkle trees used CT-style lone-node
  promotion (no rehash for odd-count levels) and numeric values in documents
  were passed through without normalization.
- ``canonical_v2`` — (current) lone Merkle nodes are self-paired instead of
  promoted, preventing batching-boundary root divergence.  Float values are
  normalised to ``int`` when whole, or to ``Decimal`` otherwise; NaN / Inf
  are rejected.  The optional Unicode-space normalization hook only maps
  Unicode space separators to ASCII spaces and does not compatibility-fold
  payload text.

Cross-version verification: the verifier accepts proofs generated under any
version listed in :data:`SUPPORTED_VERSIONS`.  ``canonical_v1`` proofs emit
a deprecation warning.  A full migration layer is tracked separately.
"""

SUPPORTED_VERSIONS = ["canonical_v1", "canonical_v2"]
"""All canonical versions the verifier is willing to accept."""


COMMIT_CANONICAL_VERSION = "canonical_commit_v1"
"""Canonicalization mode used for document commitments and Merkle leaves.

This mode uses the same structural rules as :data:`CANONICAL_VERSION` but
disables Unicode-space normalization before encoding bytes.  It is intentionally
a separate provenance label so verifiers do not replay the display/search
canonicalizer and derive different commitment bytes.
"""


def _normalize_unicode_spaces(text: str) -> str:
    """Normalize Unicode space separators to ASCII spaces.

    This intentionally does **not** compatibility-fold glyphs such as
    ``¹``, ``Ａ``, ``Ⅳ``, ``K``, ``№``.  Those characters must remain
    distinct for committed content hashes; folding them would let two
    semantically distinct documents collide in the ledger.

    Args:
        text: Input string (should already be NFC-normalised).

    Returns:
        String with recognized Unicode space separators replaced by ASCII
        ``" "``.
    """
    return text.translate(_UNICODE_SPACE_TRANSLATION)


# Backwards-compatible alias for the historical name.  The behavior is now
# Unicode-space normalization only, not homoglyph folding.
_scrub_homoglyphs = _normalize_unicode_spaces


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
    normalize_unicode_spaces: bool = True,
    scrub_homoglyphs: bool | None = None,
    sorted_list_keys: set[str] | None = None,
) -> dict[str, Any]:
    """
    Canonicalize a document structure.

    This ensures deterministic ordering and formatting.

    Args:
        doc: Document to canonicalize
        normalize_unicode_spaces: If ``True`` (default), replace recognized
            Unicode space separators in string values with ASCII space.
            Compatibility glyphs (e.g. ``¹``, ``Ａ``, ``Ⅳ``, ``№``) are
            preserved because folding them is non-injective for content
            hashes.
        scrub_homoglyphs: Backward-compatible alias for the old parameter
            name. The behavior is now Unicode-space normalization only, not
            homoglyph folding.
        sorted_list_keys: Optional set of field names whose array values
            should be sorted for canonical ordering.  Fields not in this set
            preserve their original order.  Sorting uses the canonical JSON
            representation of each element so it is deterministic across
            types.  Pass ``None`` (default) to skip all list sorting.

    Returns:
        Canonicalized document
    """
    if scrub_homoglyphs is not None:
        normalize_unicode_spaces = scrub_homoglyphs
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
                normalize_unicode_spaces=normalize_unicode_spaces,
                sorted_list_keys=sorted_list_keys,
            )
        if isinstance(value, list):
            items = [_canonicalize_value(item) for item in value]
            if field_name in _sorted_keys:
                items = sorted(items, key=_sort_key)
            return items
        if isinstance(value, str):
            # Preserve exact string values in the cryptographic hash path.
            # Whitespace normalization (trimming, collapsing) is intentionally
            # NOT applied here because it would erase meaningful differences —
            # e.g. {"0": " "} and {"0": ""} must produce distinct hashes.
            # Business-level whitespace normalisation must be done *before*
            # calling canonicalize_document(), keeping policy separate from
            # cryptographic commitments.
            if normalize_unicode_spaces:
                return _normalize_unicode_spaces(value)
            return value
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
    normalize_unicode_spaces: bool = True,
    scrub_homoglyphs: bool | None = None,
    sorted_list_keys: set[str] | None = None,
) -> bytes:
    """
    Convert document to canonical byte representation.

    Args:
        doc: Document to convert
        normalize_unicode_spaces: Forwarded to :func:`canonicalize_document`.
        scrub_homoglyphs: Backward-compatible alias for
            ``normalize_unicode_spaces``. The behavior is now Unicode-space
            normalization only, not homoglyph folding.
        sorted_list_keys: Forwarded to :func:`canonicalize_document`.

    Returns:
        Canonical bytes
    """
    if scrub_homoglyphs is not None:
        normalize_unicode_spaces = scrub_homoglyphs
    canonical = canonicalize_document(
        doc,
        normalize_unicode_spaces=normalize_unicode_spaces,
        sorted_list_keys=sorted_list_keys,
    )
    json_str = canonicalize_json(canonical)
    return json_str.encode("utf-8")


def canonicalize_for_commit(doc: dict[str, Any]) -> dict[str, Any]:
    """Compatibility-preserving canonicalization for cryptographic commitment.

    Identical to :func:`canonicalize_document` but with the optional
    Unicode-space normalization disabled.  The space-only mapping is still
    non-injective (it collapses several distinct space codepoints to ASCII
    ``" "``), so the commit path skips it to keep distinct payload bytes
    distinct.

    This is not a raw byte-injective transform: NFC Unicode normalization and
    numeric normalization are still applied, so canonically equivalent spellings
    such as ``"café"`` and ``"cafe\u0301"`` intentionally commit to the same
    bytes.

    Use this function everywhere a hash or Merkle leaf is derived from document
    content.  Use :func:`canonicalize_document` only for display or comparison.
    """
    return canonicalize_document(doc, normalize_unicode_spaces=False)


def document_to_commit_bytes(doc: dict[str, Any]) -> bytes:
    """Convert a document to its canonical byte representation for commitment.

    Equivalent to ``document_to_bytes(doc, normalize_unicode_spaces=False)``
    but named explicitly for the commit path so that call sites make their
    intent clear.  Unicode-space normalization is disabled to preserve every
    distinct payload codepoint — see :func:`canonicalize_for_commit`.
    """
    return document_to_bytes(doc, normalize_unicode_spaces=False)


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
_XML_TAG_ATTRS_RE = re.compile(r"<(\w[\w:.-]*)((?:\s+[\w:.-]+\s*=\s*\"[^\"]*\")*)\s*(/?)>")
_XML_SINGLE_ATTR_RE = re.compile(r'([\w:.-]+)\s*=\s*"([^"]*)"')


def _strip_bom(text: str) -> str:
    """Strip Unicode BOM (U+FEFF) from start of text."""
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def _canonicalize_xml_lxml(text: str) -> str:
    """Canonicalize XML using lxml's Canonical XML 2.0 (no comments).

    This is the primary path when lxml is available (it is an unconditional
    dependency).  It correctly handles CDATA sections, namespace prefixes,
    default namespace declarations, and attribute value entities — all cases
    that the hand-written regex pipeline handles incorrectly or not at all.

    Steps applied before handing to lxml:
    1. Strip BOM.
    2. NFC normalize.
    3. Parse with XXE-safe parser (resolve_entities=False, no_network=True).
    4. Serialize with C14N 2.0: canonical attribute order, no comments,
       explicit empty elements (no self-closing shorthand in the output).

    Args:
        text: XML text to canonicalize.

    Returns:
        Canonicalized XML as a UTF-8 decoded string.

    Raises:
        CanonicalizationError: If lxml parse or serialization fails.
    """
    text = _strip_bom(text)
    text = unicodedata.normalize("NFC", text)
    try:
        parser = _lxml_etree.XMLParser(
            resolve_entities=False,  # block XXE
            no_network=True,  # no remote DTD/schema fetch
            load_dtd=False,  # never load any DTD
            dtd_validation=False,  # never validate against DTD
            remove_comments=True,
            remove_pis=True,
        )
        root = _lxml_etree.fromstring(text.encode("utf-8"), parser=parser)
        canonical_bytes: bytes = _lxml_etree.tostring(
            root,
            method="c14n2",
            strip_text=False,
            with_comments=False,
        )
        return canonical_bytes.decode("utf-8")
    except Exception as exc:
        raise CanonicalizationError(f"XML C14N 2.0 failed: {exc}") from exc


def canonicalize_plaintext(
    text: str,
    *,
    normalize_unicode_spaces: bool = True,
    scrub_homoglyphs: bool | None = None,
) -> str:
    """Canonicalize plain text for deterministic hashing.

    Produces a deterministic plain-text representation by:

    1. Stripping BOM (U+FEFF).
    2. Normalizing to Unicode NFC.
    3. Converting all line endings to Unix ``\\n``.
    4. Optionally mapping recognized Unicode space separators to ASCII space
       (gated by ``normalize_unicode_spaces``).
    5. Collapsing runs of whitespace within each line — this is a plaintext
       mode behavior and uses Python's :py:meth:`str.split`, which collapses
       any Unicode whitespace, regardless of the flag above.
    6. Stripping trailing whitespace from each line.
    7. Removing leading/trailing blank lines.

    The optional explicit Unicode-space translation in step 4 only normalizes
    *space separators* to ASCII space.  It never compatibility-folds glyphs
    (``¹`` stays ``¹``, ``Ａ`` stays ``Ａ``).

    Args:
        text: Input plain text.
        normalize_unicode_spaces: If ``True`` (default), apply explicit
            Unicode space-separator translation in step 4.  Setting this to
            ``False`` skips the explicit translation table; note that step 5
            (whitespace collapse via :py:meth:`str.split`) still runs
            because it is part of plaintext canonicalization.
        scrub_homoglyphs: Backward-compatible alias for the old parameter
            name.  The behavior is now Unicode-space normalization only.

    Returns:
        Canonicalized plain text.

    Raises:
        CanonicalizationError: If text exceeds the size limit.
    """
    if scrub_homoglyphs is not None:
        normalize_unicode_spaces = scrub_homoglyphs
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

    # Steps 4–6: per-line normalization.  The explicit Unicode-space
    # translation is gated by the flag so callers can opt out; whitespace
    # collapse remains part of plaintext mode in either case.
    lines: list[str] = []
    for line in text.split("\n"):
        if normalize_unicode_spaces:
            line = _normalize_unicode_spaces(line)
        # Collapse whitespace within line
        line = " ".join(line.split())
        lines.append(line)

    # Step 7: Remove leading/trailing blank lines
    while lines and not lines[0]:
        lines.pop(0)
    while lines and not lines[-1]:
        lines.pop()

    return "\n".join(lines)


def canonicalize_plaintext_bytes(
    data: bytes,
    *,
    encoding: str = "utf-8",
    normalize_unicode_spaces: bool = True,
    scrub_homoglyphs: bool | None = None,
) -> bytes:
    """Canonicalize plain text bytes for deterministic hashing.

    Args:
        data: Raw text bytes.
        encoding: Source encoding (default UTF-8).
        normalize_unicode_spaces: Forwarded to :func:`canonicalize_plaintext`.
        scrub_homoglyphs: Backward-compatible alias for
            ``normalize_unicode_spaces``.

    Returns:
        Canonical UTF-8 bytes.
    """
    if scrub_homoglyphs is not None:
        normalize_unicode_spaces = scrub_homoglyphs
    text = data.decode(encoding)
    return canonicalize_plaintext(
        text,
        normalize_unicode_spaces=normalize_unicode_spaces,
    ).encode("utf-8")


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

    Primary path (when lxml is available - the default): uses lxml's C14N 2.0
    implementation which correctly handles CDATA sections, namespace prefixes,
    default namespace declarations, and attribute-value entities.

    Fallback (lxml unavailable): applies a regex-based subset of Exclusive XML
    Canonicalization sufficient for simple government XML artifacts.  This path
    is retained for environments where lxml cannot be installed; it does *not*
    guarantee full C14N compliance.

    The lxml path performs:
    1. Strip BOM.
    2. NFC normalization.
    3. Parse with an XXE-safe parser (resolve_entities=False, no_network=True).
    4. Serialize with W3C C14N 2.0 (canonical attribute order, comments stripped,
       processing instructions stripped).

    The fallback path applies the same sequence that was previously the only
    implementation (regex-based PI/comment/DOCTYPE removal + attribute sorting).

    Args:
        text: XML text to canonicalize.

    Returns:
        Canonicalized XML text.

    Raises:
        CanonicalizationError: If text exceeds the size limit or parsing fails.
    """
    if len(text.encode("utf-8")) > _MAX_XML_BYTES:
        raise CanonicalizationError(f"XML text exceeds maximum size ({_MAX_XML_BYTES} bytes)")

    # Primary path: lxml Canonical XML 2.0 (safe parser, no XXE).
    if _LXML_AVAILABLE:
        return _canonicalize_xml_lxml(text)

    # Fallback: regex-based subset (lxml not installed)
    # Step 1-2: BOM + NFC
    text = _strip_bom(text)
    text = unicodedata.normalize("NFC", text)

    # Step 3-5: Remove PIs, comments, DOCTYPE
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
        raise CanonicalizationError(f"CSV text exceeds maximum size ({_MAX_CSV_BYTES} bytes)")

    # Step 1–3: BOM, NFC, line endings
    text = _strip_bom(text)
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Step 4: Parse
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows: list[list[str]] = []
    for row in reader:
        if len(rows) >= _MAX_CSV_ROWS:
            raise CanonicalizationError(f"CSV exceeds maximum row count ({_MAX_CSV_ROWS})")
        # NFC-normalize each cell and strip whitespace
        rows.append([unicodedata.normalize("NFC", cell.strip()) for cell in row])

    if not rows:
        raise CanonicalizationError("CSV is empty")

    # Step 5: Optionally sort data rows
    if sort_rows:
        if has_header and len(rows) > 1:
            header = rows[0]
            data = rows[1:]
            data.sort(key=canonical_json_encode)
            rows = [header] + data
        elif not has_header:
            rows.sort(key=canonical_json_encode)

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
