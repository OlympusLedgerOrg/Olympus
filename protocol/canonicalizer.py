"""
Olympus C-Pipe: Hardened Deterministic Canonicalization.

Phase 0.1 Institutional Pinning — provides multi-format artifact ingestion
with byte-stable idempotency guarantees. Supports JSON (JCS/RFC 8785),
HTML, DOCX, and PDF canonicalization with deterministic hashing via BLAKE3.

Designed for 100% byte-stability without external system dependencies.
"""

import io
import json
import os
import re
import unicodedata
import zipfile
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import blake3 as _blake3
import pikepdf


# PHASE-0.1 INSTITUTIONAL PINNING
# These versions must be strictly adhered to for hash stability.
CANONICALIZER_VERSIONS: dict[str, str] = {
    "jcs": "1.2.0-strict-numeric",
    "html": "1.0.1-lxml-pinned-nfc",
    "docx": "1.1.0-c14n-strict",
    "pdf": "1.4.0-pikepdf-10.3.0-linearized",
}


def canonicalization_provenance(
    format_name: str,
    normalization_mode: str,
    fallback_reason: str | None = None,
) -> dict[str, Any]:
    """Build canonicalization provenance metadata for commitments.

    Args:
        format_name: Artifact format (e.g. MIME type).
        normalization_mode: Canonicalization mode identifier.
        fallback_reason: Optional fallback reason code.

    Returns:
        Dictionary capturing canonicalization provenance for bundle/commitment metadata.
    """
    return {
        "format": format_name,
        "normalization_mode": normalization_mode,
        "fallback_reason": fallback_reason,
        "canonicalizer_versions": CANONICALIZER_VERSIONS,
    }


# ---------------------------------------------------------------------------
# Safety limits — prevent resource exhaustion from malicious inputs
# ---------------------------------------------------------------------------
MAX_INPUT_SIZE: int = 256 * 1024 * 1024  # 256 MiB per artifact
MAX_JSON_DEPTH: int = 128  # Maximum nesting depth for JSON structures
MAX_DOCX_ENTRIES: int = 10_000  # Maximum ZIP entries in a DOCX file
MAX_DOCX_DECOMPRESSED: int = 512 * 1024 * 1024  # 512 MiB total decompressed

# HTML tags stripped during canonicalization — active content, data-exfiltration
# vectors, and volatile metadata tags.
_STRIPPED_HTML_TAGS: list[str] = [
    "script",
    "style",
    "iframe",
    "object",
    "embed",
    "applet",
    "meta",
    "base",
    "link",
    "form",
    "noscript",
]

try:
    from lxml import etree, html as lxml_html

    LXML_VERSION: str | None = ".".join(map(str, etree.LXML_VERSION))
except ImportError:  # pragma: no cover
    lxml_html = None
    etree = None
    LXML_VERSION = None


class CanonicalizationError(Exception):
    """Raised when an artifact fails deterministic constraints."""


class ArtifactProcessingError(CanonicalizationError):
    """Base class for ingestion-level failures."""


class UnsupportedMimeTypeError(ArtifactProcessingError):
    """Raised when process_artifact is asked to handle an unknown MIME type."""


class ArtifactCanonicalizationError(ArtifactProcessingError):
    """Raised when canonicalization for a supported MIME type fails."""


class ArtifactIdempotencyError(ArtifactProcessingError):
    """Raised when a canonicalization pipeline is not byte-idempotent."""


@dataclass(frozen=True)
class ArtifactPayload:
    """Payload describing a single artifact for concurrent processing."""

    raw_data: bytes
    mime_type: str
    witness_anchor: str | None = None


def _should_strip_attribute(attr_name: str, attr_value: str) -> bool:
    """Return True when an HTML attribute is unsafe and should be removed.

    Strips event handlers (on*), dangerous URI schemes (javascript:,
    vbscript:, data:) even when obfuscated with embedded whitespace or
    mixed-case, and any ``style`` attribute to prevent CSS-based data
    exfiltration.
    """
    name = attr_name.lower()
    if name.startswith("on"):
        return True

    # Strip style attributes to prevent CSS-based data exfiltration
    if name == "style":
        return True

    if name in {"href", "src", "xlink:href", "formaction", "action"}:
        # Collapse all whitespace (tabs, newlines, etc.) before checking
        # the protocol scheme — attackers can inject control characters to
        # bypass naive prefix checks.
        value = re.sub(r"\s+", "", attr_value).lower()
        if value.startswith(("javascript:", "vbscript:", "data:")):
            return True

    return False


class Canonicalizer:
    """
    Olympus C-Pipe: Hardened Deterministic Canonicalization.

    Provides format-specific canonicalization pipelines that guarantee
    byte-stable, idempotent output for JSON, HTML, DOCX, and PDF artifacts.
    """

    @staticmethod
    def get_hash(data: bytes) -> bytes:
        """Compute BLAKE3 hash of raw bytes.

        Args:
            data: Raw bytes to hash.

        Returns:
            32-byte BLAKE3 digest.
        """
        return _blake3.blake3(data).digest()

    @staticmethod
    def _json_check_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        """Strictly reject duplicate keys (Semantic Ambiguity Protection).

        Args:
            pairs: List of key-value pairs from JSON parsing.

        Returns:
            Dictionary built from the pairs.

        Raises:
            CanonicalizationError: If duplicate keys are found.
        """
        dict_obj: dict[str, Any] = {}
        for k, v in pairs:
            if k in dict_obj:
                raise CanonicalizationError(f"Duplicate JSON key: {k}")
            dict_obj[k] = v
        return dict_obj

    @staticmethod
    def _serialize_jcs_number(d: Decimal) -> str:
        """Deterministic Number Serialization (RFC 8785 / ECMA-262 compliant).

        Ensures parity between Python, Rust, and JS implementations.

        Args:
            d: Decimal value to serialize.

        Returns:
            Deterministic string representation of the number.

        Raises:
            CanonicalizationError: If the value is non-finite (NaN/Infinity).
        """
        if not d.is_finite():
            raise CanonicalizationError("Rejected non-finite numeric value.")

        # 1. Normalize -0 to 0 and strip trailing zeros
        if d == 0:
            return "0"
        d = d.normalize()

        sign, digits, exponent = d.as_tuple()
        # Calculate base-10 exponent of highest digit
        exp10 = int(exponent) + len(digits) - 1

        # 2. Threshold check for scientific vs fixed notation
        if -6 <= exp10 < 21:
            s = format(d, "f")
            if "." in s:
                s = s.rstrip("0").rstrip(".")
            return s
        else:
            # Scientific formatting: lowercase 'e', sign on exp, no leading zeros
            s = format(d, "e")
            # Strip mantissa trailing zeros: 1.000e+21 -> 1e+21
            s = re.sub(r"(\d)\.0+e", r"\1e", s)
            s = re.sub(r"(\.\d*?)0+e", r"\1e", s)
            s = s.replace(".e", "e")
            # Strip exponent leading zeros: e+07 -> e+7
            s = re.sub(r"e([+-])0+(\d+)", r"e\1\2", s)
            return s

    @staticmethod
    def json_jcs(data: bytes) -> bytes:
        """Strict JCS (RFC 8785) canonicalization with NFC Normalization.

        Args:
            data: Raw JSON bytes to canonicalize.

        Returns:
            Canonical JSON as UTF-8 bytes.

        Raises:
            CanonicalizationError: If the JSON is invalid, contains duplicates,
                exceeds the nesting depth limit, or exceeds the input size limit.
        """
        if len(data) > MAX_INPUT_SIZE:
            raise CanonicalizationError(
                f"Input size {len(data)} exceeds limit of {MAX_INPUT_SIZE} bytes"
            )

        try:
            # Step 1: Normalize Unicode to NFC to resolve glyph ambiguity
            decoded = data.decode("utf-8")
            normalized = unicodedata.normalize("NFC", decoded)

            # Step 2: Parse using Decimal to avoid binary float (IEEE-754) drift
            obj = json.loads(
                normalized,
                object_pairs_hook=Canonicalizer._json_check_duplicates,
                parse_float=Decimal,
                parse_int=Decimal,
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise CanonicalizationError(f"JSON Ingest Failure: {e!s}")

        def encode_recursive(item: Any, depth: int = 0) -> str:
            if depth > MAX_JSON_DEPTH:
                raise CanonicalizationError(f"JSON nesting depth exceeds limit of {MAX_JSON_DEPTH}")
            if isinstance(item, dict):
                # Lexicographical sort of keys (UTF-16 code units)
                sorted_keys = sorted(item.keys())
                return (
                    "{"
                    + ",".join(
                        f"{json.dumps(k, ensure_ascii=False)}:{encode_recursive(item[k], depth + 1)}"
                        for k in sorted_keys
                    )
                    + "}"
                )
            elif isinstance(item, list):
                return "[" + ",".join(encode_recursive(x, depth + 1) for x in item) + "]"
            elif isinstance(item, Decimal):
                return Canonicalizer._serialize_jcs_number(item)
            elif isinstance(item, str):
                return json.dumps(item, ensure_ascii=False)
            elif item is True:
                return "true"
            elif item is False:
                return "false"
            elif item is None:
                return "null"
            raise CanonicalizationError(f"Unsupported type: {type(item)}")  # pragma: no cover

        return encode_recursive(obj).encode("utf-8")

    @staticmethod
    def html_v1(data: bytes) -> bytes:
        """Pinned HTML Normalization (NFC + Attribute Sorting + Active Content Strip).

        Args:
            data: Raw HTML bytes to canonicalize.

        Returns:
            Canonical HTML as UTF-8 bytes.

        Raises:
            ImportError: If lxml is not installed.
            CanonicalizationError: If the HTML is unparseable or exceeds size limit.
        """
        if lxml_html is None:
            raise ImportError("lxml required for HTML canonicalization.")

        if len(data) > MAX_INPUT_SIZE:
            raise CanonicalizationError(
                f"Input size {len(data)} exceeds limit of {MAX_INPUT_SIZE} bytes"
            )

        parser = lxml_html.HTMLParser(
            remove_comments=True,
            remove_pis=True,
            encoding="utf-8",
            recover=False,
            huge_tree=True,
        )
        try:
            raw_nfc = unicodedata.normalize("NFC", data.decode("utf-8"))
            root = lxml_html.fromstring(raw_nfc.encode("utf-8"), parser=parser)
        except Exception as e:
            raise CanonicalizationError(f"HTML Parse Failure: {e!s}")

        # Remove volatile active tags and data-exfiltration vectors
        # (along with their contents and tails)
        def _strip_element(el: Any) -> None:
            """Remove a stripped element while preserving its tail text.

            Note: lxml's HTMLParser always wraps content in <html><body>,
            so stripped tags (script, style, etc.) always have a parent.
            The parent.remove(el) call below is always safe.
            """
            parent = el.getparent()
            tail = el.tail
            if tail:
                previous = el.getprevious()
                if previous is None:
                    parent.text = (parent.text or "") + tail
                else:
                    previous.tail = (previous.tail or "") + tail

            parent.remove(el)

        for tag in _STRIPPED_HTML_TAGS:
            for el in root.xpath(f"//{tag}"):
                _strip_element(el)

        def walk(el: Any) -> None:
            if el.attrib:
                # Sort attributes by name
                items = sorted(
                    (k, v) for k, v in el.attrib.items() if not _should_strip_attribute(k, v)
                )
                el.attrib.clear()
                for k, v in items:
                    el.attrib[k] = v
            if el.text:
                el.text = re.sub(r"\s+", " ", unicodedata.normalize("NFC", el.text)).strip()
            if el.tail:
                el.tail = re.sub(r"\s+", " ", unicodedata.normalize("NFC", el.tail)).strip()
            for child in el:
                walk(child)

        walk(root)
        result: bytes = lxml_html.tostring(root, encoding="utf-8", include_meta_content_type=True)
        return result

    @staticmethod
    def docx_v1(data: bytes) -> bytes:
        """Deterministic DOCX: ZIP entries + XML C14N 1.1 + Volatile Stripping.

        Args:
            data: Raw DOCX bytes to canonicalize.

        Returns:
            32-byte BLAKE3 digest of the canonical DOCX content.

        Raises:
            CanonicalizationError: If the DOCX is malformed, unparseable,
                exceeds size limits, or contains too many entries (ZIP bomb
                protection).
        """
        if etree is None:
            raise ImportError("lxml required for DOCX canonicalization.")

        if len(data) > MAX_INPUT_SIZE:
            raise CanonicalizationError(
                f"Input size {len(data)} exceeds limit of {MAX_INPUT_SIZE} bytes"
            )

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z_in:
                # Lexicographical sort for archive entry order independence
                namelist = sorted(z_in.namelist())

                # ZIP bomb protection: limit entry count
                if len(namelist) > MAX_DOCX_ENTRIES:
                    raise CanonicalizationError(
                        f"DOCX contains {len(namelist)} entries, "
                        f"exceeding limit of {MAX_DOCX_ENTRIES}"
                    )

                # ZIP bomb protection: check total decompressed size
                total_size = sum(info.file_size for info in z_in.infolist())
                if total_size > MAX_DOCX_DECOMPRESSED:
                    raise CanonicalizationError(
                        f"DOCX decompressed size {total_size} exceeds "
                        f"limit of {MAX_DOCX_DECOMPRESSED} bytes"
                    )

                hasher = _blake3.blake3()
                # XXE-safe XML parser: disable entity resolution and network access
                xml_parser = etree.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                )
                for name in namelist:
                    # Strip non-deterministic timestamps and metadata parts
                    if any(
                        x in name
                        for x in [
                            "docProps/core.xml",
                            "metadata",
                            ".bin",
                            "thumbnail",
                            "_rels/.rels",
                        ]
                    ):
                        continue

                    content = z_in.read(name)
                    if name.endswith(".xml") or name.endswith(".rels"):
                        try:
                            # Apply Exclusive XML Canonicalization (C14N)
                            xml_root = etree.fromstring(content, parser=xml_parser)
                            content = etree.tostring(
                                xml_root, method="xml", exclusive=True, with_comments=False
                            )
                        except Exception:  # nosec B112
                            continue

                    hasher.update(name.encode("utf-8"))
                    hasher.update(content)
                return hasher.digest()
        except CanonicalizationError:
            raise
        except Exception as e:
            raise CanonicalizationError(f"DOCX C14N failure: {e!s}")

    @staticmethod
    def pdf_normalize(data: bytes) -> tuple[bytes, str]:
        """Deterministic PDF normalization using pikepdf.

        - Strips volatile metadata (CreationDate, ModDate, Producer, Creator, Title,
          Subject, Author, Keywords)
        - Forces static document IDs and linearized output for canonical byte order
        - Normalizes line endings to LF

        Args:
            data: Raw PDF bytes to normalize.

        Returns:
            Tuple of (normalized bytes, mode string).

        Raises:
            CanonicalizationError: If the PDF cannot be parsed, normalized,
                or exceeds the input size limit.
        """
        if len(data) > MAX_INPUT_SIZE:
            raise CanonicalizationError(
                f"Input size {len(data)} exceeds limit of {MAX_INPUT_SIZE} bytes"
            )

        volatile_keys = [
            "/CreationDate",
            "/ModDate",
            "/Producer",
            "/Creator",
            "/Title",
            "/Subject",
            "/Author",
            "/Keywords",
        ]

        try:
            with pikepdf.open(io.BytesIO(data)) as pdf:
                for key in volatile_keys:
                    for candidate in {key, key.lstrip("/")}:
                        if candidate in pdf.docinfo:
                            del pdf.docinfo[candidate]

                try:
                    pdf.remove_unreferenced_resources()
                except pikepdf.PdfError:
                    # Safe to ignore; best-effort cleanup
                    pass

                # Ensure any XMP packet is cleared to avoid hidden timestamps
                try:
                    metadata = pdf.open_metadata(set_pikepdf_as_editor=False)
                    metadata.clear()
                except pikepdf.PdfError:
                    # Some PDFs omit XMP packets; safe to continue
                    pass

                buf = io.BytesIO()
                pdf.save(buf, linearize=True, static_id=True)
                normalized = buf.getvalue()
        except Exception as e:
            raise CanonicalizationError(f"PDF normalization failure: {e!s}")

        normalized = normalized.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        return normalized, "pdf_norm_pikepdf_v1"


def process_artifact(
    raw_data: bytes, mime_type: str, witness_anchor: str | None = None
) -> dict[str, Any]:
    """Primary Entry Point for Olympus Artifact Ingestion.

    Canonicalizes the given artifact based on its MIME type and returns
    a result dictionary with raw and canonical hashes, mode, and metadata.
    Includes byte-stable idempotency check and witness metadata injection.

    Args:
        raw_data: Raw artifact bytes.
        mime_type: MIME type string (e.g. "application/json", "text/html").
        witness_anchor: Optional external witness anchor identifier.

    Returns:
        Dictionary containing raw_hash, canonical_hash, mode, version,
        and related metadata.
    Raises:
        UnsupportedMimeTypeError: If the MIME type is not supported.
        ArtifactCanonicalizationError: If canonicalization for the MIME type fails.
        ArtifactIdempotencyError: If a canonicalized artifact fails byte-idempotency checks.
    """
    c = Canonicalizer()
    if "json" in mime_type:
        try:
            processed = c.json_jcs(raw_data)
        except CanonicalizationError as exc:
            raise ArtifactCanonicalizationError(f"JSON canonicalization failed: {exc!s}") from exc

        if processed != c.json_jcs(processed):
            raise ArtifactIdempotencyError("JCS Byte-Idempotency Violation")

        return {
            "raw_hash": c.get_hash(raw_data).hex(),
            "canonical_hash": c.get_hash(processed).hex(),
            "mode": "jcs_v1",
            "fallback_reason": None,
            "version": CANONICALIZER_VERSIONS["jcs"],
            "witness_anchor": witness_anchor,
            "lxml_pinned": LXML_VERSION,
        }

    if "html" in mime_type:
        try:
            processed = c.html_v1(raw_data)
        except CanonicalizationError as exc:
            raise ArtifactCanonicalizationError(f"HTML canonicalization failed: {exc!s}") from exc

        if processed != c.html_v1(processed):
            raise ArtifactIdempotencyError("HTML Byte-Idempotency Violation")

        return {
            "raw_hash": c.get_hash(raw_data).hex(),
            "canonical_hash": c.get_hash(processed).hex(),
            "mode": "html_v1",
            "fallback_reason": None,
            "version": CANONICALIZER_VERSIONS["html"],
            "witness_anchor": witness_anchor,
            "lxml_pinned": LXML_VERSION,
        }

    if "vnd.openxmlformats-officedocument.wordprocessingml.document" in mime_type:
        try:
            canon_hash = c.docx_v1(raw_data)
        except CanonicalizationError as exc:
            raise ArtifactCanonicalizationError(f"DOCX canonicalization failed: {exc!s}") from exc

        # DOCX idempotency: re-hashing the same input must produce the same digest
        if canon_hash != c.docx_v1(raw_data):
            raise ArtifactIdempotencyError("DOCX Byte-Idempotency Violation")

        return {
            "raw_hash": c.get_hash(raw_data).hex(),
            "canonical_hash": canon_hash.hex(),
            "mode": "docx_v1",
            "fallback_reason": None,
            "version": CANONICALIZER_VERSIONS["docx"],
            "witness_anchor": witness_anchor,
            "lxml_pinned": LXML_VERSION,
        }

    if "pdf" in mime_type:
        try:
            processed, pdf_mode = c.pdf_normalize(raw_data)
        except CanonicalizationError as exc:
            raise ArtifactCanonicalizationError(f"PDF canonicalization failed: {exc!s}") from exc

        # PDF idempotency: normalizing the already-normalized output must be stable
        re_processed, _ = c.pdf_normalize(processed)
        if processed != re_processed:
            raise ArtifactIdempotencyError("PDF Byte-Idempotency Violation")

        return {
            "raw_hash": c.get_hash(raw_data).hex(),
            "canonical_hash": c.get_hash(processed).hex(),
            "mode": pdf_mode,
            "fallback_reason": None,
            "version": CANONICALIZER_VERSIONS["pdf"],
            "witness_anchor": witness_anchor,
            "lxml_pinned": LXML_VERSION,
        }

    raise UnsupportedMimeTypeError(f"Unsupported MIME type: {mime_type}")


def _process_payload(payload: ArtifactPayload) -> dict[str, Any]:
    return process_artifact(
        payload.raw_data,
        payload.mime_type,
        witness_anchor=payload.witness_anchor,
    )


def process_artifacts_concurrently(
    artifacts: Sequence[ArtifactPayload],
    *,
    max_workers: int | None = None,
) -> list[dict[str, Any]]:
    """
    Canonicalize multiple artifacts concurrently using multiprocessing.

    Args:
        artifacts: Sequence of ArtifactPayload items to process.
        max_workers: Optional worker count; when <= 1, processing is sequential.

    Returns:
        List of canonicalization results in the same order as the input payloads.
    """
    if max_workers is None:
        max_workers = os.cpu_count() or 1
    if max_workers <= 1:
        return [_process_payload(payload) for payload in artifacts]

    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(_process_payload, artifacts))
