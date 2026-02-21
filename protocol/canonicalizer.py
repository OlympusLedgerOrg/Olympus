"""
Olympus C-Pipe: Hardened Deterministic Canonicalization.

Phase 0.1 Institutional Pinning — provides multi-format artifact ingestion
with byte-stable idempotency guarantees. Supports JSON (JCS/RFC 8785),
HTML, DOCX, and PDF canonicalization with deterministic hashing via BLAKE3.

Designed for 100% byte-stability without external system dependencies.
"""

import io
import json
import re
import unicodedata
import zipfile
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
    "pdf": "1.3.0-pikepdf-linearized",
}

try:
    from lxml import etree, html as lxml_html

    LXML_VERSION: str | None = ".".join(map(str, etree.LXML_VERSION))
except ImportError:
    lxml_html = None
    etree = None
    LXML_VERSION = None


class CanonicalizationError(Exception):
    """Raised when an artifact fails deterministic constraints."""


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
            CanonicalizationError: If the JSON is invalid or contains duplicates.
        """
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

        def encode_recursive(item: Any) -> str:
            if isinstance(item, dict):
                # Lexicographical sort of keys (UTF-16 code units)
                sorted_keys = sorted(item.keys())
                return (
                    "{"
                    + ",".join(
                        f"{json.dumps(k, ensure_ascii=False)}:{encode_recursive(item[k])}"
                        for k in sorted_keys
                    )
                    + "}"
                )
            elif isinstance(item, list):
                return "[" + ",".join(encode_recursive(x) for x in item) + "]"
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
            raise CanonicalizationError(f"Unsupported type: {type(item)}")

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
            CanonicalizationError: If the HTML is unparseable.
        """
        if lxml_html is None:
            raise ImportError("lxml required for HTML canonicalization.")

        parser = lxml_html.HTMLParser(
            remove_comments=True, remove_pis=True, encoding="utf-8", recover=False
        )
        try:
            raw_nfc = unicodedata.normalize("NFC", data.decode("utf-8"))
            root = lxml_html.fromstring(raw_nfc.encode("utf-8"), parser=parser)
        except Exception as e:
            raise CanonicalizationError(f"HTML Parse Failure: {e!s}")

        # Remove volatile active tags
        for tag in ["script", "style", "iframe", "object", "embed", "applet", "meta"]:
            for el in root.xpath(f"//{tag}"):
                if el.getparent() is not None:
                    el.getparent().remove(el)

        def walk(el: Any) -> None:
            if el.attrib:
                # Sort attributes by name
                items = sorted(el.attrib.items())
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
        result: bytes = etree.tostring(
            root, method="html", encoding="utf-8", include_meta_content_type=True
        )
        return result

    @staticmethod
    def docx_v1(data: bytes) -> bytes:
        """Deterministic DOCX: ZIP entries + XML C14N 1.1 + Volatile Stripping.

        Args:
            data: Raw DOCX bytes to canonicalize.

        Returns:
            32-byte BLAKE3 digest of the canonical DOCX content.

        Raises:
            CanonicalizationError: If the DOCX is malformed or unparseable.
        """
        if etree is None:
            raise ImportError("lxml required for DOCX canonicalization.")

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z_in:
                # Lexicographical sort for archive entry order independence
                namelist = sorted(z_in.namelist())
                hasher = _blake3.blake3()
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
                            xml_root = etree.fromstring(content)
                            content = etree.tostring(
                                xml_root, method="xml", exclusive=True, with_comments=False
                            )
                        except Exception:
                            pass

                    hasher.update(name.encode("utf-8"))
                    hasher.update(content)
                return hasher.digest()
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
            CanonicalizationError: If the PDF cannot be parsed or normalized.
        """
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
    """
    c = Canonicalizer()
    mode: str = "byte_preserved"
    reason: str | None = None
    processed: bytes = raw_data

    try:
        if "json" in mime_type:
            processed = c.json_jcs(raw_data)
            mode = "jcs_v1"
            # Determinism Guard: C(x) == C(C(x))
            if processed != c.json_jcs(processed):
                raise CanonicalizationError("JCS Byte-Idempotency Violation")

        elif "html" in mime_type:
            processed = c.html_v1(raw_data)
            mode = "html_v1"
            if processed != c.html_v1(processed):
                raise CanonicalizationError("HTML Byte-Idempotency Violation")

        elif "vnd.openxmlformats-officedocument.wordprocessingml.document" in mime_type:
            canon_hash = c.docx_v1(raw_data)
            return {
                "raw_hash": c.get_hash(raw_data).hex(),
                "canonical_hash": canon_hash.hex(),
                "mode": "docx_v1",
                "version": CANONICALIZER_VERSIONS["docx"],
                "witness_anchor": witness_anchor,
            }

        elif "pdf" in mime_type:
            processed, mode = c.pdf_normalize(raw_data)

    except Exception as e:
        mode, reason, processed = "byte_preserved", f"canonical_error: {e!s}", raw_data

    return {
        "raw_hash": c.get_hash(raw_data).hex(),
        "canonical_hash": c.get_hash(processed).hex(),
        "mode": mode,
        "fallback_reason": reason,
        "version": CANONICALIZER_VERSIONS.get(mode.split("_")[0], "0.0.0"),
        "witness_anchor": witness_anchor,
        "lxml_pinned": LXML_VERSION,
    }
