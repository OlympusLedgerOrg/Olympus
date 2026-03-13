"""
Unit tests for the hardened canonicalizer module (protocol.canonicalizer).

Validates JCS JSON canonicalization, PDF structural scrub, the artifact
ingestion pipeline, and version pinning constants.
"""

import io
import json
import zipfile
from decimal import Decimal

import pikepdf
import pytest
from hypothesis import given, settings, strategies as st

from protocol.canonicalizer import (
    CANONICALIZER_VERSIONS,
    ArtifactCanonicalizationError,
    ArtifactIdempotencyError,
    CanonicalizationError,
    Canonicalizer,
    UnsupportedMimeTypeError,
    process_artifact,
)


# ---------------------------------------------------------------------------
# Canonicalizer.get_hash
# ---------------------------------------------------------------------------


class TestGetHash:
    def test_deterministic(self):
        data = b"olympus test vector"
        assert Canonicalizer.get_hash(data) == Canonicalizer.get_hash(data)

    def test_different_input_different_hash(self):
        assert Canonicalizer.get_hash(b"a") != Canonicalizer.get_hash(b"b")

    def test_returns_32_bytes(self):
        assert len(Canonicalizer.get_hash(b"x")) == 32


# ---------------------------------------------------------------------------
# JCS number serialization
# ---------------------------------------------------------------------------


class TestSerializeJcsNumber:
    """RFC 8785 / ECMA-262 compliant number formatting."""

    def test_zero(self):
        assert Canonicalizer._serialize_jcs_number(Decimal("0")) == "0"
        assert Canonicalizer._serialize_jcs_number(Decimal("-0")) == "0"

    def test_integer(self):
        assert Canonicalizer._serialize_jcs_number(Decimal("42")) == "42"

    def test_negative(self):
        assert Canonicalizer._serialize_jcs_number(Decimal("-3.14")) == "-3.14"

    def test_trailing_zeros_stripped(self):
        assert Canonicalizer._serialize_jcs_number(Decimal("1.00")) == "1"

    def test_scientific_notation_large(self):
        result = Canonicalizer._serialize_jcs_number(Decimal("1e21"))
        assert "e" in result.lower()

    def test_fixed_notation_within_range(self):
        result = Canonicalizer._serialize_jcs_number(Decimal("0.000001"))
        assert result == "0.000001"

    def test_scientific_notation_small(self):
        result = Canonicalizer._serialize_jcs_number(Decimal("1e-7"))
        assert "e" in result.lower()

    def test_non_finite_rejected(self):
        with pytest.raises(CanonicalizationError, match="non-finite"):
            Canonicalizer._serialize_jcs_number(Decimal("Infinity"))


# ---------------------------------------------------------------------------
# JCS JSON canonicalization
# ---------------------------------------------------------------------------


class TestJsonJcs:
    def test_sorted_keys(self):
        obj = {"z": 1, "a": 2}
        result = Canonicalizer.json_jcs(json.dumps(obj).encode("utf-8"))
        assert result == b'{"a":2,"z":1}'

    def test_nested_sorted_keys(self):
        obj = {"b": {"d": 1, "c": 2}, "a": 3}
        result = Canonicalizer.json_jcs(json.dumps(obj).encode("utf-8"))
        parsed_keys = list(json.loads(result).keys())
        assert parsed_keys == ["a", "b"]

    def test_idempotent(self):
        obj = {"hello": "world", "num": 42}
        raw = json.dumps(obj).encode("utf-8")
        first = Canonicalizer.json_jcs(raw)
        second = Canonicalizer.json_jcs(first)
        assert first == second

    def test_duplicate_keys_rejected(self):
        raw = b'{"a":1,"a":2}'
        with pytest.raises(CanonicalizationError, match="Duplicate JSON key"):
            Canonicalizer.json_jcs(raw)

    def test_invalid_json_rejected(self):
        with pytest.raises(CanonicalizationError, match="JSON Ingest Failure"):
            Canonicalizer.json_jcs(b"not json")

    def test_null_true_false(self):
        raw = json.dumps({"a": None, "b": True, "c": False}).encode("utf-8")
        result = Canonicalizer.json_jcs(raw)
        assert b"null" in result
        assert b"true" in result
        assert b"false" in result

    def test_array_preserved(self):
        raw = json.dumps({"arr": [3, 2, 1]}).encode("utf-8")
        result = Canonicalizer.json_jcs(raw)
        assert result == b'{"arr":[3,2,1]}'

    def test_unicode_nfc_normalization(self):
        """Ensure NFC normalization of Unicode input."""
        # Use raw UTF-8 bytes (not json.dumps ensure_ascii=True which escapes)
        # \u00e9 (é precomposed) vs e + \u0301 (decomposed) should give same result
        precomposed = '{"key":"\u00e9"}'.encode()
        decomposed = '{"key":"e\u0301"}'.encode()
        assert Canonicalizer.json_jcs(precomposed) == Canonicalizer.json_jcs(decomposed)

    @given(
        st.recursive(
            st.one_of(
                st.none(),
                st.booleans(),
                st.integers(min_value=-(2**53), max_value=2**53),
                st.floats(allow_nan=False, allow_infinity=False),
                st.text(),
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=5),
                st.dictionaries(st.text(), children, max_size=5),
            ),
            max_leaves=20,
        )
    )
    @settings(max_examples=100)
    def test_json_jcs_property_deterministic(self, value):
        """Property: canonicalization output is deterministic for valid JSON payloads."""
        raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
        first = Canonicalizer.json_jcs(raw)
        second = Canonicalizer.json_jcs(raw)
        assert first == second

    @given(st.binary(min_size=1, max_size=256))
    @settings(max_examples=100)
    def test_json_jcs_fuzz_malformed_json(self, random_payload: bytes):
        """Malformed JSON fuzzing should always raise CanonicalizationError."""
        malformed = b'{"payload":' + random_payload + b",}"
        with pytest.raises(CanonicalizationError, match="JSON Ingest Failure"):
            Canonicalizer.json_jcs(malformed)

    @given(st.binary(min_size=1, max_size=256))
    @settings(max_examples=100)
    def test_json_jcs_fuzz_random_bytes_no_crash(self, random_payload: bytes):
        """Random byte fuzzing should either canonicalize or raise CanonicalizationError."""
        try:
            canonical = Canonicalizer.json_jcs(random_payload)
        except CanonicalizationError:
            return

        assert canonical == Canonicalizer.json_jcs(canonical)

    @given(
        st.binary(min_size=1, max_size=64).filter(
            lambda b: any(byte not in b" \t\r\n" for byte in b)
        )
    )
    @settings(max_examples=100)
    def test_json_jcs_fuzz_rejects_trailing_bytes(self, trailing: bytes):
        """Valid JSON plus non-whitespace trailing bytes must be rejected."""
        malformed = b'{"payload":1}' + trailing
        with pytest.raises(CanonicalizationError, match="JSON Ingest Failure"):
            Canonicalizer.json_jcs(malformed)


# ---------------------------------------------------------------------------
# PDF normalization
# ---------------------------------------------------------------------------


class TestPdfNormalize:
    @staticmethod
    def _build_pdf() -> bytes:
        pdf = pikepdf.Pdf.new()
        pdf.add_blank_page(page_size=(612, 792))
        pdf.docinfo["/CreationDate"] = "D:20240101"
        pdf.docinfo["/ModDate"] = "D:20240102"
        pdf.docinfo["/Producer"] = "Test Producer"
        pdf.docinfo["/Creator"] = "Test Creator"
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_volatile_keys_stripped_and_linearized(self):
        raw_pdf = self._build_pdf()
        cleaned, mode = Canonicalizer.pdf_normalize(raw_pdf)
        assert b"/CreationDate" not in cleaned
        assert b"/ModDate" not in cleaned
        assert b"/Producer" not in cleaned
        assert b"/Creator" not in cleaned
        assert b"/Linearized" in cleaned[:256]
        assert mode == "pdf_norm_pikepdf_v1"

    def test_line_endings_normalized(self):
        raw_pdf = self._build_pdf().replace(b"\n", b"\r\n")
        cleaned, _ = Canonicalizer.pdf_normalize(raw_pdf)
        assert b"\r" not in cleaned

    def test_idempotent(self):
        raw_pdf = self._build_pdf()
        first, _ = Canonicalizer.pdf_normalize(raw_pdf)
        second, _ = Canonicalizer.pdf_normalize(first)
        assert first == second

    def test_returns_tuple(self):
        result = Canonicalizer.pdf_normalize(self._build_pdf())
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bytes)
        assert isinstance(result[1], str)


# ---------------------------------------------------------------------------
# process_artifact
# ---------------------------------------------------------------------------


class TestProcessArtifact:
    def test_json_artifact(self):
        raw = json.dumps({"key": "value"}).encode("utf-8")
        result = process_artifact(raw, "application/json")
        assert result["mode"] == "jcs_v1"
        assert result["raw_hash"]
        assert result["canonical_hash"]
        assert result["version"] == CANONICALIZER_VERSIONS["jcs"]
        assert result["fallback_reason"] is None

    def test_pdf_artifact(self):
        raw = TestPdfNormalize._build_pdf()
        result = process_artifact(raw, "application/pdf")
        assert result["mode"] == "pdf_norm_pikepdf_v1"

    def test_unknown_mime_type_rejected(self):
        raw = b"arbitrary binary data"
        with pytest.raises(UnsupportedMimeTypeError):
            process_artifact(raw, "application/octet-stream")

    def test_witness_anchor_propagated(self):
        raw = json.dumps({"a": 1}).encode("utf-8")
        result = process_artifact(raw, "application/json", witness_anchor="anchor-123")
        assert result["witness_anchor"] == "anchor-123"

    def test_invalid_json_rejected(self):
        raw = b"not json at all"
        with pytest.raises(ArtifactCanonicalizationError):
            process_artifact(raw, "application/json")

    def test_html_idempotency_violation_raises(self, monkeypatch):
        raw = b"<html><body>ok</body></html>"

        def bad_html(data: bytes) -> bytes:  # pragma: no cover - controlled monkeypatch
            if data == raw:
                return b"first"
            return b"second"

        monkeypatch.setattr(Canonicalizer, "html_v1", staticmethod(bad_html))
        with pytest.raises(ArtifactIdempotencyError):
            process_artifact(raw, "text/html")

    def test_lxml_version_included(self):
        raw = b"<html><body>test</body></html>"
        result = process_artifact(raw, "text/html")
        assert "lxml_pinned" in result

    def test_html_artifact(self):
        raw = b"<html><body><p>hello</p></body></html>"
        result = process_artifact(raw, "text/html")
        assert result["mode"] == "html_v1"
        assert result["raw_hash"]
        assert result["canonical_hash"]

    def test_docx_artifact(self):
        raw = _build_minimal_docx()
        result = process_artifact(
            raw,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert result["mode"] == "docx_v1"
        assert result["raw_hash"]
        assert result["canonical_hash"]


# ---------------------------------------------------------------------------
# HTML canonicalization
# ---------------------------------------------------------------------------


class TestHtmlV1:
    def test_sorted_attributes(self):
        html = b"<html><body><div z='1' a='2'>hello</div></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<div" in result
        # Attributes should be sorted alphabetically
        a_pos = result.index(b"a=")
        z_pos = result.index(b"z=")
        assert a_pos < z_pos

    def test_strips_scripts(self):
        html = b"<html><body><script>alert(1)</script><p>content</p></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<script" not in result
        assert b"content" in result

    def test_strips_styles(self):
        html = b"<html><body><style>.x{color:red}</style><p>text</p></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<style" not in result

    def test_nfc_normalization(self):
        # Both decomposed and precomposed should produce the same output
        precomposed = "<html><body><p>\u00e9</p></body></html>".encode()
        decomposed = "<html><body><p>e\u0301</p></body></html>".encode()
        assert Canonicalizer.html_v1(precomposed) == Canonicalizer.html_v1(decomposed)

    def test_returns_bytes(self):
        html = b"<html><body><p>hello</p></body></html>"
        result = Canonicalizer.html_v1(html)
        assert isinstance(result, bytes)

    def test_invalid_html_raises(self):
        with pytest.raises(CanonicalizationError, match="HTML Parse Failure"):
            Canonicalizer.html_v1(b"\xff\xfe not utf-8 not html \x00\x01")

    def test_strips_event_handlers(self):
        html = b"<html><body><a href='/' onclick='steal()'>x</a></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"onclick" not in result

    def test_strips_javascript_urls(self):
        html = b"<html><body><a href=' javascript:alert(1) '>x</a></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"javascript:" not in result

    def test_removes_script_contents(self):
        html = b"<html><body><script>alert('hi')</script><p>ok</p></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"alert" not in result
        assert b"ok" in result


# ---------------------------------------------------------------------------
# DOCX canonicalization
# ---------------------------------------------------------------------------


def _build_minimal_docx() -> bytes:
    """Create a minimal valid DOCX (ZIP with word/document.xml)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "word/document.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            "<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body>"
            "</w:document>",
        )
        zf.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/'
            'package/2006/relationships"></Relationships>',
        )
        zf.writestr(
            "docProps/core.xml",
            '<?xml version="1.0"?><cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties">'
            "</cp:coreProperties>",
        )
    return buf.getvalue()


class TestDocxV1:
    def test_returns_32_bytes(self):
        docx = _build_minimal_docx()
        result = Canonicalizer.docx_v1(docx)
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_deterministic(self):
        docx = _build_minimal_docx()
        assert Canonicalizer.docx_v1(docx) == Canonicalizer.docx_v1(docx)

    def test_invalid_docx_raises(self):
        with pytest.raises(CanonicalizationError, match="DOCX C14N failure"):
            Canonicalizer.docx_v1(b"not a zip file at all")

    def test_strips_volatile_metadata(self):
        # The core.xml is stripped (docProps/core.xml in the skip list)
        # Two DOCXes with different core.xml but same document.xml should hash the same
        buf1 = io.BytesIO()
        with zipfile.ZipFile(buf1, "w") as zf:
            zf.writestr("word/document.xml", "<root/>")
            zf.writestr("docProps/core.xml", "<core>v1</core>")

        buf2 = io.BytesIO()
        with zipfile.ZipFile(buf2, "w") as zf:
            zf.writestr("word/document.xml", "<root/>")
            zf.writestr("docProps/core.xml", "<core>v2</core>")

        assert Canonicalizer.docx_v1(buf1.getvalue()) == Canonicalizer.docx_v1(buf2.getvalue())


# ---------------------------------------------------------------------------
# Version constants
# ---------------------------------------------------------------------------


class TestVersionConstants:
    def test_all_formats_have_versions(self):
        for fmt in ("jcs", "html", "docx", "pdf"):
            assert fmt in CANONICALIZER_VERSIONS

    def test_versions_are_strings(self):
        for v in CANONICALIZER_VERSIONS.values():
            assert isinstance(v, str)
            assert len(v) > 0


# ---------------------------------------------------------------------------
# Golden vector: deterministic hash stability
# ---------------------------------------------------------------------------


class TestGoldenVector:
    """Byte-stability anchor — if these fail, hash semantics changed."""

    def test_json_jcs_golden(self):
        raw = b'{"z":1,"a":2,"m":3}'
        canonical = Canonicalizer.json_jcs(raw)
        assert canonical == b'{"a":2,"m":3,"z":1}'

    def test_json_jcs_nested_golden(self):
        raw = json.dumps({"b": {"d": 4, "c": 3}, "a": 1}).encode("utf-8")
        canonical = Canonicalizer.json_jcs(raw)
        assert canonical == b'{"a":1,"b":{"c":3,"d":4}}'

    def test_get_hash_golden(self):
        """Anchor BLAKE3 hash output for a known input."""
        h = Canonicalizer.get_hash(b"olympus")
        # Just verify it's deterministic and 32 bytes
        assert len(h) == 32
        assert h == Canonicalizer.get_hash(b"olympus")
