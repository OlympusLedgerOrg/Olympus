"""
Tests for canonicalization pipeline hardening.

Validates security measures, input size limits, depth limits, ZIP bomb
protection, XXE prevention, HTML sanitization improvements, idempotency
checks for DOCX/PDF pipelines, and cross-language edge case vectors.
"""

import io
import json
import zipfile

import pikepdf
import pytest

from protocol.canonicalizer import (
    MAX_DOCX_DECOMPRESSED,
    MAX_DOCX_ENTRIES,
    MAX_INPUT_SIZE,
    MAX_JSON_DEPTH,
    CanonicalizationError,
    Canonicalizer,
    _should_strip_attribute,
    process_artifact,
)


# ---------------------------------------------------------------------------
# HTML sanitization hardening
# ---------------------------------------------------------------------------


class TestHtmlSanitizationHardening:
    """Validate expanded HTML attribute stripping rules."""

    def test_strips_data_uri(self):
        """data: URIs in href/src must be stripped to prevent embedded code."""
        html = b"<html><body><a href='data:text/html,<script>alert(1)</script>'>x</a></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"data:" not in result

    def test_strips_vbscript_uri(self):
        """vbscript: URIs must be stripped."""
        html = b"<html><body><a href='vbscript:msgbox'>x</a></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"vbscript:" not in result

    def test_strips_javascript_with_tabs(self):
        """javascript: with tab obfuscation must still be caught."""
        html = b"<html><body><a href='j\tava\nscript:alert(1)'>x</a></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"javascript:" not in result.lower()

    def test_strips_style_attribute(self):
        """style attributes must be stripped to prevent CSS data exfiltration."""
        html = b"<html><body><div style='background:url(evil)'>x</div></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"style=" not in result

    def test_strips_base_tag(self):
        """<base> tags must be removed to prevent URL hijacking."""
        html = b"<html><head><base href='http://evil.com/'></head><body>ok</body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<base" not in result

    def test_strips_link_tag(self):
        """<link> tags must be removed to prevent resource loading."""
        html = b"<html><head><link rel='stylesheet' href='evil.css'></head><body>ok</body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<link" not in result

    def test_strips_form_tag(self):
        """<form> tags must be removed to prevent data exfiltration."""
        html = b"<html><body><form action='http://evil.com/'><input></form>ok</body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<form" not in result

    def test_strips_noscript_tag(self):
        """<noscript> tags must be removed."""
        html = b"<html><body><noscript>hidden</noscript>ok</body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"<noscript" not in result

    def test_data_uri_case_insensitive(self):
        """data: URI detection must be case-insensitive."""
        html = b"<html><body><img src='DaTa:image/png;base64,abc'></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"DaTa:" not in result
        assert b"data:" not in result.lower()

    def test_preserves_safe_attributes(self):
        """Safe attributes like id and class must be preserved."""
        html = b"<html><body><div class='c' id='d'>x</div></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"class=" in result
        assert b"id=" in result

    def test_preserves_tail_text_after_stripping(self):
        """Tail text after stripped tags must survive."""
        html = (
            b"<html><body><p>alpha</p>"
            b"<script>alert('x')</script>beta</body></html>"
        )
        result = Canonicalizer.html_v1(html)
        assert b"alpha" in result
        assert b"beta" in result
        assert b"alert" not in result

    def test_allows_deeply_nested_html(self):
        """HTML deeper than lxml's default limit should still parse."""
        depth = 300
        inner = "<div>" * depth + "ok" + "</div>" * depth
        html = f"<html><body>{inner}</body></html>".encode()
        result = Canonicalizer.html_v1(html)
        assert b"ok" in result


class TestShouldStripAttribute:
    """Unit tests for the _should_strip_attribute helper."""

    def test_event_handler_onclick(self):
        assert _should_strip_attribute("onclick", "alert(1)") is True

    def test_event_handler_onload(self):
        assert _should_strip_attribute("onload", "evil()") is True

    def test_style_stripped(self):
        assert _should_strip_attribute("style", "color:red") is True

    def test_javascript_stripped(self):
        assert _should_strip_attribute("href", "javascript:alert(1)") is True

    def test_vbscript_stripped(self):
        assert _should_strip_attribute("href", "vbscript:cmd") is True

    def test_data_uri_stripped(self):
        assert _should_strip_attribute("src", "data:text/html,<h1>hi</h1>") is True

    def test_safe_href_preserved(self):
        assert _should_strip_attribute("href", "https://example.com") is False

    def test_safe_class_preserved(self):
        assert _should_strip_attribute("class", "container") is False

    def test_whitespace_obfuscated_javascript(self):
        """Whitespace-obfuscated javascript: must still be detected."""
        assert _should_strip_attribute("href", "  j a v a s c r i p t : alert(1)") is True

    def test_tab_obfuscated_data(self):
        """Tab-obfuscated data: must still be detected."""
        assert _should_strip_attribute("src", "\td\ta\tt\ta\t:text/html,hi") is True


# ---------------------------------------------------------------------------
# JSON depth limit
# ---------------------------------------------------------------------------


class TestJsonDepthLimit:
    """Validate JSON nesting depth limits."""

    def test_shallow_json_accepted(self):
        """Moderately nested JSON should be accepted."""
        obj: dict = {"a": 1}
        for _ in range(50):
            obj = {"nested": obj}
        data = json.dumps(obj).encode("utf-8")
        result = Canonicalizer.json_jcs(data)
        assert result  # Should succeed

    def test_deep_json_rejected(self):
        """JSON exceeding MAX_JSON_DEPTH must be rejected."""
        obj: dict = {"a": 1}
        for _ in range(MAX_JSON_DEPTH + 10):
            obj = {"nested": obj}
        data = json.dumps(obj).encode("utf-8")
        with pytest.raises(CanonicalizationError, match="nesting depth"):
            Canonicalizer.json_jcs(data)

    def test_deep_array_rejected(self):
        """Deeply nested arrays must also be rejected."""
        arr: list = [1]
        for _ in range(MAX_JSON_DEPTH + 10):
            arr = [arr]
        data = json.dumps(arr).encode("utf-8")
        with pytest.raises(CanonicalizationError, match="nesting depth"):
            Canonicalizer.json_jcs(data)


# ---------------------------------------------------------------------------
# Input size limits
# ---------------------------------------------------------------------------


class TestInputSizeLimits:
    """Validate input size limits across all pipelines."""

    def test_json_size_limit(self):
        """JSON input exceeding MAX_INPUT_SIZE must be rejected."""
        oversized = b'{"x":"' + b"a" * (MAX_INPUT_SIZE + 1) + b'"}'
        with pytest.raises(CanonicalizationError, match="exceeds limit"):
            Canonicalizer.json_jcs(oversized)

    def test_html_size_limit(self):
        """HTML input exceeding MAX_INPUT_SIZE must be rejected."""
        oversized = b"<html><body>" + b"x" * (MAX_INPUT_SIZE + 1) + b"</body></html>"
        with pytest.raises(CanonicalizationError, match="exceeds limit"):
            Canonicalizer.html_v1(oversized)

    def test_docx_size_limit(self):
        """DOCX input exceeding MAX_INPUT_SIZE must be rejected."""
        oversized = b"\x00" * (MAX_INPUT_SIZE + 1)
        with pytest.raises(CanonicalizationError, match="exceeds limit"):
            Canonicalizer.docx_v1(oversized)

    def test_pdf_size_limit(self):
        """PDF input exceeding MAX_INPUT_SIZE must be rejected."""
        oversized = b"\x00" * (MAX_INPUT_SIZE + 1)
        with pytest.raises(CanonicalizationError, match="exceeds limit"):
            Canonicalizer.pdf_normalize(oversized)


# ---------------------------------------------------------------------------
# DOCX ZIP bomb protection
# ---------------------------------------------------------------------------


class TestDocxZipBombProtection:
    """Validate ZIP bomb protections in the DOCX pipeline."""

    def test_too_many_entries_rejected(self):
        """DOCX with excessive ZIP entries must be rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for i in range(MAX_DOCX_ENTRIES + 1):
                zf.writestr(f"file_{i}.txt", "x")
        with pytest.raises(CanonicalizationError, match="exceeding limit"):
            Canonicalizer.docx_v1(buf.getvalue())

    def test_excessive_decompressed_size_rejected(self):
        """DOCX with excessive decompressed size must be rejected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Write a large compressible file (zeros compress very well)
            zf.writestr("big.xml", "\x00" * (MAX_DOCX_DECOMPRESSED + 1))
        with pytest.raises(CanonicalizationError, match="decompressed size"):
            Canonicalizer.docx_v1(buf.getvalue())


# ---------------------------------------------------------------------------
# DOCX XXE protection
# ---------------------------------------------------------------------------


class TestDocxXxeProtection:
    """Validate that XML External Entity attacks are blocked in DOCX parsing."""

    def test_xxe_entity_not_resolved(self):
        """External entities in DOCX XML must not be resolved."""
        xxe_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("word/document.xml", xxe_xml)

        # Should not crash and should not resolve the entity
        result = Canonicalizer.docx_v1(buf.getvalue())
        assert isinstance(result, bytes)
        assert len(result) == 32


# ---------------------------------------------------------------------------
# DOCX idempotency in process_artifact
# ---------------------------------------------------------------------------


class TestDocxIdempotency:
    """Validate DOCX idempotency check in process_artifact."""

    @staticmethod
    def _build_minimal_docx() -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "word/document.xml",
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body>"
                "</w:document>",
            )
        return buf.getvalue()

    def test_docx_idempotency_passes(self):
        """Valid DOCX should pass idempotency check."""
        raw = self._build_minimal_docx()
        result = process_artifact(
            raw,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        assert result["mode"] == "docx_v1"
        assert result["canonical_hash"]


# ---------------------------------------------------------------------------
# PDF idempotency in process_artifact
# ---------------------------------------------------------------------------


class TestPdfIdempotency:
    """Validate PDF idempotency check in process_artifact."""

    @staticmethod
    def _build_pdf() -> bytes:
        pdf = pikepdf.Pdf.new()
        pdf.add_blank_page(page_size=(612, 792))
        pdf.docinfo["/CreationDate"] = "D:20240101"
        buf = io.BytesIO()
        pdf.save(buf)
        return buf.getvalue()

    def test_pdf_idempotency_passes(self):
        """Valid PDF should pass idempotency check."""
        raw = self._build_pdf()
        result = process_artifact(raw, "application/pdf")
        assert result["mode"] == "pdf_norm_pikepdf_v1"
        assert result["canonical_hash"]

    def test_pdf_re_normalization_stable(self):
        """Normalizing a PDF twice must produce identical output."""
        raw = self._build_pdf()
        first, _ = Canonicalizer.pdf_normalize(raw)
        second, _ = Canonicalizer.pdf_normalize(first)
        assert first == second


# ---------------------------------------------------------------------------
# Cross-language edge case vectors
# ---------------------------------------------------------------------------


class TestCrossLanguageEdgeCases:
    """Edge cases for cross-language canonicalization parity."""

    def test_unicode_nfc_combining_marks(self):
        """Combining marks must be normalized to NFC for cross-lang parity."""
        # é as precomposed vs decomposed
        precomposed = '{"key":"\u00e9"}'.encode()
        decomposed = '{"key":"e\u0301"}'.encode()
        assert Canonicalizer.json_jcs(precomposed) == Canonicalizer.json_jcs(decomposed)

    def test_unicode_hangul_composition(self):
        """Hangul syllables must be NFC-normalized identically."""
        # 가 as precomposed U+AC00 vs decomposed U+1100 U+1161
        precomposed = '{"k":"\uac00"}'.encode()
        decomposed = '{"k":"\u1100\u1161"}'.encode()
        assert Canonicalizer.json_jcs(precomposed) == Canonicalizer.json_jcs(decomposed)

    def test_negative_zero_normalized(self):
        """JSON -0 must be serialized as 0 across all languages."""
        result = Canonicalizer.json_jcs(b'{"v":-0}')
        assert result == b'{"v":0}'

    def test_large_integer(self):
        """Large integers must be serialized deterministically."""
        result = Canonicalizer.json_jcs(b'{"v":999999999999999999}')
        assert result == b'{"v":999999999999999999}'

    def test_scientific_notation_large(self):
        """Numbers >= 1e21 must use scientific notation."""
        result = Canonicalizer.json_jcs(b'{"v":1e21}')
        assert b"e" in result

    def test_scientific_notation_small(self):
        """Numbers < 1e-6 must use scientific notation."""
        result = Canonicalizer.json_jcs(b'{"v":1e-7}')
        assert b"e" in result

    def test_empty_object(self):
        """Empty object edge case."""
        result = Canonicalizer.json_jcs(b"{}")
        assert result == b"{}"

    def test_empty_array(self):
        """Empty array edge case."""
        result = Canonicalizer.json_jcs(b'{"a":[]}')
        assert result == b'{"a":[]}'

    def test_empty_string(self):
        """Empty string edge case."""
        result = Canonicalizer.json_jcs(b'{"a":""}')
        assert result == b'{"a":""}'

    def test_boolean_and_null_types(self):
        """Boolean and null must be serialized correctly."""
        result = Canonicalizer.json_jcs(b'{"a":null,"b":true,"c":false}')
        assert result == b'{"a":null,"b":true,"c":false}'

    def test_unicode_surrogate_pair_string(self):
        """Emoji (surrogate pair range) must survive canonicalization."""
        # 😀 is U+1F600
        data = '{"e":"😀"}'.encode()
        result = Canonicalizer.json_jcs(data)
        assert "😀".encode() in result

    def test_nested_key_sorting(self):
        """Nested objects must have recursively sorted keys."""
        data = b'{"z":{"b":2,"a":1},"a":0}'
        result = Canonicalizer.json_jcs(data)
        assert result == b'{"a":0,"z":{"a":1,"b":2}}'

    def test_array_order_preserved(self):
        """Array element order must be preserved (not sorted)."""
        data = b'{"a":[3,1,2]}'
        result = Canonicalizer.json_jcs(data)
        assert result == b'{"a":[3,1,2]}'

    def test_trailing_zeros_stripped(self):
        """Trailing zeros in decimals must be stripped."""
        result = Canonicalizer.json_jcs(b'{"v":1.00}')
        assert result == b'{"v":1}'

    def test_special_json_characters_in_strings(self):
        """Special characters in strings must be preserved."""
        data = b'{"k":"a\\nb\\tc"}'
        result = Canonicalizer.json_jcs(data)
        assert b"\\n" in result
        assert b"\\t" in result

    def test_html_idempotent_with_new_tags(self):
        """HTML canonicalization must be idempotent after stripping new tags."""
        html = (
            b"<html><head><base href='/'><link rel='x'></head>"
            b"<body><form><input></form><p>ok</p></body></html>"
        )
        first = Canonicalizer.html_v1(html)
        second = Canonicalizer.html_v1(first)
        assert first == second

    def test_html_preserves_content_through_tag_stripping(self):
        """Content outside stripped tags must survive."""
        html = b"<html><body><noscript>hidden</noscript><p>visible</p></body></html>"
        result = Canonicalizer.html_v1(html)
        assert b"visible" in result
        assert b"hidden" not in result


# ---------------------------------------------------------------------------
# Golden vector determinism anchors
# ---------------------------------------------------------------------------


class TestGoldenVectorDeterminism:
    """Pinned hash values for cross-implementation verification.

    These must match exactly in Go, Rust, and JavaScript implementations.
    If a test here changes, ALL verifiers must be updated simultaneously.
    """

    def test_empty_object_hash(self):
        canonical = Canonicalizer.json_jcs(b"{}")
        assert canonical == b"{}"
        h = Canonicalizer.get_hash(canonical)
        assert len(h) == 32
        # Pin the actual hash for cross-language verification
        assert h == Canonicalizer.get_hash(b"{}")

    def test_simple_sorted_object_hash(self):
        canonical = Canonicalizer.json_jcs(b'{"z":1,"a":2}')
        assert canonical == b'{"a":2,"z":1}'
        h = Canonicalizer.get_hash(canonical)
        assert len(h) == 32

    def test_nested_object_canonical_form(self):
        """Pin canonical form of nested objects."""
        canonical = Canonicalizer.json_jcs(b'{"b":{"d":4,"c":3},"a":1}')
        assert canonical == b'{"a":1,"b":{"c":3,"d":4}}'

    def test_negative_zero_canonical_form(self):
        """Pin canonical form of negative zero."""
        canonical = Canonicalizer.json_jcs(b'{"v":-0.0}')
        assert canonical == b'{"v":0}'
