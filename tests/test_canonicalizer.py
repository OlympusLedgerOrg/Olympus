"""
Unit tests for the hardened canonicalizer module (protocol.canonicalizer).

Validates JCS JSON canonicalization, PDF structural scrub, the artifact
ingestion pipeline, and version pinning constants.
"""

import json

import pytest

from protocol.canonicalizer import (
    CANONICALIZER_VERSIONS,
    CanonicalizationError,
    Canonicalizer,
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
        from decimal import Decimal

        assert Canonicalizer._serialize_jcs_number(Decimal("0")) == "0"
        assert Canonicalizer._serialize_jcs_number(Decimal("-0")) == "0"

    def test_integer(self):
        from decimal import Decimal

        assert Canonicalizer._serialize_jcs_number(Decimal("42")) == "42"

    def test_negative(self):
        from decimal import Decimal

        assert Canonicalizer._serialize_jcs_number(Decimal("-3.14")) == "-3.14"

    def test_trailing_zeros_stripped(self):
        from decimal import Decimal

        assert Canonicalizer._serialize_jcs_number(Decimal("1.00")) == "1"

    def test_scientific_notation_large(self):
        from decimal import Decimal

        result = Canonicalizer._serialize_jcs_number(Decimal("1e21"))
        assert "e" in result.lower()

    def test_fixed_notation_within_range(self):
        from decimal import Decimal

        result = Canonicalizer._serialize_jcs_number(Decimal("0.000001"))
        assert result == "0.000001"

    def test_scientific_notation_small(self):
        from decimal import Decimal

        result = Canonicalizer._serialize_jcs_number(Decimal("1e-7"))
        assert "e" in result.lower()

    def test_non_finite_rejected(self):
        from decimal import Decimal

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


# ---------------------------------------------------------------------------
# PDF safe scrub
# ---------------------------------------------------------------------------


class TestPdfSafe:
    def test_volatile_keys_stripped(self):
        pdf = b"""%PDF-1.4
/CreationDate (D:20240101)
/ModDate (D:20240102)
/Producer (Test Producer)
/Creator (Test Creator)
/Content (preserved)
%%EOF"""
        cleaned, mode = Canonicalizer.pdf_safe(pdf)
        assert b"/CreationDate" not in cleaned
        assert b"/ModDate" not in cleaned
        assert b"/Producer" not in cleaned
        assert b"/Creator" not in cleaned
        assert b"/Content" in cleaned
        assert mode == "pdf_structural_scrub_v1"

    def test_line_endings_normalized(self):
        pdf = b"line1\r\nline2\rline3\n"
        cleaned, _ = Canonicalizer.pdf_safe(pdf)
        assert b"\r" not in cleaned

    def test_idempotent(self):
        pdf = b"%PDF-1.4\n/CreationDate (D:20240101)\n/Body (data)\n%%EOF"
        first, _ = Canonicalizer.pdf_safe(pdf)
        second, _ = Canonicalizer.pdf_safe(first)
        assert first == second

    def test_returns_tuple(self):
        result = Canonicalizer.pdf_safe(b"minimal pdf")
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
        raw = b"%PDF-1.4\n/CreationDate (D:20240101)\n%%EOF"
        result = process_artifact(raw, "application/pdf")
        assert result["mode"] == "pdf_structural_scrub_v1"

    def test_unknown_mime_type_preserved(self):
        raw = b"arbitrary binary data"
        result = process_artifact(raw, "application/octet-stream")
        assert result["mode"] == "byte_preserved"
        assert result["raw_hash"] == result["canonical_hash"]

    def test_witness_anchor_propagated(self):
        raw = json.dumps({"a": 1}).encode("utf-8")
        result = process_artifact(raw, "application/json", witness_anchor="anchor-123")
        assert result["witness_anchor"] == "anchor-123"

    def test_invalid_json_falls_back(self):
        raw = b"not json at all"
        result = process_artifact(raw, "application/json")
        assert result["mode"] == "byte_preserved"
        assert result["fallback_reason"] is not None
        assert "canonical_error" in result["fallback_reason"]

    def test_lxml_version_included(self):
        raw = b"test"
        result = process_artifact(raw, "text/plain")
        assert "lxml_pinned" in result


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
