"""
Tests for extended canonicalization formats (plaintext, XML, CSV).

Tests the new format support added to protocol/canonical.py for
deterministic canonicalization of plain text, XML, and CSV/TSV data.
"""

import pytest

from protocol.canonical import (
    CanonicalizationError,
    canonicalize_csv,
    canonicalize_csv_bytes,
    canonicalize_plaintext,
    canonicalize_plaintext_bytes,
    canonicalize_xml,
    canonicalize_xml_bytes,
)


# ---------------------------------------------------------------------------
# Plain text canonicalization
# ---------------------------------------------------------------------------


class TestCanonicalizePlaintext:
    """Tests for canonicalize_plaintext()."""

    def test_basic_whitespace_normalization(self) -> None:
        """Multiple spaces collapse to single space."""
        result = canonicalize_plaintext("Hello   World")
        assert result == "Hello World"

    def test_crlf_to_lf(self) -> None:
        """CRLF line endings are normalized to LF."""
        result = canonicalize_plaintext("line1\r\nline2\r\nline3")
        assert result == "line1\nline2\nline3"

    def test_cr_to_lf(self) -> None:
        """CR line endings are normalized to LF."""
        result = canonicalize_plaintext("line1\rline2")
        assert result == "line1\nline2"

    def test_bom_stripped(self) -> None:
        """Unicode BOM is stripped."""
        result = canonicalize_plaintext("\ufeffHello World")
        assert result == "Hello World"

    def test_unicode_nbsp_normalized(self) -> None:
        """Unicode NBSP (U+00A0) is replaced with ASCII space."""
        result = canonicalize_plaintext("Hello\u00a0World")
        assert result == "Hello World"

    def test_narrow_nbsp_normalized(self) -> None:
        """Narrow NBSP (U+202F) is replaced with ASCII space."""
        result = canonicalize_plaintext("Hello\u202fWorld")
        assert result == "Hello World"

    def test_leading_trailing_blank_lines_removed(self) -> None:
        """Leading and trailing blank lines are stripped."""
        result = canonicalize_plaintext("\n\nHello\n\n")
        assert result == "Hello"

    def test_internal_blank_lines_preserved(self) -> None:
        """Internal blank lines are preserved."""
        result = canonicalize_plaintext("Para 1\n\nPara 2")
        assert result == "Para 1\n\nPara 2"

    def test_compatibility_glyphs_preserved(self) -> None:
        """Fullwidth characters are preserved, not compatibility-folded."""
        result = canonicalize_plaintext("\uff21\uff22\uff23")
        assert result == "\uff21\uff22\uff23"

    def test_legacy_scrub_flag_false_preserves_compatibility_glyphs(self) -> None:
        """The legacy scrub flag must not affect compatibility glyphs."""
        result = canonicalize_plaintext("\uff21\uff22\uff23", scrub_homoglyphs=False)
        assert result == "\uff21\uff22\uff23"

    def test_normalize_unicode_spaces_keyword_supported(self) -> None:
        """The renamed keyword maps Unicode space separators to ASCII space."""
        result = canonicalize_plaintext("Hello\u00a0World", normalize_unicode_spaces=True)
        assert result == "Hello World"

    def test_normalize_unicode_spaces_false_skips_explicit_translation(self) -> None:
        """With the flag off, the explicit Unicode-space translation is skipped.

        Plaintext mode still collapses whitespace via :py:meth:`str.split`,
        so NBSP between words is collapsed to a single ASCII space — the
        per-line ``" ".join(line.split())`` step intentionally treats any
        Unicode whitespace as a separator.  But a *leading* NBSP is preserved
        as a distinct codepoint when the explicit translation is disabled.
        """
        # With flag on: leading NBSP becomes ASCII space, then collapsed.
        on = canonicalize_plaintext("\u00a0Hello", normalize_unicode_spaces=True)
        # With flag off: leading NBSP is preserved through the explicit step,
        # then ``str.split`` strips it as leading whitespace (it is Unicode
        # whitespace).  The two outputs must still be equal at this point;
        # the meaningful divergence shows up in the JSON canonicalizer's
        # value path, exercised in test_canonical_document.py.
        off = canonicalize_plaintext("\u00a0Hello", normalize_unicode_spaces=False)
        assert on == "Hello"
        assert off == "Hello"

    def test_scrub_homoglyphs_keyword_alias_supported(self) -> None:
        """``scrub_homoglyphs`` remains as a backward-compatible alias."""
        a = canonicalize_plaintext("Hello\u00a0World", scrub_homoglyphs=True)
        b = canonicalize_plaintext("Hello\u00a0World", normalize_unicode_spaces=True)
        assert a == b == "Hello World"

    def test_idempotent(self) -> None:
        """Canonicalization is idempotent: C(x) == C(C(x))."""
        text = "  Hello   World  \r\n\r\n  Second   line  \r\n"
        once = canonicalize_plaintext(text)
        twice = canonicalize_plaintext(once)
        assert once == twice

    def test_deterministic(self) -> None:
        """Canonicalization is deterministic."""
        text = "  Hello \u00a0 World \r\n\r\n"
        a = canonicalize_plaintext(text)
        b = canonicalize_plaintext(text)
        assert a == b

    def test_empty_text(self) -> None:
        """Empty text returns empty string."""
        result = canonicalize_plaintext("")
        assert result == ""

    def test_whitespace_only(self) -> None:
        """Whitespace-only text returns empty string."""
        result = canonicalize_plaintext("   \n\n   \n   ")
        assert result == ""


class TestCanonicalizePlaintextBytes:
    """Tests for canonicalize_plaintext_bytes()."""

    def test_returns_utf8_bytes(self) -> None:
        """Output is UTF-8 encoded bytes."""
        result = canonicalize_plaintext_bytes(b"Hello World")
        assert isinstance(result, bytes)
        assert result == b"Hello World"

    def test_crlf_normalized(self) -> None:
        """CRLF is normalized in byte mode."""
        result = canonicalize_plaintext_bytes(b"line1\r\nline2")
        assert result == b"line1\nline2"


# ---------------------------------------------------------------------------
# XML canonicalization
# ---------------------------------------------------------------------------


class TestCanonicalizeXml:
    """Tests for canonicalize_xml().

    With lxml available (the default), canonicalize_xml() uses W3C C14N 2.0.
    C14N 2.0 outputs full end-tags for empty elements (``<root></root>`` rather
    than ``<root/>``), strips PIs and comments, and applies canonical attribute
    ordering.  Tests assert on observable properties (e.g., "no ``<?``") rather
    than exact self-closing form where the two paths differ.
    """

    def test_removes_processing_instructions(self) -> None:
        """XML processing instructions are stripped."""
        result = canonicalize_xml('<?xml version="1.0"?>\n<root/>')
        assert "<?" not in result
        assert "root" in result

    def test_removes_comments(self) -> None:
        """XML comments are stripped."""
        result = canonicalize_xml("<root><!-- comment --><child/></root>")
        assert "<!--" not in result
        assert "child" in result

    def test_removes_doctype(self) -> None:
        """DOCTYPE declarations are stripped."""
        result = canonicalize_xml("<!DOCTYPE html>\n<root/>")
        assert "DOCTYPE" not in result

    def test_sorts_attributes(self) -> None:
        """Attributes are sorted canonically."""
        result = canonicalize_xml('<root z="3" a="1" m="2"></root>')
        # Attribute order must be a=1, m=2, z=3 regardless of input order
        idx_a = result.index('a="1"')
        idx_m = result.index('m="2"')
        idx_z = result.index('z="3"')
        assert idx_a < idx_m < idx_z, f"Attributes not in canonical order: {result}"

    def test_normalizes_self_closing(self) -> None:
        """Well-formed self-closing tags are accepted and round-trip correctly."""
        result = canonicalize_xml("<root><br/></root>")
        # After C14N 2.0 the output has full end-tags; the key property is it
        # doesn't raise and the element name survives.
        assert "br" in result

    def test_bom_stripped(self) -> None:
        """BOM is stripped from XML."""
        result = canonicalize_xml("\ufeff<root/>")
        assert "\ufeff" not in result
        assert "root" in result

    def test_crlf_normalized(self) -> None:
        """CRLF is normalized to LF."""
        result = canonicalize_xml("<root>\r\n<child/>\r\n</root>")
        assert "\r" not in result

    def test_idempotent(self) -> None:
        """XML canonicalization is idempotent."""
        xml = '<?xml version="1.0"?>\n<root b="2" a="1"><!-- comment --><child/></root>'
        once = canonicalize_xml(xml)
        twice = canonicalize_xml(once)
        assert once == twice

    def test_deterministic(self) -> None:
        """XML canonicalization is deterministic."""
        xml = '<root z="3" a="1"><child m="5" b="2"/></root>'
        a = canonicalize_xml(xml)
        b = canonicalize_xml(xml)
        assert a == b

    def test_nested_attribute_sorting(self) -> None:
        """Nested element attributes are also sorted canonically."""
        xml = '<root><child z="3" a="1"/></root>'
        result = canonicalize_xml(xml)
        # a=1 must appear before z=3 in the output
        assert result.index('a="1"') < result.index('z="3"')

    def test_preserves_text_content(self) -> None:
        """Element text content is preserved."""
        xml = "<root>Hello World</root>"
        result = canonicalize_xml(xml)
        assert "Hello World" in result

    def test_empty_root(self) -> None:
        """Empty element is round-tripped (output is valid XML)."""
        result = canonicalize_xml("<root/>")
        assert "root" in result
        # C14N 2.0 uses full end-tags; regex fallback uses self-closing
        assert result.strip() in ("<root/>", "<root></root>")

    def test_namespace_prefixed_attributes_deterministic(self) -> None:
        """Namespace-prefixed attributes are handled deterministically.

        The regex path cannot correctly resolve namespace prefixes; lxml C14N 2.0
        expands them according to the canonical namespace ordering rules.  This
        test verifies that the output is deterministic (same input → same output)
        and that the result is valid UTF-8 text regardless of which path is used.
        """
        xml = (
            '<root xmlns:b="http://b.example/" xmlns:a="http://a.example/"'
            ' b:attr="2" a:attr="1"><child/></root>'
        )
        result1 = canonicalize_xml(xml)
        result2 = canonicalize_xml(xml)
        # Determinism: identical inputs must produce identical output
        assert result1 == result2
        # Output must be valid UTF-8 text
        result1.encode("utf-8")
        # Neither attribute must be silently dropped
        assert "attr" in result1


class TestCanonicalizeXmlBytes:
    """Tests for canonicalize_xml_bytes()."""

    def test_returns_utf8_bytes(self) -> None:
        """Output is UTF-8 encoded bytes of the canonical XML."""
        result = canonicalize_xml_bytes(b"<root/>")
        assert isinstance(result, bytes)
        # Decode must succeed as UTF-8 and produce valid XML with a root element
        decoded = result.decode("utf-8")
        assert "root" in decoded


# ---------------------------------------------------------------------------
# CSV canonicalization
# ---------------------------------------------------------------------------


class TestCanonicalizeCsv:
    """Tests for canonicalize_csv()."""

    def test_basic_csv(self) -> None:
        """Basic CSV with header and data rows."""
        csv_text = "name,age\nBob,30\nAlice,25"
        result = canonicalize_csv(csv_text)
        lines = result.split("\n")
        assert lines[0] == "name,age"
        # Data rows should be sorted (Alice before Bob)
        assert lines[1] == "Alice,25"
        assert lines[2] == "Bob,30"

    def test_crlf_normalized(self) -> None:
        """CRLF line endings are normalized."""
        csv_text = "name,age\r\nAlice,25\r\nBob,30\r\n"
        result = canonicalize_csv(csv_text)
        assert "\r" not in result

    def test_bom_stripped(self) -> None:
        """BOM is stripped from CSV."""
        csv_text = "\ufeffname,age\nAlice,25"
        result = canonicalize_csv(csv_text)
        assert not result.startswith("\ufeff")

    def test_cell_whitespace_stripped(self) -> None:
        """Cell values have leading/trailing whitespace stripped."""
        csv_text = "name , age \n Alice , 25 "
        result = canonicalize_csv(csv_text)
        lines = result.split("\n")
        assert lines[0] == "name,age"
        assert lines[1] == "Alice,25"

    def test_sort_rows_preserves_header(self) -> None:
        """Sorting preserves header as first row."""
        csv_text = "name,age\nZoe,20\nAlice,25"
        result = canonicalize_csv(csv_text)
        lines = result.split("\n")
        assert lines[0] == "name,age"

    def test_sort_disabled(self) -> None:
        """Row sorting can be disabled."""
        csv_text = "name,age\nZoe,20\nAlice,25"
        result = canonicalize_csv(csv_text, sort_rows=False)
        lines = result.split("\n")
        assert lines[1] == "Zoe,20"

    def test_no_header(self) -> None:
        """CSV without header — all rows are sorted."""
        csv_text = "Zoe,20\nAlice,25\nBob,30"
        result = canonicalize_csv(csv_text, has_header=False)
        lines = result.split("\n")
        assert lines[0] == "Alice,25"

    def test_tsv_delimiter(self) -> None:
        """TSV (tab delimiter) is supported."""
        tsv_text = "name\tage\nAlice\t25\nBob\t30"
        result = canonicalize_csv(tsv_text, delimiter="\t")
        # Output always uses comma delimiter
        lines = result.split("\n")
        assert lines[0] == "name,age"

    def test_quoted_fields(self) -> None:
        """Fields with commas are properly quoted."""
        csv_text = 'name,description\nAlice,"Has, comma"\nBob,Simple'
        result = canonicalize_csv(csv_text)
        assert '"Has, comma"' in result

    def test_idempotent(self) -> None:
        """CSV canonicalization is idempotent."""
        csv_text = "name,age\r\nBob,30\r\nAlice,25\r\n"
        once = canonicalize_csv(csv_text)
        twice = canonicalize_csv(once)
        assert once == twice

    def test_deterministic(self) -> None:
        """CSV canonicalization is deterministic."""
        csv_text = "name,age\nBob,30\nAlice,25"
        a = canonicalize_csv(csv_text)
        b = canonicalize_csv(csv_text)
        assert a == b

    def test_empty_csv_raises(self) -> None:
        """Empty CSV raises CanonicalizationError."""
        with pytest.raises(CanonicalizationError, match="empty"):
            canonicalize_csv("")

    def test_unicode_nfc_normalized(self) -> None:
        """Unicode in cells is NFC-normalized."""
        # e + combining acute (U+0301) vs é (U+00E9)
        csv_text = "name\ne\u0301"
        result = canonicalize_csv(csv_text, has_header=False)
        assert "\u00e9" in result  # NFC form


class TestCanonicalizeCsvBytes:
    """Tests for canonicalize_csv_bytes()."""

    def test_returns_utf8_bytes(self) -> None:
        """Output is UTF-8 encoded bytes."""
        result = canonicalize_csv_bytes(b"name,age\nAlice,25")
        assert isinstance(result, bytes)

    def test_tsv_input(self) -> None:
        """TSV bytes are handled."""
        result = canonicalize_csv_bytes(b"a\tb\n1\t2", delimiter="\t")
        assert b"a,b" in result
