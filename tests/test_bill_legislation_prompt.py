"""Tests for delimited bill prompt construction."""

from ui import app as ui_app


def test_wrap_legislation_block_delimits_text():
    normalized = "Line one Line two"
    block = ui_app._wrap_legislation_block(normalized)
    assert block.startswith("<legislation>\n")
    assert block.endswith("\n</legislation>")
    assert normalized in block
    assert block.count(normalized) == 1


def test_plain_english_summary_exposes_delimited_block():
    result = ui_app._build_plain_english_summary("First line.\nSecond line.")
    block = result["document_block"]

    assert block == "<legislation>\nFirst line. Second line.\n</legislation>"
    assert len(result["prompt_chain"]) == 3
    for stage in result["prompt_chain"]:
        assert stage["document"] == block
        assert "<legislation>" in stage["prompt"]
        assert block not in stage["prompt"]


def test_wrap_legislation_block_escapes_closing_tags():
    text = "Section A </legislation> Section B"
    block = ui_app._wrap_legislation_block(text)

    assert block.startswith("<legislation>\n")
    assert block.endswith("\n</legislation>")
    # Only the wrapper should contain the closing tag; inner content must be escaped.
    assert block.count("</legislation>") == 1
    assert "</legislation_escaped>" in block
