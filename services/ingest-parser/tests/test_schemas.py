"""Tests for the Pydantic schemas."""

from __future__ import annotations

import pytest

from ingest_parser.schemas import (
    BlockType,
    ContentBlock,
    DocumentPage,
    ExtractedDocument,
    ParseResponse,
    Provenance,
)


class TestContentBlock:
    """Tests for ContentBlock schema."""

    def test_bbox_rounding(self) -> None:
        """Test that bounding box coordinates are rounded to 4 decimal places."""
        block = ContentBlock(
            id="blk_01",
            type=BlockType.TEXT,
            content="Test content",
            bbox=[10.123456789, 20.987654321, 200.111111111, 35.999999999],
        )

        assert block.bbox == [10.1235, 20.9877, 200.1111, 36.0]

    def test_confidence_rounding(self) -> None:
        """Test that confidence is rounded to 4 decimal places."""
        block = ContentBlock(
            id="blk_01",
            type=BlockType.TEXT,
            content="Test content",
            bbox=[0.0, 0.0, 100.0, 100.0],
            confidence=0.987654321,
        )

        assert block.confidence == 0.9877

    def test_bbox_validation_length(self) -> None:
        """Test that bbox must have exactly 4 elements."""
        with pytest.raises(ValueError):
            ContentBlock(
                id="blk_01",
                type=BlockType.TEXT,
                content="Test",
                bbox=[0.0, 0.0, 100.0],  # Only 3 elements
            )

    def test_block_types(self) -> None:
        """Test all block types are valid."""
        for block_type in BlockType:
            block = ContentBlock(
                id="blk_01",
                type=block_type,
                content="Test",
                bbox=[0.0, 0.0, 100.0, 100.0],
            )
            assert block.type == block_type


class TestDocumentPage:
    """Tests for DocumentPage schema."""

    def test_dimension_rounding(self) -> None:
        """Test that page dimensions are rounded."""
        page = DocumentPage(
            page_number=1,
            width=612.123456789,
            height=792.987654321,
            blocks=[],
        )

        assert page.width == 612.1235
        assert page.height == 792.9877

    def test_page_number_validation(self) -> None:
        """Test that page number must be >= 1."""
        with pytest.raises(ValueError):
            DocumentPage(page_number=0, blocks=[])


class TestProvenance:
    """Tests for Provenance schema."""

    def test_valid_provenance(self) -> None:
        """Test creating a valid provenance object."""
        provenance = Provenance(
            raw_file_blake3="blake3_" + "a" * 64,
            parser_name="docling",
            parser_version="2.1.0",
            canonical_parser_version="v1.0",
            model_hash="sha256_" + "b" * 64,
            environment_digest="sha256_" + "c" * 64,
        )

        assert provenance.parser_name == "docling"
        assert provenance.canonical_parser_version == "v1.0"
        assert provenance.raw_file_blake3.startswith("blake3_")

    def test_canonical_version_pattern(self) -> None:
        """Test that canonical_parser_version follows v{major}.{minor} pattern."""
        # Valid versions
        for version in ["v1.0", "v2.5", "v10.20"]:
            provenance = Provenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="docling",
                parser_version="2.1.0",
                canonical_parser_version=version,
                model_hash="sha256_" + "b" * 64,
                environment_digest="sha256_" + "c" * 64,
            )
            assert provenance.canonical_parser_version == version

        # Invalid versions
        for invalid in ["1.0", "v1", "v1.0.0", "latest"]:
            with pytest.raises(ValueError):
                Provenance(
                    raw_file_blake3="blake3_" + "a" * 64,
                    parser_name="docling",
                    parser_version="2.1.0",
                    canonical_parser_version=invalid,
                    model_hash="sha256_" + "b" * 64,
                    environment_digest="sha256_" + "c" * 64,
                )

    def test_invalid_blake3_hash(self) -> None:
        """Test that invalid BLAKE3 hash is rejected."""
        with pytest.raises(ValueError):
            Provenance(
                raw_file_blake3="invalid_hash",  # Missing blake3_ prefix
                parser_name="docling",
                parser_version="2.1.0",
                canonical_parser_version="v1.0",
                model_hash="sha256_" + "b" * 64,
                environment_digest="sha256_" + "c" * 64,
            )

    def test_invalid_model_hash(self) -> None:
        """Test that invalid model hash is rejected."""
        with pytest.raises(ValueError):
            Provenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="docling",
                parser_version="2.1.0",
                canonical_parser_version="v1.0",
                model_hash="invalid",  # Missing sha256_ prefix
                environment_digest="sha256_" + "c" * 64,
            )


class TestExtractedDocument:
    """Tests for ExtractedDocument schema."""

    def test_empty_document(self) -> None:
        """Test creating an empty document."""
        doc = ExtractedDocument(pages=[], total_pages=0)
        assert doc.total_pages == 0
        assert len(doc.pages) == 0

    def test_document_with_pages(self) -> None:
        """Test creating a document with pages and blocks."""
        doc = ExtractedDocument(
            pages=[
                DocumentPage(
                    page_number=1,
                    width=612.0,
                    height=792.0,
                    blocks=[
                        ContentBlock(
                            id="blk_01_01",
                            type=BlockType.TEXT,
                            content="Hello, world!",
                            bbox=[10.0, 20.0, 200.0, 35.0],
                        ),
                    ],
                ),
            ],
            total_pages=1,
            language="en",
        )

        assert doc.total_pages == 1
        assert len(doc.pages) == 1
        assert len(doc.pages[0].blocks) == 1
        assert doc.pages[0].blocks[0].content == "Hello, world!"


class TestParseResponse:
    """Tests for ParseResponse schema."""

    def test_complete_response(self) -> None:
        """Test creating a complete parse response."""
        response = ParseResponse(
            provenance=Provenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="docling",
                parser_version="2.1.0",
                canonical_parser_version="v1.0",
                model_hash="sha256_" + "b" * 64,
                environment_digest="sha256_" + "c" * 64,
            ),
            document=ExtractedDocument(
                pages=[
                    DocumentPage(
                        page_number=1,
                        blocks=[
                            ContentBlock(
                                id="blk_01_01",
                                type=BlockType.TEXT,
                                content="Test",
                                bbox=[0.0, 0.0, 100.0, 100.0],
                            ),
                        ],
                    ),
                ],
                total_pages=1,
            ),
        )

        assert response.provenance.parser_name == "docling"
        assert response.provenance.canonical_parser_version == "v1.0"
        assert response.document.total_pages == 1

    def test_response_serialization(self) -> None:
        """Test that response can be serialized to JSON."""
        response = ParseResponse(
            provenance=Provenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="fallback",
                parser_version="1.0.0",
                canonical_parser_version="v1.0",
                model_hash="sha256_" + "0" * 64,
                environment_digest="sha256_" + "0" * 64,
            ),
            document=ExtractedDocument(pages=[], total_pages=0),
        )

        json_str = response.model_dump_json()
        assert "provenance" in json_str
        assert "document" in json_str
        assert "blake3_" in json_str
        assert "canonical_parser_version" in json_str
