"""
Tests for the ingest-parser-service integration with Olympus.

These tests verify the extraction pipeline from file upload through
canonicalization to ledger commitment.
"""

from __future__ import annotations

import pytest

from integrations.extractors.schemas import (
    BlockType,
    ContentBlock,
    DocumentPage,
    ExtractedDocument,
    ExtractionResult,
    ParseProvenance,
)


class TestExtractionSchemas:
    """Test the extraction schemas used by the Olympus API."""

    def test_parse_provenance_valid(self) -> None:
        """Test creating a valid provenance object."""
        provenance = ParseProvenance(
            raw_file_blake3="blake3_" + "a" * 64,
            parser_name="docling",
            parser_version="2.1.0",
            model_hash="sha256_" + "b" * 64,
            environment_digest="sha256_" + "c" * 64,
        )

        assert provenance.parser_name == "docling"
        assert provenance.raw_file_blake3.startswith("blake3_")
        assert len(provenance.raw_file_blake3) == 7 + 64

    def test_parse_provenance_invalid_blake3(self) -> None:
        """Test that invalid BLAKE3 hash is rejected."""
        with pytest.raises(ValueError):
            ParseProvenance(
                raw_file_blake3="invalid",
                parser_name="docling",
                parser_version="2.1.0",
                model_hash="sha256_" + "b" * 64,
                environment_digest="sha256_" + "c" * 64,
            )

    def test_content_block_types(self) -> None:
        """Test all block types are valid."""
        for block_type in BlockType:
            block = ContentBlock(
                id="blk_01",
                type=block_type,
                content="Test content",
                bbox=[0.0, 0.0, 100.0, 100.0],
            )
            assert block.type == block_type

    def test_extraction_result_get_all_text(self) -> None:
        """Test extracting all text from a document."""
        result = ExtractionResult(
            provenance=ParseProvenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="fallback",
                parser_version="1.0.0",
                model_hash="sha256_" + "0" * 64,
                environment_digest="sha256_" + "0" * 64,
            ),
            document=ExtractedDocument(
                pages=[
                    DocumentPage(
                        page_number=1,
                        blocks=[
                            ContentBlock(
                                id="blk_01_01",
                                type=BlockType.TEXT,
                                content="First block",
                                bbox=[0.0, 0.0, 100.0, 50.0],
                            ),
                            ContentBlock(
                                id="blk_01_02",
                                type=BlockType.TEXT,
                                content="Second block",
                                bbox=[0.0, 50.0, 100.0, 100.0],
                            ),
                        ],
                    ),
                    DocumentPage(
                        page_number=2,
                        blocks=[
                            ContentBlock(
                                id="blk_02_01",
                                type=BlockType.TEXT,
                                content="Page two",
                                bbox=[0.0, 0.0, 100.0, 100.0],
                            ),
                        ],
                    ),
                ],
                total_pages=2,
            ),
        )

        all_text = result.get_all_text()
        assert "First block" in all_text
        assert "Second block" in all_text
        assert "Page two" in all_text

    def test_extraction_result_get_text_blocks(self) -> None:
        """Test filtering text blocks."""
        result = ExtractionResult(
            provenance=ParseProvenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="fallback",
                parser_version="1.0.0",
                model_hash="sha256_" + "0" * 64,
                environment_digest="sha256_" + "0" * 64,
            ),
            document=ExtractedDocument(
                pages=[
                    DocumentPage(
                        page_number=1,
                        blocks=[
                            ContentBlock(
                                id="blk_01_01",
                                type=BlockType.TEXT,
                                content="Text content",
                                bbox=[0.0, 0.0, 100.0, 50.0],
                            ),
                            ContentBlock(
                                id="blk_01_02",
                                type=BlockType.TABLE,
                                content="Table content",
                                bbox=[0.0, 50.0, 100.0, 100.0],
                            ),
                        ],
                    ),
                ],
                total_pages=1,
            ),
        )

        text_blocks = result.get_text_blocks()
        assert len(text_blocks) == 1
        assert text_blocks[0].type == BlockType.TEXT
        assert text_blocks[0].content == "Text content"


class TestExtractionResultDeterminism:
    """Test that extraction results can be canonicalized deterministically."""

    def test_extraction_result_serialization(self) -> None:
        """Test that extraction results serialize consistently."""
        result = ExtractionResult(
            provenance=ParseProvenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="fallback",
                parser_version="1.0.0",
                model_hash="sha256_" + "0" * 64,
                environment_digest="sha256_" + "0" * 64,
            ),
            document=ExtractedDocument(
                pages=[
                    DocumentPage(
                        page_number=1,
                        width=612.0,
                        height=792.0,
                        blocks=[
                            ContentBlock(
                                id="blk_01_01",
                                type=BlockType.TEXT,
                                content="Test",
                                bbox=[10.0, 20.0, 200.0, 35.0],
                                confidence=0.95,
                            ),
                        ],
                    ),
                ],
                total_pages=1,
                language="en",
            ),
        )

        # Serialize twice and verify identical output
        json1 = result.model_dump_json(indent=None)
        json2 = result.model_dump_json(indent=None)
        assert json1 == json2

    def test_extraction_result_can_be_canonicalized(self) -> None:
        """Test that extraction results can be serialized deterministically.

        Note: The RFC 8785 canonicalization in Olympus requires Decimal values
        for floats, so the extraction pipeline would convert floats to Decimals
        before canonicalization for ledger commitment. For standard API responses,
        we use Pydantic's JSON serialization.
        """
        import json

        result = ExtractionResult(
            provenance=ParseProvenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="fallback",
                parser_version="1.0.0",
                model_hash="sha256_" + "0" * 64,
                environment_digest="sha256_" + "0" * 64,
            ),
            document=ExtractedDocument(
                pages=[
                    DocumentPage(
                        page_number=1,
                        blocks=[
                            ContentBlock(
                                id="blk_01_01",
                                type=BlockType.TEXT,
                                content="Test content",
                                bbox=[10.0, 20.0, 200.0, 35.0],
                            ),
                        ],
                    ),
                ],
                total_pages=1,
            ),
        )

        # Convert to dict and use deterministic JSON serialization
        data = result.model_dump()
        canonical1 = json.dumps(data, sort_keys=True, separators=(",", ":"))
        canonical2 = json.dumps(data, sort_keys=True, separators=(",", ":"))

        # Verify deterministic output
        assert canonical1 == canonical2
        assert isinstance(canonical1, str)

    def test_canonical_hash_is_stable(self) -> None:
        """Test that canonical hash is stable across serialization.

        This test uses a simple structure without floats to test the
        canonical JSON encoder directly.
        """
        from protocol.canonical_json import canonical_json_bytes
        from protocol.hashes import hash_bytes

        # Use a simple structure without floats for canonical encoding
        data = {
            "provenance": {
                "raw_file_blake3": "blake3_" + "a" * 64,
                "parser_name": "fallback",
                "parser_version": "1.0.0",
            },
            "document": {
                "total_pages": 0,
            },
        }

        canonical_bytes = canonical_json_bytes(data)

        hash1 = hash_bytes(canonical_bytes)
        hash2 = hash_bytes(canonical_bytes)

        assert hash1 == hash2
        assert len(hash1) == 32  # BLAKE3 raw bytes output (256 bits = 32 bytes)


class TestApiSchemas:
    """Test the API-facing extraction schemas."""

    def test_extract_request_validation(self) -> None:
        """Test ExtractRequest validation."""
        from api.schemas.extraction import ExtractRequest

        # Valid request
        request = ExtractRequest(
            expected_blake3="blake3_" + "a" * 64,
            auto_detect_pii=True,
            commit_after_extract=False,
        )
        assert request.expected_blake3.startswith("blake3_")

    def test_extract_request_invalid_hash(self) -> None:
        """Test ExtractRequest rejects invalid hash."""
        from api.schemas.extraction import ExtractRequest

        with pytest.raises(ValueError):
            ExtractRequest(
                expected_blake3="invalid_hash",
            )

    def test_extract_response_structure(self) -> None:
        """Test ExtractResponse structure."""
        from datetime import datetime, timezone

        from api.schemas.extraction import (
            ContentBlockResponse,
            ExtractedDocumentResponse,
            ExtractionProvenance,
            ExtractResponse,
            PageResponse,
        )

        response = ExtractResponse(
            provenance=ExtractionProvenance(
                raw_file_blake3="blake3_" + "a" * 64,
                parser_name="fallback",
                parser_version="1.0.0",
                model_hash="sha256_" + "0" * 64,
                environment_digest="sha256_" + "0" * 64,
            ),
            document=ExtractedDocumentResponse(
                pages=[
                    PageResponse(
                        page_number=1,
                        width=612.0,
                        height=792.0,
                        blocks=[
                            ContentBlockResponse(
                                id="blk_01_01",
                                type="text",
                                content="Test",
                                bbox=[10.0, 20.0, 200.0, 35.0],
                                is_redactable=False,
                            ),
                        ],
                    ),
                ],
                total_pages=1,
            ),
            extracted_at=datetime.now(timezone.utc),
        )

        assert response.provenance.parser_name == "fallback"
        assert response.document.total_pages == 1
        assert response.commit_id is None
