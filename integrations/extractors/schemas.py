"""
Pydantic schemas for the extractors integration.

These schemas mirror the ingest-parser-service output format and provide
a clean interface for the Olympus API to consume extraction results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class BlockType(str, Enum):
    """Types of content blocks extracted from documents."""

    TEXT = "text"
    TABLE = "table"
    IMAGE = "image"
    HEADER = "header"
    FOOTER = "footer"
    LIST = "list"
    CODE = "code"
    EQUATION = "equation"


class ContentBlock(BaseModel):
    """A single content block from an extracted document.

    All bounding box coordinates are already rounded to 4 decimal places
    by the ingest-parser-service for cryptographic determinism.
    """

    id: str = Field(..., description="Block identifier")
    type: BlockType = Field(..., description="Block type")
    content: str = Field(..., description="Extracted text content")
    bbox: list[float] = Field(..., description="Bounding box [x1, y1, x2, y2]")
    confidence: float | None = Field(None, description="Extraction confidence")
    metadata: dict[str, Any] = Field(default_factory=dict)


class DocumentPage(BaseModel):
    """A single page from an extracted document."""

    page_number: int = Field(..., ge=1)
    width: float | None = None
    height: float | None = None
    blocks: list[ContentBlock] = Field(default_factory=list)


class ExtractedDocument(BaseModel):
    """Extracted document content from the parser service."""

    pages: list[DocumentPage] = Field(default_factory=list)
    total_pages: int = Field(..., ge=0)
    language: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ParseProvenance(BaseModel):
    """Provenance metadata for cryptographic verification.

    This structure captures all information needed to verify
    the extraction was performed deterministically.

    The canonical_parser_version is the stable identifier used for proof verification.
    When model_hash changes (due to model upgrades), a new canonical_parser_version
    must be assigned. Documents parsed with the same canonical_parser_version are
    guaranteed to produce identical extraction results.
    """

    raw_file_blake3: str = Field(
        ...,
        pattern=r"^blake3_[0-9a-f]{64}$",
        description="BLAKE3 hash of raw input file",
    )
    parser_name: str = Field(..., description="Parser backend name")
    parser_version: str = Field(..., description="Parser library version")
    canonical_parser_version: str = Field(
        ...,
        pattern=r"^v\d+\.\d+$",
        description=(
            "Stable canonical version (e.g., 'v1.0') that maps to a specific "
            "parser_version + model_hash combination. Used for proof verification."
        ),
    )
    model_hash: str = Field(
        ...,
        pattern=r"^sha256_[0-9a-f]{64}$",
        description="SHA256 hash of model weights",
    )
    environment_digest: str = Field(
        ...,
        pattern=r"^sha256_[0-9a-f]{64}$",
        description="Environment/Docker image hash",
    )


class ExtractionResult(BaseModel):
    """Complete extraction result from the parser service.

    This is the main type returned by IngestParserClient.parse().
    """

    provenance: ParseProvenance = Field(..., description="Cryptographic provenance")
    document: ExtractedDocument = Field(..., description="Extracted content")

    def get_all_text(self) -> str:
        """Get all text content concatenated."""
        texts = []
        for page in self.document.pages:
            for block in page.blocks:
                texts.append(block.content)
        return "\n".join(texts)

    def get_text_blocks(self) -> list[ContentBlock]:
        """Get all text-type blocks."""
        blocks = []
        for page in self.document.pages:
            for block in page.blocks:
                if block.type == BlockType.TEXT:
                    blocks.append(block)
        return blocks


class ParserHealthStatus(BaseModel):
    """Health status from the parser service."""

    status: str = Field(..., description="Service status")
    parser_name: str = Field(..., description="Parser name")
    parser_version: str = Field(..., description="Parser version")
    model_hash: str = Field(..., description="Model hash")
    cpu_only: bool = Field(..., description="CPU-only mode")
    environment_digest: str = Field(..., description="Environment hash")
