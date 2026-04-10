"""
Pydantic schemas for the ingest-parser service.

Defines the standardized JSON output format that bridges the AI extraction
world to the Olympus canonicalization pipeline.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


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
    """A single content block extracted from a document.

    All bounding box coordinates are rounded to exactly 4 decimal places
    to ensure deterministic hashing across different execution environments.
    """

    id: str = Field(..., description="Unique block identifier (e.g., 'blk_01')")
    type: BlockType = Field(..., description="Type of content block")
    content: str = Field(..., description="Extracted text content")
    bbox: list[float] = Field(
        ...,
        min_length=4,
        max_length=4,
        description="Bounding box [x1, y1, x2, y2] rounded to 4 decimal places",
    )
    confidence: float | None = Field(
        None, ge=0.0, le=1.0, description="Extraction confidence score"
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional block-specific metadata"
    )

    @field_validator("bbox", mode="before")
    @classmethod
    def round_bbox_coordinates(cls, v: list[float]) -> list[float]:
        """Round all bounding box coordinates to exactly 4 decimal places.

        This is CRITICAL for cryptographic determinism. Floating-point drift
        is the #1 killer of hash stability across environments.
        """
        # bbox is a required field, but this validator runs "before" mode
        # so we handle the case where v might not be the expected type yet
        return [round(float(coord), 4) for coord in v]

    @field_validator("confidence", mode="before")
    @classmethod
    def round_confidence(cls, v: float | None) -> float | None:
        """Round confidence to 4 decimal places for determinism."""
        if v is None:
            return v
        return round(float(v), 4)


class DocumentPage(BaseModel):
    """A single page of an extracted document."""

    page_number: int = Field(..., ge=1, description="1-indexed page number")
    width: float | None = Field(None, description="Page width in points")
    height: float | None = Field(None, description="Page height in points")
    blocks: list[ContentBlock] = Field(
        default_factory=list, description="Content blocks on this page"
    )

    @field_validator("width", "height", mode="before")
    @classmethod
    def round_dimensions(cls, v: float | None) -> float | None:
        """Round page dimensions to 4 decimal places."""
        if v is None:
            return v
        return round(float(v), 4)


class ExtractedDocument(BaseModel):
    """The extracted document content structure."""

    pages: list[DocumentPage] = Field(
        default_factory=list, description="List of document pages"
    )
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    language: str | None = Field(None, description="Detected document language (ISO 639-1)")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Document-level metadata"
    )


class Provenance(BaseModel):
    """Provenance metadata for cryptographic verification.

    This structure captures all information needed to reproduce
    the exact same extraction output given the same input file.

    The canonical_parser_version is the stable identifier used for proof verification.
    When model_hash changes (due to model upgrades), a new canonical_parser_version
    must be assigned. Documents parsed with the same canonical_parser_version are
    guaranteed to produce identical extraction results.
    """

    raw_file_blake3: str = Field(
        ...,
        pattern=r"^blake3_[0-9a-f]{64}$",
        description="BLAKE3 hash of the raw input file (prefixed with 'blake3_')",
    )
    parser_name: str = Field(..., description="Name of the parser used (e.g., 'docling')")
    parser_version: str = Field(..., description="Semantic version of the parser library")
    canonical_parser_version: str = Field(
        ...,
        pattern=r"^v\d+\.\d+$",
        description=(
            "Stable canonical version (e.g., 'v1.0') that maps to a specific "
            "parser_version + model_hash combination. Used for proof verification. "
            "When model_hash changes, this version must be incremented."
        ),
    )
    model_hash: str = Field(
        ...,
        pattern=r"^sha256_[0-9a-f]{64}$",
        description="SHA256 hash of the AI model weights (prefixed with 'sha256_')",
    )
    environment_digest: str = Field(
        ...,
        pattern=r"^sha256_[0-9a-f]{64}$",
        description="SHA256 hash of the Docker image or environment manifest",
    )


class ParseResponse(BaseModel):
    """Complete response from the /parse endpoint.

    This is the standardized JSON structure that bridges AI extraction
    to the Olympus canonicalization pipeline.
    """

    provenance: Provenance = Field(..., description="Cryptographic provenance metadata")
    document: ExtractedDocument = Field(..., description="Extracted document content")


class ParseRequest(BaseModel):
    """Request metadata for the /parse endpoint (used with multipart form)."""

    expected_blake3: str | None = Field(
        None,
        pattern=r"^blake3_[0-9a-f]{64}$",
        description="Optional: expected BLAKE3 hash for verification",
    )


class HealthResponse(BaseModel):
    """Response from the /health endpoint."""

    status: str = Field(..., description="Service status ('healthy' or 'unhealthy')")
    parser_name: str = Field(..., description="Parser name")
    parser_version: str = Field(..., description="Parser version")
    model_hash: str = Field(..., description="Model weights hash")
    cpu_only: bool = Field(..., description="Whether CPU-only mode is enforced")
    environment_digest: str = Field(..., description="Environment manifest hash")


class ErrorResponse(BaseModel):
    """Error response structure."""

    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Human-readable error message")
    details: dict[str, Any] | None = Field(None, description="Additional error details")
