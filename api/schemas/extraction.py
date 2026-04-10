"""
Pydantic v2 schemas for document extraction endpoints.

These schemas define the API contract for document extraction, providing
a bridge between raw document uploads and the ingest-parser-service.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ExtractRequest(BaseModel):
    """Request body for POST /extract endpoint.

    The file is uploaded via multipart form data, not in this body.
    This schema captures additional request parameters.
    """

    expected_blake3: str | None = Field(
        None,
        pattern=r"^blake3_[0-9a-f]{64}$",
        description=(
            "Optional expected BLAKE3 hash of the uploaded file. "
            "If provided, the request fails if the hash doesn't match."
        ),
    )
    auto_detect_pii: bool = Field(
        False,
        description=(
            "If true, automatically detect and flag PII fields for redaction. "
            "Requires Presidio integration to be enabled."
        ),
    )
    commit_after_extract: bool = Field(
        False,
        description=(
            "If true, automatically commit the canonical extraction to the ledger. "
            "Returns commit_id in the response."
        ),
    )
    shard_id: str | None = Field(
        None,
        pattern=r"^[a-zA-Z0-9_.:\-]+$",
        description="Optional shard ID for the commitment (required if commit_after_extract=true).",
    )


class ExtractionProvenance(BaseModel):
    """Provenance metadata for the extraction.

    Captures all information needed to reproduce the exact same
    extraction output given the same input file.
    """

    raw_file_blake3: str = Field(
        ...,
        description="BLAKE3 hash of the raw input file (blake3_ prefix)",
    )
    parser_name: str = Field(
        ...,
        description="Name of the parser backend (e.g., 'docling', 'fallback')",
    )
    parser_version: str = Field(
        ...,
        description="Semantic version of the parser",
    )
    model_hash: str = Field(
        ...,
        description="SHA256 hash of the AI model weights (sha256_ prefix)",
    )
    environment_digest: str = Field(
        ...,
        description="SHA256 hash of the parser service environment",
    )


class ContentBlockResponse(BaseModel):
    """A content block from the extracted document."""

    id: str = Field(..., description="Block identifier")
    type: str = Field(..., description="Block type (text, table, image, etc.)")
    content: str = Field(..., description="Extracted text content")
    bbox: list[float] = Field(
        ...,
        description="Bounding box [x1, y1, x2, y2] rounded to 4 decimal places",
    )
    confidence: float | None = Field(None, description="Extraction confidence (0-1)")
    is_redactable: bool = Field(
        False,
        description="Whether this block contains PII and should be redactable",
    )
    pii_types: list[str] = Field(
        default_factory=list,
        description="Types of PII detected (e.g., 'SSN', 'PHONE_NUMBER')",
    )


class PageResponse(BaseModel):
    """A page from the extracted document."""

    page_number: int = Field(..., ge=1, description="1-indexed page number")
    width: float | None = Field(None, description="Page width in points")
    height: float | None = Field(None, description="Page height in points")
    blocks: list[ContentBlockResponse] = Field(
        default_factory=list,
        description="Content blocks on this page",
    )


class ExtractedDocumentResponse(BaseModel):
    """The extracted document content."""

    pages: list[PageResponse] = Field(default_factory=list, description="Document pages")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    language: str | None = Field(None, description="Detected language (ISO 639-1)")


class ExtractResponse(BaseModel):
    """Response body for POST /extract endpoint."""

    provenance: ExtractionProvenance = Field(
        ...,
        description="Cryptographic provenance metadata",
    )
    document: ExtractedDocumentResponse = Field(
        ...,
        description="Extracted document content",
    )
    canonical_hash: str | None = Field(
        None,
        description="BLAKE3 hash of the canonical JSON (after RFC 8785 canonicalization)",
    )
    commit_id: str | None = Field(
        None,
        pattern=r"^0x[0-9a-f]{64}$",
        description="Commit ID if commit_after_extract was true",
    )
    extracted_at: datetime = Field(
        ...,
        description="Timestamp of extraction",
    )


class ExtractStatusResponse(BaseModel):
    """Response body for GET /extract/status endpoint."""

    parser_available: bool = Field(
        ...,
        description="Whether the parser service is available",
    )
    parser_name: str | None = Field(
        None,
        description="Parser backend name",
    )
    parser_version: str | None = Field(
        None,
        description="Parser version",
    )
    cpu_only: bool = Field(
        True,
        description="Whether CPU-only mode is enforced",
    )
    supported_types: list[str] = Field(
        default_factory=list,
        description="List of supported MIME types",
    )


class PiiDetectionResult(BaseModel):
    """Result of PII detection on a content block."""

    block_id: str = Field(..., description="ID of the content block")
    pii_findings: list[dict[str, Any]] = Field(
        default_factory=list,
        description="List of PII findings with type, score, and position",
    )
    is_redactable: bool = Field(
        ...,
        description="Whether this block should be marked as redactable",
    )
