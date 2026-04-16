"""
Pydantic schemas for the Olympus ingest API.

This module contains request and response models for record ingestion,
proof retrieval, and artifact commitment endpoints.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Identifier validation patterns
# ---------------------------------------------------------------------------

# Allowlist pattern for identifier fields. Permits alphanumeric chars plus the
# small set of punctuation needed for record/artifact IDs
# (e.g. "org/repo/v1.2.3-rc.1", "doc-001").
# Deliberately excludes control characters, null bytes, shell metacharacters
# (\ * ? < > | ; ` $ ! &), and Unicode homoglyphs (pure ASCII allowlist).
SHARD_ID_PATTERN = r"^[a-zA-Z0-9_.:\-]+$"
IDENTIFIER_PATTERN = r"^[a-zA-Z0-9_./:@+\-]+$"
IDENTIFIER_MAX_LEN = 256
# Artifact IDs (e.g. 'org/repo/v1.2.3-rc.1+build.42') are typically longer than shard/record IDs.
ARTIFACT_ID_MAX_LEN = 512
# Accept mixed-case UUIDs from clients; normalize to lowercase before lookup.
PROOF_ID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"

# H-3 Fix: Content validation limits (matching canonicalizer limits).
# These are enforced at Pydantic deserialization time, before the potentially
# expensive canonicalization step, to prevent DoS via deeply nested JSON.
MAX_CONTENT_DEPTH = 128  # Maximum nesting depth for content JSON
MAX_CONTENT_SIZE_ESTIMATE = 16 * 1024 * 1024  # 16 MiB rough size limit per record content


# ---------------------------------------------------------------------------
# Content validation helpers
# ---------------------------------------------------------------------------


def check_json_depth(obj: Any, current_depth: int = 0) -> int:
    """Check the nesting depth of a JSON-like object.

    Uses an iterative approach (explicit stack) to avoid Python recursion
    limits on adversarial input (L-4 hardening).

    Args:
        obj: The object to check.
        current_depth: Initial depth offset (normally 0).

    Returns:
        Maximum depth found in the object.

    Raises:
        ValueError: If depth exceeds MAX_CONTENT_DEPTH.
    """
    max_depth = current_depth
    # Explicit stack of (value, depth) pairs replaces recursion
    stack: list[tuple[Any, int]] = [(obj, current_depth)]

    while stack:
        current, depth = stack.pop()

        if depth >= MAX_CONTENT_DEPTH:
            raise ValueError(f"Content nesting depth exceeds limit of {MAX_CONTENT_DEPTH}")

        if depth > max_depth:
            max_depth = depth

        if isinstance(current, dict):
            for value in current.values():
                stack.append((value, depth + 1))
        elif isinstance(current, list):
            for item in current:
                stack.append((item, depth + 1))

    return max_depth


def estimate_json_size(obj: Any) -> int:
    """Estimate the serialized size of a JSON-like object.

    This is a rough estimate based on traversing the object. It's not exact
    but is good enough to catch obvious DoS attempts before full serialization.

    Uses an iterative approach (explicit stack) to avoid Python recursion
    limits on adversarial input, consistent with check_json_depth().

    Args:
        obj: The object to estimate size for.

    Returns:
        Estimated size in bytes.
    """
    total_size = 0
    # Stack of items to process: (value, container_overhead)
    # container_overhead accounts for separators (commas between items)
    stack: list[tuple[Any, int]] = [(obj, 0)]

    while stack:
        current, overhead = stack.pop()
        total_size += overhead

        if current is None:
            total_size += 4  # "null"
        elif isinstance(current, bool):
            total_size += 5  # "true" or "false"
        elif isinstance(current, (int, float)):
            total_size += len(str(current))
        elif isinstance(current, str):
            # UTF-8 encoding for accurate size + surrounding JSON double-quote characters
            total_size += len(current.encode("utf-8")) + 2
        elif isinstance(current, dict):
            # braces
            total_size += 2  # {}
            items = list(current.items())
            for i, (key, value) in enumerate(items):
                # Key UTF-8 encoded + surrounding quotes + colon
                total_size += len(str(key).encode("utf-8")) + 2 + 1
                # Add comma overhead for non-last items
                comma_overhead = 1 if i < len(items) - 1 else 0
                stack.append((value, comma_overhead))
        elif isinstance(current, list):
            # brackets
            total_size += 2  # []
            for i, item in enumerate(current):
                # Add comma overhead for non-last items
                comma_overhead = 1 if i < len(current) - 1 else 0
                stack.append((item, comma_overhead))
        else:
            total_size += len(str(current))

    return total_size


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class RecordInput(BaseModel):
    """A single record to ingest."""

    shard_id: str = Field(
        ...,
        description="Target shard identifier",
        max_length=IDENTIFIER_MAX_LEN,
        pattern=SHARD_ID_PATTERN,
    )
    record_type: str = Field(
        ...,
        description="Record type (e.g. 'document')",
        max_length=IDENTIFIER_MAX_LEN,
        pattern=IDENTIFIER_PATTERN,
    )
    record_id: str = Field(
        ...,
        description="Unique record identifier",
        max_length=IDENTIFIER_MAX_LEN,
        pattern=IDENTIFIER_PATTERN,
    )
    version: int = Field(..., ge=1, description="Record version (≥ 1)")
    content: dict[str, Any] = Field(..., description="Record content (JSON document)")

    @field_validator("content")
    @classmethod
    def validate_content_limits(cls, v: dict[str, Any]) -> dict[str, Any]:
        """H-3 Fix: Validate content depth and size at Pydantic layer.

        This prevents DoS attacks via deeply nested or very large JSON content
        before the expensive canonicalization step runs.
        """
        # Check depth
        try:
            check_json_depth(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

        # Estimate size
        estimated_size = estimate_json_size(v)
        if estimated_size > MAX_CONTENT_SIZE_ESTIMATE:
            raise ValueError(
                f"Content size estimate ({estimated_size} bytes) exceeds limit "
                f"of {MAX_CONTENT_SIZE_ESTIMATE} bytes per record"
            )

        return v


class BatchIngestionRequest(BaseModel):
    """Request body for batch record ingestion."""

    records: list[RecordInput] = Field(
        ..., min_length=1, max_length=1000, description="Records to ingest"
    )


class IngestionResult(BaseModel):
    """Result for a single ingested record."""

    proof_id: str = Field(
        ...,
        description="Proof identifier for async retrieval",
        pattern=PROOF_ID_PATTERN,
        max_length=36,
    )
    record_id: str
    shard_id: str
    content_hash: str = Field(..., description="BLAKE3 content hash (hex)")
    deduplicated: bool = Field(False, description="True if record was already present")
    idempotent: bool = Field(
        False,
        description=(
            "True when this response returns an existing record instead of "
            "creating a new one. Callers can use this to distinguish a fresh "
            "insert from a deduplicated return."
        ),
    )


class BatchIngestionResponse(BaseModel):
    """Response for a batch ingestion request."""

    ingested: int = Field(..., description="Number of records ingested")
    deduplicated: int = Field(..., description="Number of duplicates skipped")
    results: list[IngestionResult]
    ledger_entry_hash: str = Field(..., description="Hash of the ledger entry for this batch")
    timestamp: str
    canonicalization: dict[str, Any]
    batch_id: str | None = Field(None, description="Durable batch identifier")


class IngestionProofResponse(BaseModel):
    """Proof for an ingested record."""

    proof_id: str = Field(..., pattern=PROOF_ID_PATTERN, max_length=36)
    record_id: str
    shard_id: str
    content_hash: str
    merkle_root: str
    merkle_proof: dict[str, Any]
    ledger_entry_hash: str
    timestamp: str
    canonicalization: dict[str, Any]
    batch_id: str | None = Field(None, description="Batch identifier if available")
    poseidon_root: str | None = Field(
        None, description="Optional Poseidon root associated with the commitment"
    )


class HashVerificationResponse(IngestionProofResponse):
    """Verification result for a committed content hash."""

    merkle_proof_valid: bool


class ProofVerificationRequest(BaseModel):
    """Request body for server-side verification of a proof bundle."""

    proof_id: str | None = Field(
        None,
        description="Optional client-side proof identifier",
        pattern=PROOF_ID_PATTERN,
        max_length=36,
    )
    content_hash: str = Field(..., description="Hex-encoded BLAKE3 hash committed by Olympus")
    merkle_root: str = Field(..., description="Hex-encoded Merkle root anchoring the content hash")
    merkle_proof: dict[str, Any] = Field(..., description="Serialized Merkle proof bundle")


class ProofVerificationResponse(BaseModel):
    """Server-side verification result for a submitted proof bundle."""

    proof_id: str | None = Field(None, pattern=PROOF_ID_PATTERN, max_length=36)
    content_hash: str
    merkle_root: str
    content_hash_matches_proof: bool
    merkle_proof_valid: bool
    known_to_server: bool
    poseidon_root: str | None = None


# DEPRECATED: submit_proof_bundle no longer accepts a JSON body.
# Retained for migration period. Will be removed in a future release.
class ProofSubmissionRequest(ProofVerificationRequest):
    """Proof bundle payload that can be submitted to the API for later retrieval."""

    record_id: str = Field(
        ...,
        description="Record identifier associated with the proof bundle",
        max_length=IDENTIFIER_MAX_LEN,
        pattern=IDENTIFIER_PATTERN,
    )
    shard_id: str = Field(
        ...,
        description="Shard identifier associated with the proof bundle",
        max_length=IDENTIFIER_MAX_LEN,
        pattern=SHARD_ID_PATTERN,
    )
    ledger_entry_hash: str = Field(..., description="Ledger entry anchoring the proof bundle")
    timestamp: str = Field(..., description="ISO 8601 timestamp associated with the bundle")
    canonicalization: dict[str, Any] = Field(
        ..., description="Canonicalization provenance metadata"
    )
    batch_id: str | None = Field(None, description="Optional batch identifier for the proof bundle")


class ProofSubmissionResponse(IngestionProofResponse):
    """Response body for a proof bundle submitted to the ingest API."""

    submitted: bool
    deduplicated: bool


class ArtifactCommitRequest(BaseModel):
    """Request body for committing a pre-computed artifact hash to the ledger.

    Security boundary:
        ``id`` and ``namespace`` are validated by ``IDENTIFIER_PATTERN`` at API
        ingestion time before persistence. This keeps externally supplied
        artifact identifiers constrained before they can flow into downstream
        proof tooling and subprocess-based proof backends.
    """

    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash of the artifact")
    namespace: str = Field(
        ...,
        description="Namespace for the artifact (e.g. 'github')",
        max_length=IDENTIFIER_MAX_LEN,
        pattern=IDENTIFIER_PATTERN,
    )
    id: str = Field(
        ...,
        description="Artifact identifier (e.g. 'org/repo/v1.0.0')",
        max_length=ARTIFACT_ID_MAX_LEN,
        pattern=IDENTIFIER_PATTERN,
    )
    source_url: str | None = Field(
        None,
        description="Optional http(s) URL describing where the artifact was retrieved from",
        max_length=2048,
    )
    raw_pdf_hash: str | None = Field(
        None,
        description=(
            "Optional 64-character hex-encoded raw-PDF BLAKE3 hash anchored "
            "alongside OCR/text hashes"
        ),
    )


class ArtifactCommitResponse(BaseModel):
    """Response for a successful artifact commitment."""

    proof_id: str = Field(..., description="Proof identifier for future verification")
    artifact_hash: str = Field(..., description="Hex-encoded BLAKE3 hash that was committed")
    namespace: str
    id: str
    committed_at: str = Field(..., description="ISO 8601 commitment timestamp")
    ledger_entry_hash: str = Field(..., description="Hash of the ledger entry")
    poseidon_root: str | None = Field(
        None, description="Optional Poseidon root bound to the artifact commitment"
    )
