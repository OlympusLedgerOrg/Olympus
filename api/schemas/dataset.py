"""
Pydantic v2 schemas for dataset provenance endpoints (ADR-0010).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared sub-models
# ---------------------------------------------------------------------------


class DatasetFileEntry(BaseModel):
    """A single file entry within a dataset manifest."""

    path: str = Field(..., max_length=2048)
    content_hash: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    byte_size: int = Field(..., ge=0)
    record_count: int | None = Field(None, ge=0)


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class DatasetCommitRequest(BaseModel):
    """Manifest submitted by the caller.  Caller signs; server verifies."""

    # Dataset identity
    dataset_name: str = Field(..., max_length=256)
    dataset_version: str = Field(..., max_length=64)
    source_uri: str = Field(..., max_length=2048, pattern=r"^https?://.+")
    canonical_namespace: str = Field(..., max_length=256)
    granularity: Literal["file", "record", "shard"]

    # Licensing
    license_spdx: str = Field(..., max_length=64)
    license_uri: str | None = Field(None, max_length=2048)
    usage_restrictions: list[str] = Field(default_factory=list)

    # Content
    file_format: str = Field(..., max_length=32)
    files: list[DatasetFileEntry] = Field(..., min_length=1)

    # Provenance
    parent_dataset_id: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")
    parent_commit_id: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")
    transform_description: str | None = None

    # Cryptographic identity
    committer_pubkey: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    committer_label: str | None = Field(None, max_length=256)
    commit_signature: str = Field(..., pattern=r"^[0-9a-f]{128}$")

    # Canonicalization
    manifest_schema_version: str = Field(default="dataset_manifest_v1", max_length=32)


class LineageCommitRequest(BaseModel):
    """Request body for POST /datasets/{dataset_id}/lineage."""

    dataset_id: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    model_id: str = Field(..., max_length=256)
    model_version: str | None = Field(None, max_length=64)
    model_org: str | None = Field(None, max_length=256)
    event_type: Literal["training_started", "training_completed", "evaluation"]
    committer_pubkey: str = Field(..., pattern=r"^[0-9a-f]{64}$")
    commit_signature: str = Field(..., pattern=r"^[0-9a-f]{128}$")


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class DatasetCommitResponse(BaseModel):
    """Response body for POST /datasets/commit."""

    dataset_id: str
    commit_id: str
    manifest_hash: str
    epoch: datetime
    shard_id: str
    merkle_root: str | None
    file_count: int
    timestamp_status: str
    rfc3161_tsa_url: str | None = None
    rfc3161_timestamp: str | None = None


class DatasetDetailResponse(DatasetCommitResponse):
    """Full record including files and provenance chain."""

    dataset_name: str
    dataset_version: str
    source_uri: str
    license_spdx: str
    committer_pubkey: str
    committer_label: str | None
    parent_commit_id: str
    parent_dataset_id: str | None
    anchor_tx_hash: str | None
    anchor_network: str | None
    files: list[DatasetFileEntry]
    proof_bundle_uri: str | None


class DatasetProofBundleResponse(BaseModel):
    """Self-contained verification bundle for a dataset commit."""

    dataset_id: str
    commit_id: str
    manifest_hash: str
    merkle_root: str | None
    committer_pubkey: str
    commit_signature: str
    epoch: datetime
    shard_id: str
    dataset_name: str
    source_uri: str
    files: list[DatasetFileEntry]
    merkle_proof: list[dict] | None = None
    signature_valid: bool
    commit_id_valid: bool


class DatasetVerifyResponse(BaseModel):
    """Response body for GET /datasets/{dataset_id}/verify."""

    verified: bool
    checks: dict[str, bool] = {}
    dataset: DatasetCommitResponse | None = None
    merkle_proof: list[dict] | None = None
    rfc3161_valid: bool | None = None
    signature_valid: bool | None = None
    commit_id_valid: bool | None = None
    chain_valid: bool | None = None
    key_revoked: bool | None = None
    zk_proof: dict | None = None


class LineageCommitResponse(BaseModel):
    """Response body for POST /datasets/{dataset_id}/lineage."""

    commit_id: str
    dataset_id: str
    model_id: str
    event_type: str
    epoch: datetime
    timestamp_status: str


class DatasetListResponse(BaseModel):
    """Paginated list of datasets."""

    items: list[DatasetCommitResponse]
    page: int
    per_page: int
    total: int


class DatasetHistoryEntry(BaseModel):
    """A single entry in dataset version history."""

    commit_id: str
    parent_commit_id: str
    dataset_version: str
    epoch: datetime
    committer_pubkey: str
    committer_label: str | None
    manifest_hash: str
    file_count: int


class DatasetHistoryResponse(BaseModel):
    """Ordered commit history for a logical dataset."""

    dataset_id: str
    commits: list[DatasetHistoryEntry]
