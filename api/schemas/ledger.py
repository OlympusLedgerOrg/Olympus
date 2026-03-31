"""
Pydantic v2 schemas for ledger endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class LedgerStateResponse(BaseModel):
    """Response for GET /ledger/state."""

    global_state_root: str
    shard_count: int
    total_commits: int
    last_epoch: datetime | None


class CommitSummary(BaseModel):
    """Compact commit summary used in shard listings."""

    commit_id: str
    doc_hash: str
    epoch: datetime
    shard_id: str
    merkle_root: str | None


class ShardStateResponse(BaseModel):
    """Response for GET /ledger/shard/{shard_id}."""

    shard_id: str
    state_root: str
    commit_count: int
    latest_commits: list[CommitSummary]


class ProofResponse(BaseModel):
    """Response for GET /ledger/proof/{commit_id}."""

    commit_id: str
    merkle_proof: list[dict]
    zk_proof: dict | None
    shard_id: str
    epoch: datetime
    proof_type: str = "unknown"  # "groth16" | "stub" | "pending" | "unknown"


class PendingProofResponse(BaseModel):
    """Returned when ZK proof generation is pending ceremony completion."""

    commit_id: str
    shard_id: str
    epoch: datetime
    status: Literal["pending"]
    reason: str
    merkle_proof: list[dict] | None = None


# ── User-friendly schemas ─────────────────────────────────────────────────────


class ProcessStep(BaseModel):
    """A single step in a multi-step operation shown to the user.

    Attributes:
        step_number: 1-based position in the process.
        title: Short label for this step.
        status: One of ``pending``, ``in_progress``, ``complete``, ``failed``.
        icon: Display icon string (e.g. ``"✓"``, ``"✗"``, ``"⏳"``).
        message: Human-readable description of what happened.
        details: Optional technical details for advanced users.
        timestamp: When this step completed.
    """

    step_number: int
    title: str
    status: Literal["pending", "in_progress", "complete", "failed"]
    icon: str
    message: str
    details: dict | None = None
    timestamp: datetime | None = None


class SimpleIngestionResponse(BaseModel):
    """User-friendly response for POST /ledger/ingest/simple.

    Attributes:
        success: Whether the document was successfully added to the ledger.
        summary: One-sentence plain-English outcome.
        steps: Ordered list of processing steps with status indicators.
        commit_id: Technical commit identifier (for reference).
        permanent_record_id: Display-friendly ID such as ``"OLY-0123"``.
        what_this_means: Plain-English explanation of what was done.
        next_steps: Suggested actions for the user after a successful submission.
        error_help: Guidance on how to resolve the problem (only set on failure).
    """

    success: bool
    summary: str
    steps: list[ProcessStep]
    commit_id: str | None = None
    permanent_record_id: str | None = None
    what_this_means: str
    next_steps: str | None = None
    error_help: str | None = None


class SimpleVerificationResponse(BaseModel):
    """User-friendly response for POST /ledger/verify/simple.

    Attributes:
        verified: Whether the document was found in the ledger.
        summary: One-sentence plain-English verdict.
        confidence: How certain the system is (``"certain"`` or ``"uncertain"``).
        recorded_date: When the document was originally recorded.
        related_request: Display ID of the FOIA request this document belongs to.
        proof_details: Step-by-step breakdown of the verification process.
        what_this_means: Plain-English explanation of the verdict.
        why_this_matters: Context about why cryptographic verification is important.
    """

    verified: bool
    summary: str
    confidence: Literal["certain", "uncertain", "none"]
    recorded_date: datetime | None = None
    related_request: str | None = None
    failure_reason: str | None = None
    proof_details: list[ProcessStep]
    what_this_means: str
    why_this_matters: str


class ActivityItem(BaseModel):
    """A single entry in the activity feed.

    Attributes:
        id: UUID of this activity record.
        timestamp: When the activity occurred.
        activity_type: Machine-readable category.
        title: Short human-readable title.
        description: Plain-English explanation.
        related_commit_id: Technical commit reference (optional).
        related_request_id: FOIA request reference (optional).
        user_friendly_status: Display badge.
    """

    id: str
    timestamp: datetime
    activity_type: str
    title: str
    description: str
    related_commit_id: str | None = None
    related_request_id: str | None = None
    user_friendly_status: str


class ActivityFeedResponse(BaseModel):
    """Response for GET /ledger/activity.

    Attributes:
        items: Ordered list of activity entries (newest first).
        total: Total number of activities matching the filter.
    """

    items: list[ActivityItem]
    total: int
