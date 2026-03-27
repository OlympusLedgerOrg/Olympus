"""
Step-by-step document ingestion service for non-technical users.

This module wraps the low-level commit pipeline with human-readable
progress tracking so the frontend can show each processing stage with
a clear status indicator and plain-English message.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.models.document import DocCommit
from api.models.ledger_activity import LedgerActivity
from api.schemas.ledger import ProcessStep, SimpleIngestionResponse
from api.services.hasher import generate_commit_id, hash_document
from api.services.merkle import build_tree
from api.services.shard import compute_state_root

logger = logging.getLogger(__name__)

# Supported MIME types / extensions for non-technical user guidance
_SUPPORTED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "text/plain",
    "text/html",
    "image/png",
    "image/jpeg",
    "image/tiff",
}

_SUPPORTED_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".txt",
    ".html",
    ".htm",
    ".png",
    ".jpg",
    ".jpeg",
    ".tif",
    ".tiff",
}


def _make_step(
    number: int,
    title: str,
    status: str,
    message: str,
    icon: str | None = None,
    details: dict | None = None,
    timestamp: datetime | None = None,
) -> ProcessStep:
    """Build a :class:`ProcessStep` with a default icon derived from status."""
    if icon is None:
        icon = {"complete": "✓", "failed": "✗", "in_progress": "⏳", "pending": "○"}.get(
            status, "○"
        )
    return ProcessStep(
        step_number=number,
        title=title,
        status=status,  # type: ignore[arg-type]
        icon=icon,
        message=message,
        details=details,
        timestamp=timestamp or datetime.now(timezone.utc),
    )


def _format_epoch(epoch: datetime) -> str:
    """Format a UTC datetime as a human-readable string (cross-platform).

    Returns a string like ``"January 15, 2025 at 2:34 PM UTC"`` without
    platform-specific ``%-d`` / ``%-I`` strftime directives.
    """
    day = epoch.day
    hour = epoch.hour % 12 or 12
    am_pm = "AM" if epoch.hour < 12 else "PM"
    return epoch.strftime(f"%B {day}, %Y at {hour}:{epoch.strftime('%M')} {am_pm} UTC")


async def ingest_document(
    file_bytes: bytes,
    filename: str,
    content_type: str | None,
    request_id: str | None,
    description: str | None,
    db: AsyncSession,
) -> SimpleIngestionResponse:
    """Ingest a document into the ledger with step-by-step user feedback.

    Runs the full commit pipeline and returns a :class:`SimpleIngestionResponse`
    that describes each processing step in plain English.  On failure the
    response still includes all completed steps so the user knows exactly
    where things went wrong.

    Args:
        file_bytes: Raw bytes of the uploaded file.
        filename: Original filename (used for extension checking).
        content_type: MIME type reported by the client.
        request_id: Optional FOIA request display-ID to associate with.
        description: Optional plain-English description of the document.
        db: Async database session.

    Returns:
        :class:`SimpleIngestionResponse` with all steps and outcome.
    """
    steps: list[ProcessStep] = []

    # ── Step 1: File received ────────────────────────────────────────────────
    file_size_kb = len(file_bytes) / 1024
    if file_size_kb >= 1024:
        size_label = f"{file_size_kb / 1024:.1f} MB"
    else:
        size_label = f"{file_size_kb:.1f} KB"

    steps.append(
        _make_step(1, "File Received", "complete", f"File '{filename}' received ({size_label}).")
    )

    # ── Step 2: File type validation ─────────────────────────────────────────
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    mime_ok = (content_type or "").lower().split(";")[0].strip() in _SUPPORTED_MIME_TYPES
    ext_ok = ext in _SUPPORTED_EXTENSIONS

    if not (mime_ok or ext_ok):
        steps.append(
            _make_step(
                2,
                "File Type Check",
                "failed",
                f"The file type '{ext or content_type}' is not supported.",
            )
        )
        return SimpleIngestionResponse(
            success=False,
            summary="This file type is not supported.",
            steps=steps,
            what_this_means=(
                "Only common document formats can be added to the ledger to ensure "
                "long-term readability and integrity."
            ),
            error_help=(
                "Please upload a PDF, Word document (.doc/.docx), plain text (.txt), "
                "or image file (PNG/JPEG/TIFF)."
            ),
        )

    steps.append(_make_step(2, "File Type Check", "complete", f"File type '{ext}' is accepted."))

    # ── Step 3: Cryptographic hash ───────────────────────────────────────────
    try:
        doc_hash = hash_document(file_bytes)
    except Exception as exc:
        logger.exception("Hashing failed for file %s", filename)
        steps.append(
            _make_step(
                3, "Creating Cryptographic Fingerprint", "failed", "Failed to hash the document."
            )
        )
        return SimpleIngestionResponse(
            success=False,
            summary="Could not create a cryptographic fingerprint for this file.",
            steps=steps,
            what_this_means="An internal error prevented the document from being processed.",
            error_help="Please try again. If the problem persists, the file may be corrupted.",
        )

    steps.append(
        _make_step(
            3,
            "Cryptographic Fingerprint Created",
            "complete",
            (
                "A unique BLAKE3 fingerprint was created for this document. "
                "Even a single changed character would produce a completely different fingerprint."
            ),
            details={"doc_hash": doc_hash},
        )
    )

    # ── Step 4: Duplicate check ──────────────────────────────────────────────
    existing_result = await db.execute(
        select(DocCommit).where(DocCommit.doc_hash == doc_hash).limit(1)
    )
    existing = existing_result.scalars().first()

    if existing:
        steps.append(
            _make_step(
                4,
                "Duplicate Check",
                "complete",
                "This document is already in the permanent record.",
                details={"existing_commit_id": existing.commit_id},
            )
        )
        epoch_str = _format_epoch(existing.epoch_timestamp)
        return SimpleIngestionResponse(
            success=True,
            summary="This document is already in the permanent record.",
            steps=steps,
            commit_id=existing.commit_id,
            permanent_record_id=_display_id(existing.commit_id),
            what_this_means=(
                f"This exact document was previously recorded on {epoch_str}. "
                "No duplicate entry was created — the existing record is still valid."
            ),
            next_steps=(
                f"Use the permanent record ID '{_display_id(existing.commit_id)}' to "
                "reference or verify this document in the future."
            ),
        )

    steps.append(
        _make_step(4, "Duplicate Check", "complete", "This document has not been submitted before.")
    )

    # ── Step 5: Commit to ledger ─────────────────────────────────────────────
    try:
        commit_id = generate_commit_id()
        shard_id = "0x4F3A"

        # Compute Merkle root for the shard after adding this commit
        existing_hashes_result = await db.execute(
            select(DocCommit.doc_hash)
            .where(DocCommit.shard_id == shard_id)
            .order_by(DocCommit.epoch_timestamp)
        )
        existing_hashes = list(existing_hashes_result.scalars().all())
        all_hashes = existing_hashes + [doc_hash]
        merkle_root = build_tree(all_hashes, preserve_order=True).root_hash

        commit = DocCommit(
            id=str(uuid.uuid4()),
            request_id=None,  # request_id FK is a UUID; display IDs like OLY-0001 are not stored here
            doc_hash=doc_hash,
            commit_id=commit_id,
            shard_id=shard_id,
            merkle_root=merkle_root,
        )
        db.add(commit)
        await db.commit()
        await db.refresh(commit)

    except Exception:
        logger.exception("Failed to commit document %s to ledger", filename)
        await db.rollback()
        steps.append(
            _make_step(
                5,
                "Adding to Permanent Record",
                "failed",
                "Failed to save the document to the ledger.",
            )
        )
        return SimpleIngestionResponse(
            success=False,
            summary="The document could not be added to the permanent record.",
            steps=steps,
            what_this_means="An internal database error occurred.",
            error_help="Please try again in a moment. If the problem continues, contact the system administrator.",
        )

    steps.append(
        _make_step(
            5,
            "Added to Permanent Record",
            "complete",
            (
                "The document's fingerprint has been permanently recorded in the ledger "
                "and cannot be altered or deleted."
            ),
            details={"commit_id": commit_id, "merkle_root": merkle_root},
        )
    )

    # ── Record a human-readable activity log entry ───────────────────────────
    display_id = _display_id(commit_id)
    activity = LedgerActivity(
        activity_type="DOCUMENT_SUBMITTED",
        title="Document Added to Permanent Record",
        description=(
            f"A document '{filename}' ({size_label}) was permanently recorded. "
            + (f"Description: {description}. " if description else "")
            + f"Record ID: {display_id}."
        ),
        related_commit_id=commit_id,
        related_request_id=request_id,
        user_friendly_status="✓ Complete",
        details_json=json.dumps(
            {"filename": filename, "doc_hash": doc_hash, "display_id": display_id}
        ),
    )
    db.add(activity)
    await db.commit()

    return SimpleIngestionResponse(
        success=True,
        summary="Your document was successfully added to the permanent record.",
        steps=steps,
        commit_id=commit_id,
        permanent_record_id=display_id,
        what_this_means=(
            "A cryptographic fingerprint of this document has been permanently recorded "
            "in the Olympus ledger. This creates an immutable timestamp proving the "
            "document existed in its current form at this moment. It cannot be altered, "
            "deleted, or backdated."
        ),
        next_steps=(
            f"Save your permanent record ID: {display_id}. You can use it at any time "
            "to verify this document or share proof of its existence."
        ),
    )


def _display_id(commit_id: str) -> str:
    """Convert a raw commit ID to a human-friendly display ID like ``OLY-0042``.

    Uses the last 4 hex digits of the commit ID converted to a decimal number.
    """
    try:
        numeric = int(commit_id.lstrip("0x")[-4:], 16)
        return f"OLY-{numeric:04d}"
    except (ValueError, IndexError):
        return f"OLY-{abs(hash(commit_id)) % 10000:04d}"
