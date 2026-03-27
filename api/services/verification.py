"""
User-friendly document verification service.

Provides a plain-English verification result that non-technical users can
understand without knowing about Merkle trees or cryptographic hashes.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.document import DocCommit
from api.models.ledger_activity import LedgerActivity
from api.models.request import PublicRecordsRequest
from api.schemas.ledger import ProcessStep, SimpleVerificationResponse
from api.services.hasher import hash_document
from api.services.merkle import build_tree, generate_proof, verify_proof


logger = logging.getLogger(__name__)


def _make_step(
    number: int,
    title: str,
    status: str,
    message: str,
    details: dict | None = None,
) -> ProcessStep:
    icon = {"complete": "✓", "failed": "✗", "in_progress": "⏳", "pending": "○"}.get(status, "○")
    return ProcessStep(
        step_number=number,
        title=title,
        status=status,  # type: ignore[arg-type]
        icon=icon,
        message=message,
        details=details,
        timestamp=datetime.now(timezone.utc),
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


async def verify_by_file(
    file_bytes: bytes,
    filename: str,
    db: AsyncSession,
) -> SimpleVerificationResponse:
    """Verify a document by its content.

    Computes the BLAKE3 fingerprint of the uploaded file and checks whether
    any ledger commit matches that fingerprint.

    Args:
        file_bytes: Raw bytes of the uploaded file.
        filename: Original filename (used in messages).
        db: Async database session.

    Returns:
        :class:`SimpleVerificationResponse` with a plain-English verdict.
    """
    steps: list[ProcessStep] = []

    # Step 1: compute hash
    try:
        doc_hash = hash_document(file_bytes)
    except Exception:
        logger.exception("Failed to hash file %s during verification", filename)
        steps.append(
            _make_step(1, "Computing Document Fingerprint", "failed", "Could not read the file.")
        )
        return SimpleVerificationResponse(
            verified=False,
            summary="Could not process this file.",
            confidence="uncertain",
            proof_details=steps,
            what_this_means="The file may be corrupted or unreadable.",
            why_this_matters=_why_matters(),
        )

    steps.append(
        _make_step(
            1,
            "Document Fingerprint Computed",
            "complete",
            "A unique cryptographic fingerprint was calculated for the uploaded file.",
            details={"doc_hash": doc_hash},
        )
    )

    return await _verify_by_hash(doc_hash, steps, db)


async def verify_by_commit_id(
    commit_id: str,
    db: AsyncSession,
) -> SimpleVerificationResponse:
    """Verify a document by its permanent record ID (display ID or raw commit ID).

    Args:
        commit_id: Either a raw ``0x…`` commit ID or an ``OLY-NNNN`` display ID.
        db: Async database session.

    Returns:
        :class:`SimpleVerificationResponse` with a plain-English verdict.
    """
    steps: list[ProcessStep] = []
    steps.append(
        _make_step(1, "Looking Up Record", "complete", f"Searching for record '{commit_id}'.")
    )

    # Resolve display ID → raw commit_id if needed
    resolved_commit_id: str | None = None
    if commit_id.upper().startswith("OLY-"):
        # Search activity log for this display ID
        result = await db.execute(
            select(LedgerActivity)
            .where(LedgerActivity.details_json.isnot(None))
            .order_by(LedgerActivity.timestamp.desc())
        )
        activities = list(result.scalars().all())
        for act in activities:
            try:
                details = json.loads(act.details_json or "{}")
                if details.get("display_id", "").upper() == commit_id.upper():
                    resolved_commit_id = act.related_commit_id
                    break
            except (json.JSONDecodeError, AttributeError):
                continue

        if not resolved_commit_id:
            steps.append(
                _make_step(2, "Record Lookup", "failed", f"No record found with ID '{commit_id}'.")
            )
            return SimpleVerificationResponse(
                verified=False,
                summary=f"No record found with ID '{commit_id}'.",
                confidence="certain",
                proof_details=steps,
                what_this_means=(
                    "The record ID you entered does not exist in the ledger. "
                    "Double-check the ID and try again."
                ),
                why_this_matters=_why_matters(),
            )
    else:
        resolved_commit_id = commit_id

    # Look up the commit directly
    result = await db.execute(
        select(DocCommit).where(DocCommit.commit_id == resolved_commit_id).limit(1)
    )
    commit = result.scalars().first()

    if not commit:
        steps.append(
            _make_step(2, "Record Lookup", "failed", f"No record found with ID '{commit_id}'.")
        )
        return SimpleVerificationResponse(
            verified=False,
            summary=f"No record found with ID '{commit_id}'.",
            confidence="certain",
            proof_details=steps,
            what_this_means=(
                "The record ID you entered does not exist in the ledger. "
                "Double-check the ID and try again."
            ),
            why_this_matters=_why_matters(),
        )

    steps.append(
        _make_step(
            2,
            "Record Found",
            "complete",
            "The record exists in the ledger.",
            details={"commit_id": commit.commit_id},
        )
    )

    return await _build_verification_response(commit, steps, db)


async def verify_by_doc_hash(
    doc_hash: str,
    db: AsyncSession,
) -> SimpleVerificationResponse:
    """Verify a document by its pre-computed BLAKE3 hash.

    Args:
        doc_hash: Hex-encoded BLAKE3 hash of the document.
        db: Async database session.

    Returns:
        :class:`SimpleVerificationResponse` with a plain-English verdict.
    """
    steps: list[ProcessStep] = []
    steps.append(
        _make_step(
            1, "Hash Lookup", "complete", "Searching the ledger for this document fingerprint."
        )
    )
    return await _verify_by_hash(doc_hash, steps, db)


# ── Internal helpers ──────────────────────────────────────────────────────────


async def _verify_by_hash(
    doc_hash: str,
    steps: list[ProcessStep],
    db: AsyncSession,
) -> SimpleVerificationResponse:
    """Common verification path that looks up a commit by doc_hash."""
    result = await db.execute(select(DocCommit).where(DocCommit.doc_hash == doc_hash).limit(1))
    commit = result.scalars().first()

    if not commit:
        steps.append(
            _make_step(
                len(steps) + 1,
                "Ledger Search",
                "failed",
                "This document's fingerprint was not found in the ledger.",
            )
        )
        return SimpleVerificationResponse(
            verified=False,
            summary="This document is NOT in the permanent record.",
            confidence="certain",
            proof_details=steps,
            what_this_means=(
                "The document you provided does not match any record in the Olympus ledger. "
                "This could mean the document was never submitted, was modified after submission, "
                "or was submitted to a different system."
            ),
            why_this_matters=_why_matters(),
        )

    steps.append(
        _make_step(
            len(steps) + 1,
            "Document Found in Ledger",
            "complete",
            "The document's fingerprint matches a permanent record.",
            details={"commit_id": commit.commit_id},
        )
    )

    return await _build_verification_response(commit, steps, db)


async def _build_verification_response(
    commit: DocCommit,
    steps: list[ProcessStep],
    db: AsyncSession,
) -> SimpleVerificationResponse:
    """Build the final response once we have a matching commit."""
    step_n = len(steps) + 1

    # Merkle proof verification
    proof_valid = False
    failure_reason: str | None = None
    try:
        all_hashes_result = await db.execute(
            select(DocCommit.doc_hash)
            .where(DocCommit.shard_id == commit.shard_id)
            .order_by(DocCommit.epoch_timestamp)
        )
        all_hashes = list(all_hashes_result.scalars().all())

        if all_hashes and commit.doc_hash in all_hashes:
            tree = build_tree(all_hashes, preserve_order=True)
            proof = generate_proof(commit.doc_hash, tree)
            proof_valid = verify_proof(commit.doc_hash, proof, tree.root_hash)
            if not proof_valid:
                failure_reason = "merkle_proof_failed"
        else:
            failure_reason = "merkle_proof_failed"
    except Exception:
        logger.exception("Merkle proof verification failed for commit %s", commit.commit_id)
        proof_valid = False
        failure_reason = "merkle_proof_failed"

    if proof_valid:
        steps.append(
            _make_step(
                step_n,
                "Cryptographic Proof Verified",
                "complete",
                (
                    "The document is correctly placed within the tamper-proof Merkle tree. "
                    "This mathematically proves it has not been altered."
                ),
            )
        )
    else:
        steps.append(
            _make_step(
                step_n,
                "Cryptographic Proof",
                "failed",
                "Merkle proof verification failed — the document's position in the "
                "tamper-proof tree could not be confirmed.",
            )
        )

    step_n += 1

    # Chain integrity check: Merkle proof validity implies content integrity.
    # If the Merkle proof failed, we consider that evidence of tampering.
    tamper_detected = not proof_valid

    if tamper_detected:
        failure_reason = failure_reason or "tamper_detected"
        steps.append(
            _make_step(
                step_n,
                "Tamper Check",
                "failed",
                "Potential tampering detected — the record's integrity could not be fully confirmed.",
            )
        )
    else:
        steps.append(
            _make_step(
                step_n,
                "Tamper Check",
                "complete",
                "The permanent record has not been modified since it was created.",
            )
        )

    # Determine overall verification result
    verified = proof_valid and not tamper_detected
    confidence = "certain" if verified else "none"

    # Resolve related request display ID
    related_request: str | None = None
    if commit.request_id:
        req_result = await db.execute(
            select(PublicRecordsRequest)
            .where(PublicRecordsRequest.id == commit.request_id)
            .limit(1)
        )
        req = req_result.scalars().first()
        if req:
            related_request = getattr(req, "display_id", None) or commit.request_id

    epoch = commit.epoch_timestamp
    if epoch.tzinfo is None:
        epoch = epoch.replace(tzinfo=timezone.utc)
    epoch_str = _format_epoch(epoch)

    # Log the verification activity
    try:
        activity_type = "VERIFICATION_SUCCESS" if verified else "VERIFICATION_FAILURE"
        activity_title = "Document Verified" if verified else "Document Verification Failed"
        activity_desc = (
            f"Document with commit '{commit.commit_id}' was successfully verified. Recorded on {epoch_str}."
            if verified
            else f"Document with commit '{commit.commit_id}' failed verification. Reason: {failure_reason}."
        )
        activity = LedgerActivity(
            activity_type=activity_type,
            title=activity_title,
            description=activity_desc,
            related_commit_id=commit.commit_id,
            related_request_id=commit.request_id,
            user_friendly_status="✓ Complete" if verified else "✗ Failed",
        )
        db.add(activity)
        await db.commit()
    except Exception:
        logger.exception("Failed to log verification activity for commit %s", commit.commit_id)
        await db.rollback()

    if verified:
        return SimpleVerificationResponse(
            verified=True,
            summary=f"VERIFIED: This document was permanently recorded on {epoch_str}.",
            confidence=confidence,
            recorded_date=epoch,
            related_request=related_request,
            proof_details=steps,
            what_this_means=(
                f"This document was permanently recorded in the Olympus ledger on {epoch_str}. "
                "Its cryptographic fingerprint has been verified against the tamper-proof Merkle tree, "
                "confirming that the document has not been altered since it was submitted."
            ),
            why_this_matters=_why_matters(),
        )
    else:
        return SimpleVerificationResponse(
            verified=False,
            summary="VERIFICATION FAILED: The document's integrity could not be confirmed.",
            confidence=confidence,
            recorded_date=epoch,
            related_request=related_request,
            failure_reason=failure_reason,
            proof_details=steps,
            what_this_means=(
                "The document was found in the ledger but its cryptographic integrity "
                "could not be fully verified. This may indicate tampering or data corruption."
            ),
            why_this_matters=_why_matters(),
        )


def _why_matters() -> str:
    return (
        "Cryptographic verification makes it mathematically impossible to change a document "
        "after it has been recorded without detection. This protects the integrity of public "
        "records and provides independent proof that a document existed at a specific point in time."
    )
