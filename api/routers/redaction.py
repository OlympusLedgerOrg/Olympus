"""
Redaction link endpoint.

POST /redaction/link — given chunk hashes from both the original and redacted
documents (computed client-side with BLAKE3), computes the Poseidon commitments
and reveal mask that prove the redacted document is a valid partial disclosure
of the original.

The client sends:
  - original_commit_id: ledger commit to anchor back to
  - original_chunks / redacted_chunks: 64 BLAKE3 hex hashes (one per chunk)

The server:
  1. Verifies the original commit exists in the ledger
  2. Derives Poseidon leaf values from the BLAKE3 chunk hashes
  3. Computes revealMask (1 = chunk unchanged, 0 = chunk differs)
  4. Computes redactedCommitment + revealMaskCommitment via the circuit's
     position-bound Poseidon chain
  5. Returns the full commitment bundle for client-side display / proof storage
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from api.deps import DBSession
from api.models.document import DocCommit
from protocol.poseidon_tree import (
    blake3_hex_to_poseidon_leaf,
    compute_poseidon_commitment_root,
    compute_redaction_commitments,
)


logger = logging.getLogger(__name__)

router = APIRouter(tags=["redaction"])

_MAX_LEAVES = 64


class RedactionLinkRequest(BaseModel):
    original_commit_id: str = Field(..., description="Ledger commit ID for the original document")
    original_chunks: list[str] = Field(
        ...,
        min_length=_MAX_LEAVES,
        max_length=_MAX_LEAVES,
        description="64 BLAKE3 hex hashes — one per equal-sized chunk of the original file",
    )
    redacted_chunks: list[str] = Field(
        ...,
        min_length=_MAX_LEAVES,
        max_length=_MAX_LEAVES,
        description="64 BLAKE3 hex hashes — one per equal-sized chunk of the redacted file",
    )


class RedactionLinkResponse(BaseModel):
    original_commit_id: str
    original_blake3: str
    original_root: str
    redacted_commitment: str
    reveal_mask_commitment: str
    reveal_mask: list[int]
    revealed_count: int
    redacted_count: int
    verified: bool
    note: str


@router.post("/redaction/link", response_model=RedactionLinkResponse)
async def link_redaction(body: RedactionLinkRequest, db: DBSession) -> RedactionLinkResponse:
    """Link a redacted document back to its original ledger entry.

    Computes the Poseidon commitment bundle that proves the redacted file is
    a valid partial disclosure of the original committed document.  No ZK proof
    is generated here — the commitments are the pre-proof artefacts that would
    be fed into the redaction_validity Groth16 circuit.

    The endpoint is intentionally public (no API key required) because
    verification is a transparency operation: anyone should be able to confirm
    that a redacted file links back to a committed original.
    """
    # 1. Confirm the original commit exists
    result = await db.execute(
        select(DocCommit).where(DocCommit.commit_id == body.original_commit_id).limit(1)
    )
    commit = result.scalars().first()
    if commit is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Commit {body.original_commit_id!r} not found in the ledger.",
        )

    # 2. Normalize to lowercase so "AABB..." and "aabb..." compare identically,
    #    then validate all hashes and derive Poseidon leaves from the originals.
    orig_normalized = [h.lower() for h in body.original_chunks]
    redc_normalized = [h.lower() for h in body.redacted_chunks]

    try:
        original_leaves = [blake3_hex_to_poseidon_leaf(h) for h in orig_normalized]
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)) from e

    # Validate redacted_chunks hex too (they're only compared, not run through
    # blake3_hex_to_poseidon_leaf, so we validate explicitly).
    for h in redc_normalized:
        try:
            bytes.fromhex(h)
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid BLAKE3 hex in redacted_chunks: {h!r}",
            ) from e

    # 3. Compute reveal mask: 1 = chunk unchanged (revealed), 0 = chunk differs (redacted)
    reveal_mask = [1 if orig_normalized[i] == redc_normalized[i] else 0 for i in range(_MAX_LEAVES)]
    revealed_count = sum(reveal_mask)
    redacted_count = _MAX_LEAVES - revealed_count

    if redacted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="All chunks are identical — no redaction detected. "
            "Ensure the redacted file differs from the original.",
        )

    if revealed_count == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No chunks are identical — the files appear unrelated. "
            "Ensure the redacted file was derived from the original.",
        )

    # 4. Compute Poseidon original root via protocol layer
    original_root = compute_poseidon_commitment_root(original_leaves, _MAX_LEAVES)

    # 5. Compute redactedCommitment + revealMaskCommitment via protocol layer
    redacted_commitment, reveal_mask_commitment = compute_redaction_commitments(
        original_leaves, reveal_mask, revealed_count
    )

    return RedactionLinkResponse(
        original_commit_id=body.original_commit_id,
        original_blake3=commit.doc_hash,
        original_root=original_root,
        redacted_commitment=redacted_commitment,
        reveal_mask_commitment=reveal_mask_commitment,
        reveal_mask=reveal_mask,
        revealed_count=revealed_count,
        redacted_count=redacted_count,
        verified=True,
        note=(
            f"Redaction commitment verified. {redacted_count} of {_MAX_LEAVES} chunks redacted, "
            f"{revealed_count} revealed. This bundle can be used as public inputs for the "
            "redaction_validity ZK proof once the trusted-setup ceremony is complete."
        ),
    )
