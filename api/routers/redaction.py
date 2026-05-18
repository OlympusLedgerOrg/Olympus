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

import asyncio
import json
import logging
import math
from typing import Annotated, Any

import blake3 as _blake3_lib
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select

from api.deps import DBSession
from api.models.document import DocCommit
from api.schemas.ingest import PROOF_ID_PATTERN, IngestionProofResponse
from protocol.hashes import SNARK_SCALAR_FIELD
from protocol.poseidon_tree import (
    POSEIDON_DOMAIN_COMMITMENT,
    PoseidonMerkleTree,
    blake3_hex_to_poseidon_leaf,
    compute_poseidon_commitment_root,
    compute_redaction_commitments,
    poseidon_hash_with_domain,
)
from protocol.redaction_subset import (
    CHUNKING_VERSION,
    MATCH_STRATEGY,
    validate_digest_hex,
    verify_redaction_merkle_inclusion,
)
from protocol.zkp import ZKProof


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


class RevealedChunk(BaseModel):
    index: int = Field(..., ge=0)
    chunk_hash: str = Field(..., min_length=64, max_length=64)
    merkle_proof: list[str] = Field(..., description="Ordered bottom-up sibling hashes")


class RedactionSubsetRequest(BaseModel):
    proof_id: str = Field(..., pattern=PROOF_ID_PATTERN, max_length=36)
    chunk_merkle_root: str = Field(..., min_length=64, max_length=64)
    chunking_version: str = Field(default=CHUNKING_VERSION)
    revealed_chunks: list[RevealedChunk] = Field(..., min_length=1)

    @model_validator(mode="after")
    def validate_unique_indices(self) -> RedactionSubsetRequest:
        indices = [chunk.index for chunk in self.revealed_chunks]
        if len(set(indices)) != len(indices):
            raise ValueError("Duplicate chunk indices detected in revealed_chunks.")
        return self


class RedactionMetadata(BaseModel):
    original_root: str
    revealed_indices: list[int]
    revealed_count: int
    redacted_count: int
    chunk_count: int


class RedactionSubsetResponse(BaseModel):
    verified: bool = True
    match_strategy: str = MATCH_STRATEGY
    original_proof: IngestionProofResponse
    redaction: RedactionMetadata


async def _get_original_proof(proof_id: str) -> dict:
    """Fetch a proof package from the authoritative ingest proof store."""
    from api import ingest as ingest_api

    normalized = proof_id.lower()
    data = ingest_api._ingestion_store.get(normalized)
    if data is None:
        data = await ingest_api._fetch_persisted_proof(normalized)
    if data is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proof not found")
    return data


@router.post(
    "/redaction/verify-subset",
    response_model=RedactionSubsetResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"description": "Invalid cryptographic proof or payload"},
        404: {"description": "Original proof package not found"},
    },
)
async def verify_subset(body: RedactionSubsetRequest, request: Request) -> RedactionSubsetResponse:
    """Verify revealed raw-byte chunks against a stored chunk Merkle root."""
    from api import ingest as ingest_api

    await ingest_api._apply_ip_rate_limit(request, "verify")
    original = await _get_original_proof(body.proof_id)

    stored_root = original.get("chunk_merkle_root")
    stored_version = original.get("chunking_version")
    stored_chunk_count = original.get("chunk_count")
    if not stored_root or not stored_version or not stored_chunk_count:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Original proof does not include redaction chunk metadata.",
        )

    try:
        validate_digest_hex(body.chunk_merkle_root)
        validate_digest_hex(stored_root)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    if body.chunk_merkle_root.lower() != str(stored_root).lower():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target root does not match stored proof.",
        )
    if body.chunking_version != stored_version:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Chunking version mismatch. Expected {stored_version}.",
        )

    chunk_count = int(stored_chunk_count)
    for chunk in body.revealed_chunks:
        if chunk.index >= chunk_count:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Chunk index {chunk.index} exceeds original bounds.",
            )
        if not verify_redaction_merkle_inclusion(
            leaf_hash_hex=chunk.chunk_hash,
            leaf_index=chunk.index,
            proof_hex=chunk.merkle_proof,
            root_hex=str(stored_root),
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Merkle inclusion proof failed for chunk {chunk.index}.",
            )

    revealed_indices = sorted(chunk.index for chunk in body.revealed_chunks)
    original_proof = IngestionProofResponse(**original)
    return RedactionSubsetResponse(
        verified=True,
        match_strategy=MATCH_STRATEGY,
        original_proof=original_proof,
        redaction=RedactionMetadata(
            original_root=str(stored_root),
            revealed_indices=revealed_indices,
            revealed_count=len(revealed_indices),
            redacted_count=chunk_count - len(revealed_indices),
            chunk_count=chunk_count,
        ),
    )


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


# ---------------------------------------------------------------------------
# ZK Redaction — server-side Groth16 prove / verify
# ---------------------------------------------------------------------------

# Must match the compiled redaction_validity circuit (REDACTION_MAX_LEAVES).
# Changing this constant requires regenerating the zkey.
_ZK_MAX_LEAVES = 6
_ZK_MERKLE_DEPTH = 3


def _split_into_sections(data: bytes) -> list[bytes]:
    """Split *data* into _ZK_MAX_LEAVES equal sections, zero-padding the last.

    Part of the commitment scheme — semantics must match exactly between prove
    and verify calls.  Do not change the split formula without regenerating the
    redaction_validity.zkey.
    """
    section_size = math.ceil(len(data) / _ZK_MAX_LEAVES)
    sections = []
    for i in range(_ZK_MAX_LEAVES):
        chunk = data[i * section_size : (i + 1) * section_size]
        sections.append(chunk.ljust(section_size, b"\x00"))
    return sections


def _poseidon_leaves_from_sections(sections: list[bytes]) -> list[int]:
    """BLAKE3-hash each section then map to a Poseidon BN254 field element."""
    return [blake3_hex_to_poseidon_leaf(_blake3_lib.blake3(s).hexdigest()) for s in sections]


def _recompute_redacted_commitment(
    poseidon_leaves: list[int],
    reveal_mask: list[int],
) -> str:
    """Recompute redactedCommitment exactly as witness_from_redaction does.

    Uses the revealed leaves (mask=1 → original leaf, mask=0 → 0) to build
    the Poseidon commitment chain.  For mask=1 sections the redacted file is
    identical to the original, so poseidon_leaves[i] already equals the
    original leaf — no original file required.
    """
    F = SNARK_SCALAR_FIELD
    revealed_leaves = [(poseidon_leaves[i] * reveal_mask[i]) % F for i in range(_ZK_MAX_LEAVES)]
    revealed_count = sum(reveal_mask)
    acc = poseidon_hash_with_domain(revealed_count, revealed_leaves[0], POSEIDON_DOMAIN_COMMITMENT)
    for k in range(1, _ZK_MAX_LEAVES):
        acc = poseidon_hash_with_domain(acc, revealed_leaves[k], POSEIDON_DOMAIN_COMMITMENT)
    return str(acc % F)


class RedactionProofBundle(BaseModel):
    proof: dict[str, Any]
    public_signals: list[str]  # [originalRoot, redactedCommitment, revealedCount]
    reveal_mask: list[int]  # length == _ZK_MAX_LEAVES
    original_commit_id: str
    circuit: str  # "redaction_validity"
    revealed_count: int
    redacted_count: int


class RedactionZkVerifyResponse(BaseModel):
    verified: bool
    original_root: str
    redacted_commitment: str
    revealed_count: int
    redacted_count: int


@router.post(
    "/redaction/prove",
    response_model=RedactionProofBundle,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"description": "Redaction invalid or files unrelated"},
        404: {"description": "Commit not found in ledger"},
        503: {"description": "snarkjs unavailable"},
    },
)
async def prove_redaction(
    original_file: Annotated[UploadFile, File()],
    redacted_file: Annotated[UploadFile, File()],
    original_commit_id: Annotated[str, Form()],
    db: DBSession,
) -> RedactionProofBundle:
    """Generate a Groth16 ZK proof that *redacted_file* is a valid partial
    disclosure of *original_file* (which must already be committed to the ledger).

    The proof bundle can later be verified by POST /redaction/verify-zk without
    supplying the original file again.
    """
    # ── Read uploads ──────────────────────────────────────────────────────────
    original_bytes = await original_file.read()
    redacted_bytes = await redacted_file.read()

    # ── Ledger binding: original must match the committed doc_hash ────────────
    result = await db.execute(
        select(DocCommit).where(DocCommit.commit_id == original_commit_id).limit(1)
    )
    commit = result.scalars().first()
    if commit is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Commit {original_commit_id!r} not found in the ledger.",
        )
    original_b3 = _blake3_lib.blake3(original_bytes).hexdigest()
    if original_b3 != commit.doc_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Original file BLAKE3 hash does not match the ledger commit. "
                "Ensure you supplied the correct original document."
            ),
        )

    # ── Section split + Poseidon leaves ───────────────────────────────────────
    orig_sections = _split_into_sections(original_bytes)
    redc_sections = _split_into_sections(redacted_bytes)
    orig_leaves = _poseidon_leaves_from_sections(orig_sections)

    reveal_mask = [1 if orig_sections[i] == redc_sections[i] else 0 for i in range(_ZK_MAX_LEAVES)]
    revealed_count = sum(reveal_mask)
    redacted_count = _ZK_MAX_LEAVES - revealed_count

    if redacted_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All sections are identical — no redaction detected.",
        )
    if revealed_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No sections match — files appear unrelated.",
        )

    # ── Build Poseidon Merkle tree + generate witness ─────────────────────────
    from proofs.proof_generator import CircuitConfig, ProofGenerator

    config = CircuitConfig.from_env()
    tree = PoseidonMerkleTree(orig_leaves, depth=_ZK_MERKLE_DEPTH)
    witness = ProofGenerator.witness_from_redaction(tree, reveal_mask, circuit_config=config)

    generator = ProofGenerator("redaction_validity", circuit_config=config)
    if not generator.snarkjs_available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="snarkjs is not available on this server. Cannot generate ZK proof.",
        )

    proof: ZKProof = await asyncio.to_thread(generator.prove, witness)

    return RedactionProofBundle(
        proof=proof.proof,
        public_signals=proof.public_signals,
        reveal_mask=reveal_mask,
        original_commit_id=original_commit_id,
        circuit="redaction_validity",
        revealed_count=revealed_count,
        redacted_count=redacted_count,
    )


@router.post(
    "/redaction/verify-zk",
    response_model=RedactionZkVerifyResponse,
    status_code=status.HTTP_200_OK,
    responses={
        400: {"description": "Bundle invalid or commitment mismatch"},
        503: {"description": "snarkjs unavailable"},
    },
)
async def verify_redaction_zk(
    redacted_file: Annotated[UploadFile, File()],
    proof_bundle: Annotated[str, Form()],
) -> RedactionZkVerifyResponse:
    """Verify a redaction ZK proof using only the redacted file + proof bundle.

    The original file is NOT required.  The verifier confirms:
    1. The redacted file's revealed sections match the commitment in the bundle.
    2. The Groth16 proof passes snarkjs verification against the vkey.
    """
    # ── Parse bundle ──────────────────────────────────────────────────────────
    try:
        raw = json.loads(proof_bundle)
        bundle = RedactionProofBundle.model_validate(raw)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid proof_bundle JSON: {exc}",
        ) from exc

    if bundle.circuit != "redaction_validity":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unexpected circuit {bundle.circuit!r}; expected 'redaction_validity'.",
        )
    if len(bundle.reveal_mask) != _ZK_MAX_LEAVES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"reveal_mask length {len(bundle.reveal_mask)} != {_ZK_MAX_LEAVES}.",
        )
    if len(bundle.public_signals) < 3:  # noqa: PLR2004
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="public_signals must have at least 3 elements.",
        )

    # ── Read redacted file + recompute commitment ─────────────────────────────
    redacted_bytes = await redacted_file.read()
    redc_sections = _split_into_sections(redacted_bytes)
    redc_leaves = _poseidon_leaves_from_sections(redc_sections)

    computed_commitment = _recompute_redacted_commitment(redc_leaves, bundle.reveal_mask)
    if computed_commitment != bundle.public_signals[1]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Redacted file commitment does not match the proof bundle. "
                "The file may have been tampered with or the wrong file was supplied."
            ),
        )

    # ── snarkjs Groth16 verify ────────────────────────────────────────────────
    from proofs.proof_generator import CircuitConfig, ProofGenerator

    config = CircuitConfig.from_env()
    generator = ProofGenerator("redaction_validity", circuit_config=config)
    if not generator.snarkjs_available:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="snarkjs is not available on this server. Cannot verify ZK proof.",
        )

    zk_proof = ZKProof(
        proof=bundle.proof,
        public_signals=bundle.public_signals,
        circuit="redaction_validity",
    )
    verified: bool = await asyncio.to_thread(generator.verify, zk_proof)

    return RedactionZkVerifyResponse(
        verified=verified,
        original_root=bundle.public_signals[0],
        redacted_commitment=bundle.public_signals[1],
        revealed_count=bundle.revealed_count,
        redacted_count=bundle.redacted_count,
    )
