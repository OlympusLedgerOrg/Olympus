"""Read-only transparency monitor API scaffolding.

Why this module exists:
    This router exposes monitor-friendly views (signed roots, witness set,
    inclusion and non-inclusion proofs, and public equivocation submissions)
    so CT-style operational hardening can be layered around Olympus's SMT.
"""

from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Protocol

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from api.transparency.gossip import SignedRootEnvelope, SplitViewEvidence
from api.transparency.witness import WitnessCosignature, verify_cosignature
from protocol.hashes import hash_string
from protocol.log_sanitization import sanitize_for_log
from protocol.ssmf import (
    ExistenceProof,
    NonExistenceProof,
    SparseMerkleTree,
    verify_nonexistence_proof,
    verify_proof,
)


logger = logging.getLogger(__name__)
router = APIRouter(tags=["transparency"])


class WitnessKeyInfo(BaseModel):
    """Registered witness metadata."""

    witness_id: str
    public_key_hex: str


class SplitViewSubmission(BaseModel):
    """Public split-view evidence submission payload."""

    height: int = Field(ge=0)
    sequencer_key_id: str
    root_a: str
    root_b: str
    signature_a: str
    signature_b: str
    source_peer_a: str
    source_peer_b: str


class _TransparencyBackend(Protocol):
    def latest_signed_root(self) -> SignedRootEnvelope:
        """Return latest signed-root envelope."""

    def signed_root_by_height(self, height: int) -> SignedRootEnvelope | None:
        """Return historical signed-root envelope."""

    def witness_keys(self) -> list[WitnessKeyInfo]:
        """Return registered witness public keys."""

    def inclusion_proof(self, key: bytes) -> ExistenceProof:
        """Return inclusion proof for a key."""

    def non_inclusion_proof(self, key: bytes) -> NonExistenceProof:
        """Return non-inclusion proof for a key."""


class _InMemoryTransparencyBackend:
    """Scaffold backend with deterministic in-memory SMT state."""

    def __init__(self) -> None:
        self._tree = SparseMerkleTree()
        self._parser_id = "docling@2.3.1"
        self._canonical_parser_version = "v1"
        self._existing_key = bytes.fromhex("11" * 32)
        self._existing_value = hash_string("transparency-scaffold-record")
        self._tree.update(
            self._existing_key,
            self._existing_value,
            parser_id=self._parser_id,
            canonical_parser_version=self._canonical_parser_version,
        )
        root_hex = self._tree.get_root().hex()
        ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        self._witnesses = [
            WitnessKeyInfo(witness_id="w1", public_key_hex="aa" * 32),
            WitnessKeyInfo(witness_id="w2", public_key_hex="bb" * 32),
            WitnessKeyInfo(witness_id="w3", public_key_hex="cc" * 32),
        ]
        self._latest = SignedRootEnvelope(
            height=1,
            root_hash=root_hex,
            sequencer_signature="ff" * 64,
            sequencer_key_id="sequencer-main",
            witness_cosignatures=[
                WitnessCosignature(
                    witness_id="w1", signature_hex="11" * 64, public_key_hex="aa" * 32
                ),
                WitnessCosignature(
                    witness_id="w2", signature_hex="22" * 64, public_key_hex="bb" * 32
                ),
            ],
            timestamp=ts,
        )

    def latest_signed_root(self) -> SignedRootEnvelope:
        return self._latest

    def signed_root_by_height(self, height: int) -> SignedRootEnvelope | None:
        if height == self._latest.height:
            return self._latest
        return None

    def witness_keys(self) -> list[WitnessKeyInfo]:
        return self._witnesses

    def inclusion_proof(self, key: bytes) -> ExistenceProof:
        return self._tree.prove_existence(key)

    def non_inclusion_proof(self, key: bytes) -> NonExistenceProof:
        return self._tree.prove_nonexistence(key)


_backend: _TransparencyBackend = _InMemoryTransparencyBackend()


def set_transparency_backend(backend: _TransparencyBackend) -> None:
    """Install a test or production backend for transparency routes."""
    global _backend
    _backend = backend


def _proof_to_dict(proof: ExistenceProof | NonExistenceProof) -> dict[str, Any]:
    return {
        "key": proof.key.hex(),
        "root_hash": proof.root_hash.hex(),
        "siblings": [sib.hex() for sib in proof.siblings],
        **(
            {
                "value_hash": proof.value_hash.hex(),
                "parser_id": proof.parser_id,
                "canonical_parser_version": proof.canonical_parser_version,
            }
            if isinstance(proof, ExistenceProof)
            else {}
        ),
    }


def _decode_key(key: str) -> bytes:
    try:
        raw = bytes.fromhex(key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="key must be valid hex") from exc
    if len(raw) != 32:
        raise HTTPException(status_code=400, detail="key must be 32 bytes (64 hex chars)")
    return raw


@router.get("/transparency/v1/signed-root")
async def get_latest_signed_root() -> dict[str, Any]:
    """Return the latest signed-root envelope for monitor polling."""
    try:
        envelope = _backend.latest_signed_root()
        root_bytes = bytes.fromhex(envelope.root_hash)
        return {
            **asdict(envelope),
            "witness_threshold_met": verify_cosignature(
                root_bytes,
                envelope.witness_cosignatures,
                threshold=2,
            ),
        }
    except HTTPException:
        raise
    except Exception:
        logger.error("Failed to fetch latest signed root", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch latest signed root") from None


@router.get("/transparency/v1/signed-root/{height}")
async def get_signed_root_by_height(height: int) -> dict[str, Any]:
    """Return a signed-root envelope at a specific tree height."""
    try:
        envelope = _backend.signed_root_by_height(height)
        if envelope is None:
            raise HTTPException(status_code=404, detail="Signed root not found")
        return asdict(envelope)
    except HTTPException:
        raise
    except Exception:
        logger.error(
            "Failed to fetch signed root at height=%s",
            sanitize_for_log(height),
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to fetch signed root") from None


@router.get("/transparency/v1/witnesses", response_model=list[WitnessKeyInfo])
async def get_witnesses() -> list[WitnessKeyInfo]:
    """Return registered witness public keys for independent verification."""
    try:
        return _backend.witness_keys()
    except Exception:
        logger.error("Failed to fetch witness key registry", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to fetch witness list") from None


@router.get("/transparency/v1/inclusion/{key}")
async def get_inclusion(key: str) -> dict[str, Any]:
    """Return an inclusion proof anchored to the latest signed root."""
    try:
        key_bytes = _decode_key(key)
        proof = _backend.inclusion_proof(key_bytes)
        latest = _backend.latest_signed_root()
        expected_root = bytes.fromhex(latest.root_hash)
        return {
            "signed_root": asdict(latest),
            "proof": _proof_to_dict(proof),
            "proof_valid": verify_proof(proof, expected_root=expected_root),
        }
    except KeyError:
        raise HTTPException(status_code=404, detail="Key is not present in latest root") from None
    except HTTPException:
        raise
    except Exception:
        logger.error(
            "Failed to fetch inclusion proof for key=%s",
            sanitize_for_log(key),
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to fetch inclusion proof") from None


@router.get("/transparency/v1/non-inclusion/{key}")
async def get_non_inclusion(key: str) -> dict[str, Any]:
    """Return a non-inclusion proof anchored to the latest signed root."""
    try:
        key_bytes = _decode_key(key)
        proof = _backend.non_inclusion_proof(key_bytes)
        latest = _backend.latest_signed_root()
        expected_root = bytes.fromhex(latest.root_hash)
        return {
            "signed_root": asdict(latest),
            "proof": _proof_to_dict(proof),
            "proof_valid": verify_nonexistence_proof(proof, expected_root=expected_root),
        }
    except HTTPException:
        raise
    except Exception:
        logger.error(
            "Failed to fetch non-inclusion proof for key=%s",
            sanitize_for_log(key),
            exc_info=True,
        )
        raise HTTPException(status_code=500, detail="Failed to fetch non-inclusion proof") from None


@router.post("/transparency/v1/gossip/equivocation")
async def submit_equivocation_evidence(payload: SplitViewSubmission) -> dict[str, Any]:
    """Accept split-view evidence for public monitor verification workflows."""
    try:
        if payload.root_a == payload.root_b:
            raise HTTPException(
                status_code=400, detail="Split-view evidence requires conflicting roots"
            )

        evidence = SplitViewEvidence(
            height=payload.height,
            sequencer_key_id=payload.sequencer_key_id,
            root_a=payload.root_a,
            root_b=payload.root_b,
            signature_a=payload.signature_a,
            signature_b=payload.signature_b,
            source_peer_a=payload.source_peer_a,
            source_peer_b=payload.source_peer_b,
            detected_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        return {
            "accepted": True,
            "evidence": asdict(evidence),
            "evidence_id": hash_string(
                f"{evidence.height}|{evidence.root_a}|{evidence.root_b}|{evidence.detected_at}"
            ).hex(),
        }
    except HTTPException:
        raise
    except Exception:
        logger.error("Failed to process equivocation evidence submission", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to process equivocation evidence"
        ) from None
