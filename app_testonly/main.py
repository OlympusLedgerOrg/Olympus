"""
FastAPI application for Olympus proof API

TEST API (IN-MEMORY, NO DATABASE)
==================================

This is a TEST-ONLY FastAPI application for validating proof generation logic.
It does NOT use a database and is NOT suitable for production.

DATABASE: None (in-memory via app_testonly/state.py)
PERSISTENCE: None (ephemeral state)
PRODUCTION USE: ❌ NO - Use api/app.py instead

For production deployment with PostgreSQL, use api/app.py.

This package is named 'app_testonly' to make its scope self-evident.
It is NOT the production API.

See docs/08_database_strategy.md for complete database strategy documentation.

Proof endpoints must always return 200 and must never throw on absence.
Non-existence is a proofable state, not an error.
"""

import os
from typing import Any

from fastapi import FastAPI, HTTPException

from app_testonly.state import OlympusState


app = FastAPI(title="Olympus Phase 0", version="0.1.0", docs_url="/")

# IMPORTANT: do NOT default to ":memory:" — breaks e2e due to per-connection DB
state = OlympusState(os.getenv("OLY_DB_PATH", "/tmp/olympus.sqlite"))


@app.get("/status")
def status() -> dict[str, Any]:
    """Health check endpoint with global root."""
    roots_data = state.roots()
    return {"status": "ok", "global_root": roots_data["global_root"]}


@app.get("/roots")
def roots() -> dict[str, Any]:
    """Get global root and all shard roots."""
    return state.roots()


@app.get("/shards")
def list_shards() -> dict[str, list[str]]:
    """List all shard IDs."""
    return {"shards": state.list_shards()}


@app.get("/shards/{shard_id}/header/latest")
def shard_header_latest(shard_id: str) -> dict[str, Any]:
    """
    Get latest header for a shard.

    Returns 404 if shard doesn't exist (does NOT create shard).
    """
    header = state.header_latest(shard_id)
    if not header:
        raise HTTPException(status_code=404, detail="shard not found")
    return header


@app.get("/shards/{shard_id}/proof/existence")
def proof_existence(shard_id: str, key: str, version: str | None = None) -> dict[str, Any]:
    """
    Get a proof for a key (existence or non-existence).

    This endpoint is named 'existence' for ergonomics, but ALWAYS returns
    a structured proof with HTTP 200. The proof.exists field indicates
    whether the key actually exists.

    NOTE: Both /proof/existence and /proof/nonexistence endpoints return
    identical results. They exist as separate routes for API ergonomics
    and semantic clarity when querying, but both return unified proofs
    that indicate actual existence status via the proof.exists field.

    ABSENCE IS NOT ERROR: always 200 with proof.exists flag.
    Missing key is NOT an error; proof.exists communicates absence.

    Args:
        shard_id: Shard identifier
        key: Hex-encoded 32-byte key
        version: Optional version parameter

    Returns:
        Structured proof dictionary with 'exists' field (always HTTP 200)
    """
    # Parse key from hex -> bytes
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        # Invalid hex -> HTTP 400
        raise HTTPException(status_code=400, detail="key must be hex") from None

    # Call state.proof() - never raises on absence
    proof = state.proof(shard_id, key_bytes, version)

    # Return proof.to_dict() - always 200
    return proof.to_dict()


@app.get("/shards/{shard_id}/proof/nonexistence")
def proof_nonexistence(shard_id: str, key: str, version: str | None = None) -> dict[str, Any]:
    """
    Get a proof for a key (existence or non-existence).

    This endpoint is named 'nonexistence' for ergonomics, but ALWAYS returns
    a structured proof with HTTP 200. The proof.exists field indicates
    whether the key actually exists.

    NOTE: Both /proof/existence and /proof/nonexistence endpoints return
    identical results. They exist as separate routes for API ergonomics
    and semantic clarity when querying, but both return unified proofs
    that indicate actual existence status via the proof.exists field.

    ABSENCE IS NOT ERROR: always 200 with proof.exists flag.
    Missing key is NOT an error; proof.exists communicates absence.

    Args:
        shard_id: Shard identifier
        key: Hex-encoded 32-byte key
        version: Optional version parameter

    Returns:
        Structured proof dictionary with 'exists' field (always HTTP 200)
    """
    # Parse key from hex -> bytes
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        # Invalid hex -> HTTP 400
        raise HTTPException(status_code=400, detail="key must be hex") from None

    # Call state.proof() - never raises on absence
    proof = state.proof(shard_id, key_bytes, version)

    # Return proof.to_dict() - always 200
    return proof.to_dict()
