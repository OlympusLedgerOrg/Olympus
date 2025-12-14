"""
FastAPI application for Olympus proof API

This module provides REST endpoints for querying existence and non-existence proofs
from the Olympus ledger without raising exceptions for missing keys.
"""

import os
from typing import Optional
from fastapi import FastAPI, HTTPException

from app.state import OlympusState


# Initialize FastAPI app
app = FastAPI(
    title="Olympus Proof API",
    description="REST API for cryptographic proofs in the Olympus ledger",
    version="0.1.0"
)

# Initialize state with file-backed database (not :memory:)
state = OlympusState(os.getenv("OLY_DB_PATH", "olympus.sqlite"))


@app.get("/")
def root():
    """Health check endpoint."""
    return {"status": "ok", "service": "olympus-proof-api"}


@app.get("/shards/{shard_id}/proof/existence")
def proof_existence(shard_id: str, key: str, version: Optional[str] = None):
    """
    Get a proof for a key (existence or non-existence).
    
    This endpoint is named 'existence' for ergonomics, but always returns
    a structured proof with HTTP 200. The proof.exists field indicates
    whether the key actually exists.
    
    Args:
        shard_id: Shard identifier
        key: Hex-encoded 32-byte key
        version: Optional version parameter
        
    Returns:
        Structured proof dictionary with 'exists' field
    """
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        raise HTTPException(status_code=400, detail="key must be hex")
    
    proof = state.proof(shard_id, key_bytes, version)
    return proof.to_dict()  # always 200; proof.exists tells truth


@app.get("/shards/{shard_id}/proof/nonexistence")
def proof_nonexistence(shard_id: str, key: str, version: Optional[str] = None):
    """
    Get a proof for a key (existence or non-existence).
    
    This endpoint is named 'nonexistence' for ergonomics, but always returns
    a structured proof with HTTP 200. The proof.exists field indicates
    whether the key actually exists.
    
    Args:
        shard_id: Shard identifier
        key: Hex-encoded 32-byte key
        version: Optional version parameter
        
    Returns:
        Structured proof dictionary with 'exists' field
    """
    try:
        key_bytes = bytes.fromhex(key)
    except ValueError:
        raise HTTPException(status_code=400, detail="key must be hex")
    
    proof = state.proof(shard_id, key_bytes, version)
    return proof.to_dict()
