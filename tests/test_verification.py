"""
Tests for the verification service.

Validates that verification correctly reports failures when Merkle proofs
fail, the chain is tampered, or stub proofs are presented in production.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.services.verification import _build_verification_response


def _make_fake_commit(
    doc_hash: str = "abc123",
    shard_id: str = "shard-0",
    commit_id: str = "0xdead",
    request_id: str | None = None,
):
    """Create a fake DocCommit-like object for testing."""
    commit = MagicMock()
    commit.doc_hash = doc_hash
    commit.shard_id = shard_id
    commit.commit_id = commit_id
    commit.request_id = request_id
    commit.epoch_timestamp = datetime(2025, 1, 15, 14, 30, tzinfo=timezone.utc)
    return commit


def _make_fake_db(all_hashes=None, raise_on_execute=False):
    """Create a fake async DB session."""
    db = AsyncMock()

    if raise_on_execute:
        db.execute.side_effect = Exception("DB error")
    elif all_hashes is not None:
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = all_hashes
        db.execute.return_value = result_mock
    else:
        result_mock = MagicMock()
        result_mock.scalars.return_value.all.return_value = []
        db.execute.return_value = result_mock

    return db


@pytest.mark.asyncio
async def test_merkle_proof_failure_returns_verified_false():
    """When Merkle proof verification fails, verified must be False."""
    commit = _make_fake_commit()
    # DB returns hashes but the doc_hash is NOT in the list, causing proof failure
    db = _make_fake_db(all_hashes=["other_hash_1", "other_hash_2"])

    result = await _build_verification_response(commit, [], db)

    assert result.verified is False
    assert result.confidence == "none"
    assert result.failure_reason is not None
    assert "merkle" in result.failure_reason.lower() or "tamper" in result.failure_reason.lower()


@pytest.mark.asyncio
async def test_merkle_exception_returns_verified_false():
    """When Merkle proof verification raises an exception, verified must be False."""
    commit = _make_fake_commit()
    db = _make_fake_db(raise_on_execute=True)

    result = await _build_verification_response(commit, [], db)

    assert result.verified is False
    assert result.confidence == "none"
    assert result.failure_reason == "merkle_proof_failed"


@pytest.mark.asyncio
async def test_successful_verification_returns_verified_true():
    """When all checks pass, verified must be True."""
    commit = _make_fake_commit(doc_hash="abc123")
    # Provide hashes that include the commit's doc_hash
    db = _make_fake_db(all_hashes=["abc123"])

    result = await _build_verification_response(commit, [], db)

    assert result.verified is True
    assert result.confidence == "certain"
    assert result.failure_reason is None
