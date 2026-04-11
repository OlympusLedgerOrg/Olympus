"""Tests for ingestion idempotency (INSERT … ON CONFLICT path).

These tests use AsyncMock / MagicMock to simulate the database session and
do **not** require a live PostgreSQL connection.
"""

from __future__ import annotations

import types
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.services.ingestion import ingest_document


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_file_bytes() -> bytes:
    """Return deterministic file content for hashing."""
    return b"Hello, Olympus ledger!"


def _fake_hash() -> str:
    """A plausible BLAKE3 hex hash (64 hex chars)."""
    return "a" * 64


def _fake_commit_id() -> str:
    """A plausible commit_id (``0x`` + 64 hex chars)."""
    return "0x" + "b" * 64


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_db() -> AsyncMock:
    """Return an ``AsyncMock`` that behaves like an ``AsyncSession``."""
    db = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    return db


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_concurrent_duplicate_returns_existing(mock_db: AsyncMock) -> None:
    """Simulate the ON CONFLICT path: insert returns no rows (conflict),
    then a follow-up SELECT returns the existing DocCommit.  The response
    must be ``success=True`` with the *existing* commit_id.
    """
    existing_commit_id = _fake_commit_id()
    existing_epoch = datetime(2026, 1, 15, 14, 34, 0, tzinfo=timezone.utc)

    # Build a mock existing DocCommit returned by the follow-up SELECT.
    existing_row = MagicMock()
    existing_row.commit_id = existing_commit_id
    existing_row.epoch_timestamp = existing_epoch

    call_count = 0

    async def _side_effect(stmt):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            # First call: SELECT existing hashes for Merkle root computation.
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result
        elif call_count == 2:
            # Second call: the pg_insert … ON CONFLICT.  fetchone() -> None
            # means the insert was a no-op (conflict).
            result = MagicMock()
            result.fetchone.return_value = None
            return result
        else:
            # Third call: follow-up SELECT to fetch the existing row.
            result = MagicMock()
            result.scalars.return_value.first.return_value = existing_row
            return result

    mock_db.execute = AsyncMock(side_effect=_side_effect)

    with (
        patch("api.services.ingestion.hash_document", return_value=_fake_hash()),
        patch("api.services.ingestion.generate_commit_id", return_value="0x" + "c" * 64),
        patch("api.services.ingestion.build_tree") as mock_tree,
    ):
        mock_tree.return_value = types.SimpleNamespace(root_hash="r" * 64)

        resp = await ingest_document(
            file_bytes=_fake_file_bytes(),
            filename="test.pdf",
            content_type="application/pdf",
            request_id=None,
            description=None,
            db=mock_db,
        )

    assert resp.success is True
    assert resp.commit_id == existing_commit_id
    assert "already in the permanent record" in resp.summary


@pytest.mark.asyncio
async def test_new_document_inserts_successfully(mock_db: AsyncMock) -> None:
    """Simulate a clean insert: the pg_insert returns a row with a valid
    commit_id.  The response must be ``success=True`` and the
    ``permanent_record_id`` must start with ``"OLY-"``.
    """
    new_commit_id = _fake_commit_id()
    new_epoch = datetime(2026, 4, 10, 12, 0, 0, tzinfo=timezone.utc)

    call_count = 0

    async def _side_effect(stmt):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            # SELECT existing hashes for Merkle root.
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result
        elif call_count == 2:
            # pg_insert … RETURNING — row returned means insert succeeded.
            result = MagicMock()
            result.fetchone.return_value = (new_commit_id, new_epoch)
            return result
        else:
            # Activity-log INSERT (if reached) — just return a mock.
            return MagicMock()

    mock_db.execute = AsyncMock(side_effect=_side_effect)

    with (
        patch("api.services.ingestion.hash_document", return_value=_fake_hash()),
        patch("api.services.ingestion.generate_commit_id", return_value=new_commit_id),
        patch("api.services.ingestion.build_tree") as mock_tree,
    ):
        mock_tree.return_value = types.SimpleNamespace(root_hash="r" * 64)

        resp = await ingest_document(
            file_bytes=_fake_file_bytes(),
            filename="test.pdf",
            content_type="application/pdf",
            request_id=None,
            description=None,
            db=mock_db,
        )

    assert resp.success is True
    assert resp.permanent_record_id is not None
    assert resp.permanent_record_id.startswith("OLY-")


@pytest.mark.asyncio
async def test_db_failure_returns_failure_response(mock_db: AsyncMock) -> None:
    """Simulate ``db.execute`` raising an exception during the upsert.
    The response must be ``success=False`` and ``db.rollback`` must be
    called.
    """
    call_count = 0

    async def _side_effect(stmt):
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            # SELECT existing hashes for Merkle root.
            result = MagicMock()
            result.scalars.return_value.all.return_value = []
            return result
        else:
            # pg_insert — simulate a database error.
            raise Exception("db error")

    mock_db.execute = AsyncMock(side_effect=_side_effect)

    with (
        patch("api.services.ingestion.hash_document", return_value=_fake_hash()),
        patch("api.services.ingestion.generate_commit_id", return_value=_fake_commit_id()),
        patch("api.services.ingestion.build_tree") as mock_tree,
    ):
        mock_tree.return_value = types.SimpleNamespace(root_hash="r" * 64)

        resp = await ingest_document(
            file_bytes=_fake_file_bytes(),
            filename="test.pdf",
            content_type="application/pdf",
            request_id=None,
            description=None,
            db=mock_db,
        )

    assert resp.success is False
    mock_db.rollback.assert_called_once()
