"""Unit and integration tests for the H-5 TSA background worker.

Covers:
  * ``claim_one_job`` atomically claims at most one row.
  * ``process_job`` happy path: target row → ``verified``.
  * ``process_job`` transient failure: status stays ``pending``, attempts
    increments, ``next_attempt_at`` is in the future.
  * ``process_job`` permanent failure after ``max_attempts`` exhausted.
  * ``run_sweeper_once`` flips past-grace pending rows to ``failed``.
  * Integration: ``POST /datasets/commit`` returns 201 quickly even when
    the TSA mock blocks for 30s — proving the call is no longer inline.
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import api.auth as auth_module
import api.workers.tsa_worker as tsa_worker
from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.models.dataset import DatasetArtifact
from api.models.tsa_job import TsaJob


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory():
    """Per-test in-memory database with all tables created."""
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture
async def session(session_factory):
    async with session_factory() as s:
        yield s


@pytest_asyncio.fixture
async def app_client(session_factory, monkeypatch):
    """FastAPI client backed by ``session_factory`` for end-to-end tests.

    Allow the dev-mode auth bypass so the integration test below can post
    without configuring an API key — same trick the existing dataset
    router tests use.
    """
    monkeypatch.setattr(auth_module, "_API_KEY_HASHES", None, raising=False)
    os.environ.pop("OLYMPUS_FOIA_API_KEYS", None)

    app = create_app()

    async def _override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


def _seed_artifact(commit_id: str | None = None) -> DatasetArtifact:
    """Build a minimal ``DatasetArtifact`` for tests; omits relationships."""
    cid = commit_id or ("a" * 64)
    return DatasetArtifact(
        id=str(uuid.uuid4()),
        dataset_id="d" * 64,
        commit_id=cid,
        parent_commit_id="",
        epoch_timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
        shard_id="0x4F3A",
        committer_pubkey="b" * 64,
        commit_signature="c" * 128,
        timestamp_status="pending",
        timestamp_attempts=0,
        dataset_name="t",
        dataset_version="1.0",
        source_uri="https://example.com/t.csv",
        canonical_namespace="ns",
        granularity="file",
        license_spdx="MIT",
        manifest_hash="e" * 64,
        manifest_schema_version="dataset_manifest_v1",
        canonicalization_method="canonical_json_v2",
        total_byte_size=1,
        file_count=1,
        file_format="csv",
    )


def _seed_job(target_pk: str, commit_id: str, *, attempts: int = 0) -> TsaJob:
    return TsaJob(
        target_table="dataset_artifacts",
        target_pk=target_pk,
        hash_hex=commit_id,
        tsa_url="https://freetsa.example/tsr",
        status="pending",
        attempts=attempts,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        next_attempt_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )


# ---------------------------------------------------------------------------
# claim_one_job
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_one_job_returns_none_when_empty(session):
    assert await tsa_worker.claim_one_job(session) is None


@pytest.mark.asyncio
async def test_claim_one_job_returns_pending_and_marks_in_flight(session):
    artifact = _seed_artifact()
    session.add(artifact)
    await session.flush()
    job = _seed_job(artifact.id, artifact.commit_id)
    session.add(job)
    await session.commit()

    claimed = await tsa_worker.claim_one_job(session)
    assert claimed is not None
    assert claimed.id == job.id
    assert claimed.status == "in_flight"
    assert claimed.claimed_at is not None


@pytest.mark.asyncio
async def test_claim_one_job_skips_future_next_attempt_at(session):
    artifact = _seed_artifact()
    session.add(artifact)
    await session.flush()
    job = _seed_job(artifact.id, artifact.commit_id)
    job.next_attempt_at = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5)
    session.add(job)
    await session.commit()

    assert await tsa_worker.claim_one_job(session) is None


# ---------------------------------------------------------------------------
# process_job — success path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_job_success_marks_target_verified(session):
    artifact = _seed_artifact(commit_id="f" * 64)
    session.add(artifact)
    await session.flush()
    job = _seed_job(artifact.id, artifact.commit_id)
    session.add(job)
    await session.commit()

    claimed = await tsa_worker.claim_one_job(session)
    assert claimed is not None

    fake_token = MagicMock()
    fake_token.tst_bytes = b"\xab" * 32
    fake_token.tsa_url = "https://freetsa.example/tsr"

    with patch.object(tsa_worker, "_fetch_token_sync", return_value=fake_token):
        await tsa_worker.process_job(session, claimed, max_attempts=8)

    refreshed_job = (
        (await session.execute(select(TsaJob).where(TsaJob.id == job.id))).scalars().one()
    )
    assert refreshed_job.status == "done"
    assert refreshed_job.attempts == 1
    assert refreshed_job.completed_at is not None

    refreshed_art = (
        (await session.execute(select(DatasetArtifact).where(DatasetArtifact.id == artifact.id)))
        .scalars()
        .one()
    )
    assert refreshed_art.timestamp_status == "verified"
    assert refreshed_art.rfc3161_tst_hex == ("ab" * 32)
    assert refreshed_art.rfc3161_tsa_url == "https://freetsa.example/tsr"
    assert refreshed_art.timestamp_attempts == 1
    assert refreshed_art.timestamp_last_error is None


# ---------------------------------------------------------------------------
# process_job — transient failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_job_transient_failure_reschedules(session):
    artifact = _seed_artifact()
    session.add(artifact)
    await session.flush()
    job = _seed_job(artifact.id, artifact.commit_id)
    session.add(job)
    await session.commit()

    claimed = await tsa_worker.claim_one_job(session)
    assert claimed is not None

    with patch.object(
        tsa_worker, "_fetch_token_sync", side_effect=RuntimeError("connection reset")
    ):
        await tsa_worker.process_job(session, claimed, max_attempts=8)

    refreshed_job = (
        (await session.execute(select(TsaJob).where(TsaJob.id == job.id))).scalars().one()
    )
    assert refreshed_job.status == "pending"
    assert refreshed_job.attempts == 1
    assert refreshed_job.last_error is not None
    assert "connection reset" in refreshed_job.last_error
    assert refreshed_job.next_attempt_at > datetime.now(timezone.utc).replace(tzinfo=None)

    refreshed_art = (
        (await session.execute(select(DatasetArtifact).where(DatasetArtifact.id == artifact.id)))
        .scalars()
        .one()
    )
    # Target row still pending, but observability columns updated.
    assert refreshed_art.timestamp_status == "pending"
    assert refreshed_art.timestamp_attempts == 1
    assert "connection reset" in (refreshed_art.timestamp_last_error or "")


# ---------------------------------------------------------------------------
# process_job — permanent failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_job_permanent_failure_after_max_attempts(session):
    artifact = _seed_artifact()
    session.add(artifact)
    await session.flush()
    # Already 7 prior attempts — next failure exhausts max_attempts=8.
    job = _seed_job(artifact.id, artifact.commit_id, attempts=7)
    session.add(job)
    await session.commit()

    claimed = await tsa_worker.claim_one_job(session)
    assert claimed is not None

    with patch.object(tsa_worker, "_fetch_token_sync", side_effect=RuntimeError("tsa down")):
        await tsa_worker.process_job(session, claimed, max_attempts=8)

    refreshed_job = (
        (await session.execute(select(TsaJob).where(TsaJob.id == job.id))).scalars().one()
    )
    assert refreshed_job.status == "failed"
    assert refreshed_job.attempts == 8
    assert refreshed_job.completed_at is not None

    refreshed_art = (
        (await session.execute(select(DatasetArtifact).where(DatasetArtifact.id == artifact.id)))
        .scalars()
        .one()
    )
    assert refreshed_art.timestamp_status == "failed"
    assert refreshed_art.timestamp_attempts == 8


# ---------------------------------------------------------------------------
# Sweeper
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sweeper_flips_past_grace_pending_to_failed(session):
    # Two artifacts: one within grace, one well past grace.
    fresh = _seed_artifact(commit_id="1" * 64)
    fresh.id = str(uuid.uuid4())
    fresh.manifest_hash = "1" * 64
    aged = _seed_artifact(commit_id="2" * 64)
    aged.id = str(uuid.uuid4())
    aged.manifest_hash = "2" * 64
    aged.epoch_timestamp = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(seconds=600)

    session.add(fresh)
    session.add(aged)
    await session.commit()

    flipped = await tsa_worker.run_sweeper_once(session, grace_seconds=300)
    assert flipped == 1

    rows = {r.id: r for r in (await session.execute(select(DatasetArtifact))).scalars().all()}
    assert rows[fresh.id].timestamp_status == "pending"
    assert rows[aged.id].timestamp_status == "failed"
    assert rows[aged.id].timestamp_last_error == "grace_window_exceeded"

    # Idempotency: a second sweep flips nothing.
    flipped_again = await tsa_worker.run_sweeper_once(session, grace_seconds=300)
    assert flipped_again == 0


# ---------------------------------------------------------------------------
# End-to-end: commit endpoint must not block on a hung TSA
# ---------------------------------------------------------------------------


def _make_commit_body() -> dict:
    """Minimal valid POST /datasets/commit body, signed with a fresh key.

    Delegates to the shared ``test_router_datasets`` helper so the request
    shape stays in lockstep with the canonical reference test.
    """
    from tests.test_router_datasets import build_commit_request, create_signing_keypair

    pubkey, _, signing_key = create_signing_keypair()
    return build_commit_request(
        pubkey,
        signing_key,
        dataset_name="h5-async-test",
        source_uri="https://example.com/h5.csv",
    )


@pytest.mark.asyncio
async def test_commit_dataset_does_not_block_on_hung_tsa(app_client):
    """``POST /datasets/commit`` must return 201 promptly even if the TSA hangs.

    H-5 regression test: the previous inline implementation would pin the
    request handler for the full TSA timeout (≥5s with our patch).  After
    the migration the TSA is enqueued and the handler must return well
    under that bound.
    """
    body = _make_commit_body()

    def _hang(*_args, **_kwargs):
        time.sleep(30)  # Simulate a TSA hang far beyond any real timeout.
        raise AssertionError("TSA must not be called inline")

    with patch("protocol.rfc3161.request_timestamp", side_effect=_hang):
        start = time.monotonic()
        resp = await app_client.post("/datasets/commit", json=body)
        elapsed = time.monotonic() - start

    assert resp.status_code == 201, resp.text
    assert resp.json()["timestamp_status"] == "pending"
    # Generous bound to keep CI stable; the real path should be milliseconds.
    assert elapsed < 2.0, f"commit_dataset took {elapsed:.2f}s — TSA likely still inline"


@pytest.mark.asyncio
async def test_commit_dataset_enqueues_tsa_job(app_client, session_factory):
    """A successful commit must leave exactly one ``pending`` ``tsa_jobs`` row."""
    body = _make_commit_body()

    fake_token = MagicMock()
    fake_token.tst_bytes = b"\x00"
    fake_token.tsa_url = "https://freetsa.org/tsr"
    with patch("protocol.rfc3161.request_timestamp", return_value=fake_token):
        resp = await app_client.post("/datasets/commit", json=body)
    assert resp.status_code == 201

    async with session_factory() as session:
        jobs = (await session.execute(select(TsaJob))).scalars().all()
    assert len(jobs) == 1
    assert jobs[0].status == "pending"
    assert jobs[0].target_table == "dataset_artifacts"
    assert jobs[0].hash_hex == resp.json()["commit_id"]


@pytest.mark.asyncio
async def test_worker_drains_enqueued_job_end_to_end(app_client, session_factory):
    """End-to-end: commit → worker tick → /verify reports ``verified``."""
    body = _make_commit_body()
    resp = await app_client.post("/datasets/commit", json=body)
    assert resp.status_code == 201
    dataset_id = resp.json()["dataset_id"]

    fake_token = MagicMock()
    fake_token.tst_bytes = b"\xcd" * 16
    fake_token.tsa_url = "https://freetsa.example/tsr"

    # Run a single worker iteration directly (no asyncio.run loop).
    async with session_factory() as session:
        # Patch the AsyncSessionLocal used by the worker so it sees the
        # in-memory test DB rather than the production engine.
        with (
            patch.object(tsa_worker, "AsyncSessionLocal", session_factory),
            patch.object(tsa_worker, "_fetch_token_sync", return_value=fake_token),
        ):
            stop = asyncio.Event()
            stop.set()  # Worker will exit after one iteration.

            # Drive the loop manually instead of run_worker so we don't
            # depend on the poll-interval timing.
            claimed = await tsa_worker.claim_one_job(session)
            assert claimed is not None
            await tsa_worker.process_job(session, claimed, max_attempts=8)

    resp = await app_client.get(f"/datasets/{dataset_id}/verify")
    assert resp.status_code == 200
    data = resp.json()
    assert data["timestamp_state"] == "verified"
    assert data["rfc3161_valid"] is True
