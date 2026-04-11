"""
Coverage boost tests for under-covered API modules.

Targets:
    - api/services/shard.py           — _ShardRing, assign_shard, compute_state_root
    - api/routers/documents.py        — embargo, missing lookup key, verify not-found
    - api/routers/admin.py            — /api/admin/stats, /api/admin/customers, CSV export
    - api/sth.py                      — set_storage, _require_storage, /protocol/sth/*
    - api/routers/shards.py           — /shards, /metrics, /shards/{id}/alert/smt-divergence
    - api/routers/ledger.py           — /ledger/state, /ledger/shard/{id}, /ledger/proof/{id},
                                        /ledger/activity, /ledger/verify/simple
    - api/services/storage_layer.py   — _is_db_unavailable_error, db_op, get_storage_status
    - api/routers/witness.py          — checkpoints, gossip, health
    - api/routers/requests.py         — list with filters, get by display_id, status transition
"""

from __future__ import annotations

from datetime import datetime, timedelta

import blake3
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.models.document import DocCommit
from api.models.ledger_activity import LedgerActivity
from api.models.purchase import Purchase
from api.models.user import User


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


def _b3(s: str) -> str:
    """Compute a BLAKE3 hex digest of a string."""
    return blake3.blake3(s.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture()
async def session_factory(db_engine):
    return async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)


@pytest_asyncio.fixture()
async def db_session(session_factory):
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture()
async def client(session_factory):
    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# 1. api/services/shard.py — _ShardRing unit tests
# ---------------------------------------------------------------------------


class TestShardRing:
    """Test the consistent-hash ring used for shard assignment."""

    def test_single_shard_ring_returns_default(self):
        from api.services.shard import DEFAULT_SHARD_ID, _ShardRing

        ring = _ShardRing([DEFAULT_SHARD_ID])
        assert ring.single_shard is True
        assert ring.assign("any-key") == DEFAULT_SHARD_ID
        assert ring.assign("another-key") == DEFAULT_SHARD_ID

    def test_empty_shard_ring_returns_default(self):
        from api.services.shard import DEFAULT_SHARD_ID, _ShardRing

        ring = _ShardRing([])
        assert ring.single_shard is True
        assert ring.assign("key") == DEFAULT_SHARD_ID

    def test_multi_shard_ring_is_deterministic(self):
        from api.services.shard import _ShardRing

        shards = ["shard-a", "shard-b", "shard-c"]
        ring = _ShardRing(shards)
        assert ring.single_shard is False

        # Same key always maps to the same shard
        result1 = ring.assign("request-123")
        result2 = ring.assign("request-123")
        assert result1 == result2
        assert result1 in shards

    def test_multi_shard_ring_distributes_keys(self):
        from api.services.shard import _ShardRing

        shards = ["shard-x", "shard-y"]
        ring = _ShardRing(shards)
        assignments = {ring.assign(f"key-{i}") for i in range(200)}
        # With 200 random keys across 2 shards, both should be hit
        assert len(assignments) == 2

    def test_assign_shard_uses_module_ring(self):
        from api.services.shard import assign_shard

        # Default ring has a single shard, so all keys map to it
        result = assign_shard("any-request-id")
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# 2. api/services/shard.py — compute_state_root
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_compute_state_root_empty_shard(db_session):
    """An empty shard should return 64 zero characters."""
    from api.services.shard import compute_state_root

    root = await compute_state_root("nonexistent-shard", db_session)
    assert root == "0" * 64


@pytest.mark.asyncio
async def test_compute_state_root_with_commits(db_session):
    """A shard with commits should return a non-zero root."""
    from api.services.shard import compute_state_root

    shard = "test-shard-01"
    for i in range(3):
        commit = DocCommit(
            doc_hash=_b3(f"doc-{i}"),
            commit_id=f"0x{_b3(f'cid-{i}')}",
            shard_id=shard,
            merkle_root=None,
        )
        db_session.add(commit)
    await db_session.commit()

    root = await compute_state_root(shard, db_session)
    assert root != "0" * 64
    assert len(root) == 64


# ---------------------------------------------------------------------------
# 3. api/routers/documents.py — embargo & missing-key paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_missing_lookup_key(client):
    """POST /doc/verify with empty body → 422 MISSING_LOOKUP_KEY."""
    resp = await client.post("/doc/verify", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_verify_embargoed_document(client, db_session):
    """Embargoed document should return 403 on verification."""
    from unittest.mock import patch

    from api.services.hasher import generate_commit_id

    doc_hash = _b3("embargoed-doc")
    commit_id = generate_commit_id()
    # SQLite strips tzinfo, so store a naive future datetime and patch the
    # comparison target in the router to also be naive.
    future_naive = datetime.utcnow() + timedelta(days=30)  # noqa: DTZ003
    commit = DocCommit(
        doc_hash=doc_hash,
        commit_id=commit_id,
        shard_id="0x4F3A",
        embargo_until=future_naive,
        merkle_root=None,
    )
    db_session.add(commit)
    await db_session.commit()

    # Patch datetime.now in the router module to return a naive UTC datetime
    # so the comparison doesn't raise on SQLite.
    fake_now = datetime.utcnow()  # noqa: DTZ003
    with patch("api.routers.documents.datetime") as mock_dt:
        mock_dt.now.return_value = fake_now
        mock_dt.side_effect = lambda *a, **kw: datetime(*a, **kw)
        verify_resp = await client.post("/doc/verify", json={"commit_id": commit_id})
    assert verify_resp.status_code == 403


@pytest.mark.asyncio
async def test_verify_nonexistent_commit_returns_false(client):
    """Verifying a commit that doesn't exist returns verified=False."""
    fake_id = "0x" + "ab" * 32
    resp = await client.post("/doc/verify", json={"commit_id": fake_id})
    assert resp.status_code == 200
    assert resp.json()["verified"] is False


# ---------------------------------------------------------------------------
# 4. api/routers/admin.py — stats, customers, CSV export
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_stats_empty_db(client):
    """GET /api/admin/stats returns zeroed metrics on empty DB."""
    resp = await client.get("/api/admin/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_count"] == 0
    assert data["total_revenue"] == 0
    assert data["conversion_rate"] == 0.0


@pytest.mark.asyncio
async def test_admin_stats_with_data(client, db_session):
    """GET /api/admin/stats returns correct metrics after seeding data."""
    user = User(email="alice@example.com", role="user", plan="pro")
    db_session.add(user)
    await db_session.flush()
    db_session.add(Purchase(user_id=user.id, price=29.99, description="Pro plan"))
    await db_session.commit()

    resp = await client.get("/api/admin/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert data["user_count"] >= 1
    assert data["total_revenue"] >= 29.0


@pytest.mark.asyncio
async def test_admin_customers_empty(client):
    """GET /api/admin/customers returns empty list on empty DB."""
    resp = await client.get("/api/admin/customers")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_admin_customers_with_data(client, db_session):
    """GET /api/admin/customers returns seeded users."""
    db_session.add(User(email="bob@test.com", role="user", plan="free"))
    await db_session.commit()

    resp = await client.get("/api/admin/customers?page=1&per_page=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    assert any(c["email"] == "bob@test.com" for c in data["items"])


@pytest.mark.asyncio
async def test_admin_customers_export_csv(client, db_session):
    """GET /api/admin/customers/export returns valid CSV."""
    db_session.add(User(email="csv@test.com", role="admin", plan="pro"))
    await db_session.commit()

    resp = await client.get("/api/admin/customers/export")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    body = resp.text
    assert "id,email,role,plan,created_at" in body
    assert "csv@test.com" in body


# ---------------------------------------------------------------------------
# 5. api/sth.py — STH storage helper functions
# ---------------------------------------------------------------------------


class TestSTHHelpers:
    """Test set_storage / _require_storage helpers in api.sth."""

    def test_require_storage_raises_503_when_none(self):
        from fastapi import HTTPException

        from api.sth import _require_storage, set_storage

        set_storage(None)
        with pytest.raises(HTTPException) as exc_info:
            _require_storage()
        assert exc_info.value.status_code == 503

    def test_set_and_require_storage(self):
        from api.sth import _require_storage, set_storage

        sentinel = object()
        set_storage(sentinel)
        assert _require_storage() is sentinel
        # Clean up
        set_storage(None)


# ---------------------------------------------------------------------------
# 6. api/routers/ledger.py — state, shard, proof, activity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ledger_state_empty(client):
    """GET /ledger/state on empty DB returns zero root."""
    resp = await client.get("/ledger/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["global_state_root"] == "0" * 64
    assert data["total_commits"] == 0


@pytest.mark.asyncio
async def test_ledger_state_with_commits(client):
    """GET /ledger/state after commits returns non-zero root."""
    doc_hash = _b3("ledger-state-test")
    await client.post("/doc/commit", json={"doc_hash": doc_hash})

    resp = await client.get("/ledger/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_commits"] >= 1


@pytest.mark.asyncio
async def test_ledger_shard_state(client):
    """GET /ledger/shard/{shard_id} returns shard info."""
    doc_hash = _b3("shard-state-doc")
    await client.post("/doc/commit", json={"doc_hash": doc_hash})

    resp = await client.get("/ledger/shard/0x4F3A")
    assert resp.status_code == 200
    data = resp.json()
    assert data["shard_id"] == "0x4F3A"
    assert data["commit_count"] >= 1


@pytest.mark.asyncio
async def test_ledger_proof_not_found(client):
    """GET /ledger/proof/{nonexistent} returns 404."""
    resp = await client.get("/ledger/proof/0xdeadbeefdeadbeefdeadbeefdeadbeef")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_ledger_proof_found(client):
    """GET /ledger/proof/{commit_id} returns proof for an existing commit."""
    doc_hash = _b3("proof-test-doc")
    commit_resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    commit_id = commit_resp.json()["commit_id"]

    resp = await client.get(f"/ledger/proof/{commit_id}")
    # In dev mode: 200 with proof; in prod mode: 202 with pending
    assert resp.status_code in (200, 202)
    data = resp.json()
    assert data["commit_id"] == commit_id


@pytest.mark.asyncio
async def test_ledger_activity_empty(client):
    """GET /ledger/activity returns empty feed on empty DB."""
    resp = await client.get("/ledger/activity")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_ledger_activity_with_data(client, db_session):
    """GET /ledger/activity returns seeded activity."""
    activity = LedgerActivity(
        activity_type="DOCUMENT_SUBMITTED",
        title="Test Doc Submitted",
        description="A test document was submitted.",
        user_friendly_status="✓ Complete",
    )
    db_session.add(activity)
    await db_session.commit()

    resp = await client.get("/ledger/activity")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1


@pytest.mark.asyncio
async def test_ledger_activity_filter_by_type(client, db_session):
    """GET /ledger/activity?activity_type=X filters correctly."""
    for act_type in ("DOCUMENT_SUBMITTED", "VERIFICATION_SUCCESS"):
        db_session.add(
            LedgerActivity(
                activity_type=act_type,
                title=f"Title {act_type}",
                description=f"Desc {act_type}",
                user_friendly_status="✓",
            )
        )
    await db_session.commit()

    resp = await client.get("/ledger/activity?activity_type=VERIFICATION_SUCCESS")
    assert resp.status_code == 200
    data = resp.json()
    for item in data["items"]:
        assert item["activity_type"] == "VERIFICATION_SUCCESS"


@pytest.mark.asyncio
async def test_ledger_verify_simple_missing_input(client):
    """POST /ledger/verify/simple with no input returns 400."""
    resp = await client.post("/ledger/verify/simple")
    # The endpoint checks for file, commit_id, or doc_hash
    assert resp.status_code == 400 or resp.status_code == 422


@pytest.mark.asyncio
async def test_ledger_verify_simple_by_commit_id(client):
    """POST /ledger/verify/simple with commit_id."""
    doc_hash = _b3("simple-verify-commit")
    commit_resp = await client.post("/doc/commit", json={"doc_hash": doc_hash})
    commit_id = commit_resp.json()["commit_id"]

    resp = await client.post(
        "/ledger/verify/simple",
        data={"commit_id": commit_id},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is True


@pytest.mark.asyncio
async def test_ledger_verify_simple_by_doc_hash(client):
    """POST /ledger/verify/simple with doc_hash."""
    doc_hash = _b3("simple-verify-hash")
    await client.post("/doc/commit", json={"doc_hash": doc_hash})

    resp = await client.post(
        "/ledger/verify/simple",
        data={"doc_hash": doc_hash},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["verified"] is True


# ---------------------------------------------------------------------------
# 7. api/services/storage_layer.py — helper functions
# ---------------------------------------------------------------------------


class TestStorageLayerHelpers:
    """Test helper functions in api/services/storage_layer.py."""

    def test_is_db_unavailable_runtime_error_retries(self):
        from api.services.storage_layer import _is_db_unavailable_error

        exc = RuntimeError("failed to acquire postgresql connection after retries")
        assert _is_db_unavailable_error(exc) is True

    def test_is_db_unavailable_circuit_breaker(self):
        from api.services.storage_layer import _is_db_unavailable_error

        exc = RuntimeError("circuit breaker is open")
        assert _is_db_unavailable_error(exc) is True

    def test_is_db_unavailable_generic_error(self):
        from api.services.storage_layer import _is_db_unavailable_error

        assert _is_db_unavailable_error(ValueError("some error")) is False

    def test_is_db_unavailable_generic_runtime_error(self):
        from api.services.storage_layer import _is_db_unavailable_error

        assert _is_db_unavailable_error(RuntimeError("unrelated error")) is False

    def test_db_op_passes_through(self):
        from api.services.storage_layer import db_op

        with db_op("test op"):
            pass  # no exception → no error

    def test_db_op_reraises_http_exception(self):
        from fastapi import HTTPException

        from api.services.storage_layer import db_op

        with pytest.raises(HTTPException) as exc_info:
            with db_op("test"):
                raise HTTPException(status_code=404, detail="not found")
        assert exc_info.value.status_code == 404

    def test_db_op_converts_db_error_to_503(self):
        from fastapi import HTTPException

        from api.services.storage_layer import db_op

        with pytest.raises(HTTPException) as exc_info:
            with db_op("test"):
                raise RuntimeError("failed to acquire postgresql connection")
        assert exc_info.value.status_code == 503

    def test_db_op_reraises_non_db_error(self):
        from api.services.storage_layer import db_op

        with pytest.raises(TypeError):
            with db_op("test"):
                raise TypeError("not a db error")

    def test_get_storage_status_not_initialized(self):
        import api.services.storage_layer as sl

        original = sl._storage
        sl._storage = None
        sl._db_error = None
        try:
            status_str, check = sl.get_storage_status()
            assert status_str == "not_initialized"
            assert check is False
        finally:
            sl._storage = original

    def test_get_storage_status_error(self):
        import api.services.storage_layer as sl

        original_storage = sl._storage
        original_error = sl._db_error
        sl._storage = None
        sl._db_error = "connection refused"
        try:
            status_str, check = sl.get_storage_status()
            assert status_str == "error"
            assert check is False
        finally:
            sl._storage = original_storage
            sl._db_error = original_error


# ---------------------------------------------------------------------------
# 8. api/routers/witness.py — checkpoints, gossip, health
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_witness_health(client):
    """GET /witness/health returns status."""
    resp = await client.get("/witness/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["observation_count"] == 0


@pytest.mark.asyncio
async def test_witness_latest_checkpoint_empty(client):
    """GET /witness/checkpoints/latest on empty DB returns 404."""
    resp = await client.get("/witness/checkpoints/latest")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_witness_checkpoint_by_seq_not_found(client):
    """GET /witness/checkpoints/999 returns 404."""
    resp = await client.get("/witness/checkpoints/999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_witness_list_checkpoints_empty(client):
    """GET /witness/checkpoints returns empty list."""
    resp = await client.get("/witness/checkpoints")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_witness_gossip_empty(client):
    """GET /witness/gossip with no data returns empty list."""
    resp = await client.get("/witness/gossip")
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# 9. api/routers/requests.py — list, get, status transitions
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_file_request(client):
    """POST /requests creates a new request."""
    resp = await client.post(
        "/requests",
        json={
            "subject": "Budget Records 2024",
            "description": "All budget documents for fiscal year 2024.",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["display_id"].startswith("OLY-")
    assert data["status"] == "PENDING"


@pytest.mark.asyncio
async def test_list_requests_empty(client):
    """GET /requests returns empty list on empty DB."""
    resp = await client.get("/requests")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


@pytest.mark.asyncio
async def test_list_requests_with_filter(client):
    """GET /requests with status filter works."""
    await client.post(
        "/requests",
        json={"subject": "Filtered req", "description": "Test filtering."},
    )
    resp = await client.get("/requests?status=PENDING")
    assert resp.status_code == 200
    for item in resp.json():
        assert item["status"] == "PENDING"


@pytest.mark.asyncio
async def test_list_requests_with_search(client):
    """GET /requests with search parameter."""
    await client.post(
        "/requests",
        json={"subject": "Unique Banana Search", "description": "Find this."},
    )
    resp = await client.get("/requests?search=Banana")
    assert resp.status_code == 200
    assert any("Banana" in r["subject"] for r in resp.json())


@pytest.mark.asyncio
async def test_get_request_not_found(client):
    """GET /requests/OLY-9999 returns 404."""
    resp = await client.get("/requests/OLY-9999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_request_found(client):
    """GET /requests/{display_id} returns the request."""
    create_resp = await client.post(
        "/requests",
        json={"subject": "Lookup test", "description": "Test get by ID."},
    )
    display_id = create_resp.json()["display_id"]

    resp = await client.get(f"/requests/{display_id}")
    assert resp.status_code == 200
    assert resp.json()["display_id"] == display_id


@pytest.mark.asyncio
async def test_status_transition_pending_to_acknowledged(client):
    """PATCH /requests/{id}/status PENDING→ACKNOWLEDGED succeeds."""
    create_resp = await client.post(
        "/requests",
        json={"subject": "Transition test", "description": "Status transition."},
    )
    display_id = create_resp.json()["display_id"]

    resp = await client.patch(
        f"/requests/{display_id}/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ACKNOWLEDGED"


@pytest.mark.asyncio
async def test_status_transition_invalid(client):
    """PATCH /requests/{id}/status with invalid transition returns 409."""
    create_resp = await client.post(
        "/requests",
        json={"subject": "Invalid transition", "description": "Should fail."},
    )
    display_id = create_resp.json()["display_id"]

    # Fulfill first so it becomes terminal
    await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})

    # FULFILLED → PENDING is not allowed
    resp = await client.patch(f"/requests/{display_id}/status", json={"status": "PENDING"})
    assert resp.status_code == 409


@pytest.mark.asyncio
async def test_status_transition_not_found(client):
    """PATCH /requests/OLY-9999/status returns 404."""
    resp = await client.patch(
        "/requests/OLY-9999/status",
        json={"status": "ACKNOWLEDGED"},
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 10. Health & root endpoints
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_root_endpoint(client):
    """GET / returns service info."""
    resp = await client.get("/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_health_endpoint(client):
    """GET /health returns ok."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] in ("ok", "degraded")
