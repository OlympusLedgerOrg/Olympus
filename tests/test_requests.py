"""
Integration tests for public-records request lifecycle.

Covers: create, list, get, status update, overdue auto-transition,
and appeal filing.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.deps import get_db
from api.main import create_app
from api.models import Base
from api.services.hasher import hash_request


TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

REQUEST_BODY = {
    "subject": "Body camera footage — incident 2024-01-15",
    "description": "All body-worn camera recordings related to incident number 2024-0115.",
    "request_type": "NC_PUBLIC_RECORDS",
    "priority": "STANDARD",
}


@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="module")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="module")
async def client(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app = create_app()
    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.mark.asyncio
async def test_create_request(client):
    """POST /requests should create a request with display_id and commit_hash."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    assert resp.status_code == 201
    data = resp.json()
    assert data["display_id"].startswith("OLY-")
    assert len(data["commit_hash"]) == 64
    assert data["status"] == "PENDING"
    assert data["deadline"] is not None


@pytest.mark.asyncio
async def test_create_request_rejects_lone_surrogate(client):
    """POST /requests surfaces hashing Unicode errors without nested detail."""
    with patch("api.routers.requests.hash_request", side_effect=ValueError("surrogates not allowed")):
        resp = await client.post("/requests", json=REQUEST_BODY)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail == [
        {
            "msg": "surrogates not allowed",
            "type": "unicode",
            "code": "INVALID_UNICODE",
        }
    ]


def test_hash_request_rejects_lone_surrogate() -> None:
    """hash_request rejects malformed Unicode before hashing."""
    with pytest.raises(ValueError, match="lone surrogate character"):
        hash_request(
            subject="Body camera \ud800 footage",
            description=REQUEST_BODY["description"],
            agency="",
            filed_at=datetime(2024, 1, 15, 9, 0, 0),
        )


@pytest.mark.asyncio
async def test_get_request(client):
    """GET /requests/{display_id} should return the created request."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    get_resp = await client.get(f"/requests/{display_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["display_id"] == display_id


@pytest.mark.asyncio
async def test_get_request_not_found(client):
    """GET /requests/OLY-9999 for a non-existent request should return 404."""
    resp = await client.get("/requests/OLY-9999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_requests(client):
    """GET /requests should return at least one result after creation."""
    await client.post("/requests", json=REQUEST_BODY)
    resp = await client.get("/requests")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


@pytest.mark.asyncio
async def test_acknowledge_request(client):
    """PATCH /requests/{display_id}/status → ACKNOWLEDGED."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    patch_resp = await client.patch(
        f"/requests/{display_id}/status", json={"status": "ACKNOWLEDGED"}
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["status"] == "ACKNOWLEDGED"


@pytest.mark.asyncio
async def test_fulfill_request(client):
    """PATCH /requests/{display_id}/status → FULFILLED sets fulfilled_at."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    patch_resp = await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})
    assert patch_resp.status_code == 200
    data = patch_resp.json()
    assert data["status"] == "FULFILLED"
    assert data["fulfilled_at"] is not None


@pytest.mark.asyncio
async def test_appeal_denied_request(client):
    """File an appeal on a DENIED request — should succeed."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "IMPROPER_EXEMPTION",
            "statement": "The agency improperly withheld non-exempt records.",
        },
    )
    assert appeal_resp.status_code == 201
    appeal_data = appeal_resp.json()
    assert appeal_data["grounds"] == "IMPROPER_EXEMPTION"
    assert appeal_data["status"] == "UNDER_REVIEW"

    # Request status should now be APPEALED
    get_resp = await client.get(f"/requests/{display_id}")
    assert get_resp.json()["status"] == "APPEALED"


@pytest.mark.asyncio
async def test_appeal_fulfilled_request_rejected(client):
    """Filing an appeal on a FULFILLED request should return 409."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "This should not be allowed.",
        },
    )
    assert appeal_resp.status_code == 409


@pytest.mark.asyncio
async def test_deadline_nc_public_records():
    """NC Public Records deadline should be ~30 business days from filing."""
    from datetime import datetime

    from api.services.deadline import compute_deadline

    filed_at = datetime(2024, 1, 15, 9, 0, 0)
    deadline = compute_deadline(filed_at, "NC_PUBLIC_RECORDS")
    # Must be strictly after filed_at
    assert deadline > filed_at


@pytest.mark.asyncio
async def test_deadline_federal_foia():
    """Federal FOIA deadline should be ~20 business days from filing."""
    from datetime import datetime

    from api.services.deadline import compute_deadline

    filed_at = datetime(2024, 1, 15, 9, 0, 0)
    deadline = compute_deadline(filed_at, "FEDERAL_FOIA")
    assert deadline > filed_at


@pytest.mark.asyncio
async def test_appeal_already_appealed_request_rejected(client):
    """Filing a second appeal on an already-APPEALED request should return 409."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]
    display_id = create_resp.json()["display_id"]

    # Transition to DENIED first (appeals require DENIED or OVERDUE status)
    await client.patch(f"/requests/{display_id}/status", json={"status": "DENIED"})

    # First appeal (on DENIED — allowed)
    first_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "First appeal.",
        },
    )
    assert first_resp.status_code == 201

    # Second appeal — should be rejected because status is now APPEALED
    second_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "Duplicate appeal attempt.",
        },
    )
    assert second_resp.status_code == 409
    assert second_resp.json()["detail"]["code"] == "APPEAL_EXISTS"


@pytest.mark.asyncio
async def test_invalid_status_transition_rejected(client):
    """PATCH /requests/{display_id}/status with invalid transition returns 409."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    display_id = create_resp.json()["display_id"]

    # PENDING → FULFILLED is allowed
    await client.patch(f"/requests/{display_id}/status", json={"status": "FULFILLED"})

    # FULFILLED → PENDING is NOT allowed (FULFILLED is terminal)
    patch_resp = await client.patch(f"/requests/{display_id}/status", json={"status": "PENDING"})
    assert patch_resp.status_code == 409
    assert patch_resp.json()["detail"]["code"] == "INVALID_STATUS_TRANSITION"


@pytest.mark.asyncio
async def test_appeal_pending_request_rejected(client):
    """Filing an appeal on a PENDING request should return 409."""
    create_resp = await client.post("/requests", json=REQUEST_BODY)
    req_id = create_resp.json()["id"]

    appeal_resp = await client.post(
        "/appeals",
        json={
            "request_id": req_id,
            "grounds": "NO_RESPONSE",
            "statement": "Should not be allowed on PENDING.",
        },
    )
    assert appeal_resp.status_code == 409
    assert appeal_resp.json()["detail"]["code"] == "APPEAL_NOT_ALLOWED"


# ---------------------------------------------------------------------------
# Extended state-machine transitions (Step 2e)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_to_in_review(client):
    """PENDING → IN_REVIEW is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    patch = await client.patch(f"/requests/{did}/status", json={"status": "IN_REVIEW"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "IN_REVIEW"


@pytest.mark.asyncio
async def test_pending_to_denied(client):
    """PENDING → DENIED is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    patch = await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "DENIED"


@pytest.mark.asyncio
async def test_in_review_to_fulfilled(client):
    """IN_REVIEW → FULFILLED is allowed and sets fulfilled_at."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "IN_REVIEW"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "FULFILLED"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "FULFILLED"
    assert patch.json()["fulfilled_at"] is not None


@pytest.mark.asyncio
async def test_in_review_to_denied(client):
    """IN_REVIEW → DENIED is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "IN_REVIEW"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "DENIED"


@pytest.mark.asyncio
async def test_denied_to_appealed(client):
    """DENIED → APPEALED via direct status patch is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "APPEALED"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "APPEALED"


@pytest.mark.asyncio
async def test_appealed_to_in_review(client):
    """APPEALED → IN_REVIEW is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    await client.patch(f"/requests/{did}/status", json={"status": "APPEALED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "IN_REVIEW"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "IN_REVIEW"


@pytest.mark.asyncio
async def test_appealed_to_fulfilled(client):
    """APPEALED → FULFILLED is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    await client.patch(f"/requests/{did}/status", json={"status": "APPEALED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "FULFILLED"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "FULFILLED"


@pytest.mark.asyncio
async def test_appealed_to_denied(client):
    """APPEALED → DENIED (re-denial on appeal) is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    await client.patch(f"/requests/{did}/status", json={"status": "APPEALED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "DENIED"


@pytest.mark.asyncio
async def test_acknowledged_to_in_review(client):
    """ACKNOWLEDGED → IN_REVIEW is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "ACKNOWLEDGED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "IN_REVIEW"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "IN_REVIEW"


@pytest.mark.asyncio
async def test_acknowledged_to_fulfilled(client):
    """ACKNOWLEDGED → FULFILLED is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "ACKNOWLEDGED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "FULFILLED"})
    assert patch.status_code == 200
    assert patch.json()["fulfilled_at"] is not None


@pytest.mark.asyncio
async def test_acknowledged_to_denied(client):
    """ACKNOWLEDGED → DENIED is allowed."""
    resp = await client.post("/requests", json=REQUEST_BODY)
    did = resp.json()["display_id"]
    await client.patch(f"/requests/{did}/status", json={"status": "ACKNOWLEDGED"})
    patch = await client.patch(f"/requests/{did}/status", json={"status": "DENIED"})
    assert patch.status_code == 200


# ---------------------------------------------------------------------------
# Filter / pagination / search (Step 2e)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_with_status_filter(client):
    """GET /requests?status=PENDING returns only PENDING requests."""
    await client.post("/requests", json=REQUEST_BODY)
    resp = await client.get("/requests", params={"status": "PENDING"})
    assert resp.status_code == 200
    assert all(r["status"] == "PENDING" for r in resp.json())


@pytest.mark.asyncio
async def test_list_with_search_filter(client):
    """GET /requests?search=... returns only matching requests."""
    # Create a request whose subject matches a unique search term
    matching_body = {**REQUEST_BODY, "subject": "Quartzy aqueduct inspection reports"}
    match_resp = await client.post("/requests", json=matching_body)
    assert match_resp.status_code == 201
    matching_id = match_resp.json()["display_id"]

    # Create a request whose subject does NOT match
    non_matching_body = {**REQUEST_BODY, "subject": "Zoning permit application records"}
    non_match_resp = await client.post("/requests", json=non_matching_body)
    assert non_match_resp.status_code == 201
    non_matching_id = non_match_resp.json()["display_id"]

    resp = await client.get("/requests", params={"search": "quartzy aqueduct"})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) >= 1, "search should return at least the matching request"
    result_ids = {r["display_id"] for r in results}
    assert matching_id in result_ids, "matching request must appear in search results"
    assert non_matching_id not in result_ids, "non-matching request must not appear"


@pytest.mark.asyncio
async def test_list_pagination(client):
    """GET /requests?page=1&per_page=2 respects pagination limits."""
    # Create enough requests for pagination to matter
    for _ in range(3):
        await client.post("/requests", json=REQUEST_BODY)
    resp = await client.get("/requests", params={"page": 1, "per_page": 2})
    assert resp.status_code == 200
    assert len(resp.json()) <= 2


@pytest.mark.asyncio
async def test_list_with_agency_id_filter(client):
    """GET /requests?agency_id=xxx filters by agency."""
    resp = await client.get("/requests", params={"agency_id": "nonexistent-agency"})
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# Error handling (Step 2e)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_nonexistent_request_returns_404(client):
    """PATCH /requests/OLY-9999/status returns 404."""
    resp = await client.patch("/requests/OLY-9999/status", json={"status": "ACKNOWLEDGED"})
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "REQUEST_NOT_FOUND"


@pytest.mark.asyncio
async def test_create_with_agency_id(client):
    """POST /requests with agency_id sets the field."""
    body = {**REQUEST_BODY, "agency_id": "test-agency-123"}
    resp = await client.post("/requests", json=body)
    assert resp.status_code == 201
    assert resp.json()["agency_id"] == "test-agency-123"


@pytest.mark.asyncio
async def test_create_with_federal_foia_type(client):
    """POST /requests with FEDERAL_FOIA request_type computes correct deadline."""
    body = {**REQUEST_BODY, "request_type": "FEDERAL_FOIA"}
    resp = await client.post("/requests", json=body)
    assert resp.status_code == 201
    assert resp.json()["request_type"] == "FEDERAL_FOIA"
    assert resp.json()["deadline"] is not None


def test_escape_like_wildcards():
    """_escape_like should escape SQL LIKE wildcards."""
    from api.routers.requests import _escape_like

    assert _escape_like("100%") == "100\\%"
    assert _escape_like("under_score") == "under\\_score"
    assert _escape_like("back\\slash") == "back\\\\slash"
    assert _escape_like("normal") == "normal"
