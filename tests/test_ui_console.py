"""Tests for developer debug console UI."""

import json
from urllib.error import HTTPError

from fastapi.testclient import TestClient

import ui.app as ui_app


client = TestClient(ui_app.app)


def test_console_shows_db_unavailable_banner(monkeypatch):
    """Root page should show DB unavailable banner on 503 from API."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    def raise_503(path: str):
        raise HTTPError(url=path, code=503, msg="service unavailable", hdrs=None, fp=None)

    monkeypatch.setattr(ui_app, "_fetch_json", raise_503)

    response = client.get("/")

    assert response.status_code == 200
    assert "Database unavailable (503)." in response.text


def test_console_shows_chain_broken_banner(monkeypatch):
    """Root page should show chain broken banner when tail linkage is invalid."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    def fake_fetch(path: str):
        if path == "/shards":
            return [{"shard_id": "s1", "latest_seq": 2, "latest_root": "abc"}]
        if path == "/shards/s1/header/latest":
            return {
                "shard_id": "s1",
                "seq": 2,
                "root_hash": "abc",
                "header_hash": "0" * 64,
                "previous_header_hash": "",
                "timestamp": "2026-01-01T00:00:00Z",
                "signature": "0" * 128,
                "pubkey": "0" * 64,
                "canonical_header_json": "{}",
            }
        if path == "/ledger/s1/tail?n=10":
            return {
                "shard_id": "s1",
                "entries": [
                    {"prev_entry_hash": "x", "entry_hash": "e2"},
                    {"prev_entry_hash": "y", "entry_hash": "e1"},
                ],
            }
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(ui_app, "_fetch_json", fake_fetch)

    response = client.get("/")

    assert response.status_code == 200
    assert "Chain linkage broken in shard s1 ledger tail." in response.text


def test_console_shows_invalid_signature_banner(monkeypatch):
    """Root page should show invalid signature banner when verification fails."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    def fake_fetch(path: str):
        if path == "/shards":
            return [{"shard_id": "s1", "latest_seq": 1, "latest_root": "abc"}]
        if path == "/shards/s1/header/latest":
            return {"header_hash": "0" * 64, "signature": "0" * 128, "pubkey": "0" * 64}
        if path == "/ledger/s1/tail?n=10":
            return {"shard_id": "s1", "entries": []}
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(ui_app, "_fetch_json", fake_fetch)
    monkeypatch.setattr(ui_app, "_verify_signature", lambda header: False)

    response = client.get("/")

    assert response.status_code == 200
    assert "Invalid signature detected for shard s1." in response.text


def test_debug_ui_disabled_by_default(monkeypatch):
    """Debug console and proof explorer return 404 when OLYMPUS_DEBUG_UI is not set."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", False)

    assert client.get("/").status_code == 404
    assert (
        client.get("/proof-explorer?shard_id=s&record_type=t&record_id=r&version=1").status_code
        == 404
    )


def test_console_uses_theme_tokens(monkeypatch):
    """Root page should expose CSS custom properties for the theme system."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "--bg:" in response.text
    assert "--accent:" in response.text
    assert "--surface-muted:" in response.text
    assert "@media (prefers-color-scheme: dark)" in response.text
    assert "background: var(--bg);" in response.text
    assert "color: var(--accent);" in response.text


# ── Commit Document endpoint ────────────────────────────────────────────────


def test_commit_txt_file(monkeypatch):
    """POST /commit with a plain-text file returns BLAKE3 and Poseidon roots."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = b"Section one\nSection two\nSection three\n"
    response = client.post(
        "/commit",
        data={"document_id": "doc1", "version": 1},
        files={"file": ("doc.txt", content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["document_id"] == "doc1"
    assert data["version"] == 1
    assert data["sections_count"] == 3
    assert len(data["blake3_root"]) == 64
    assert data["poseidon_root"].isdigit()
    assert data["commit_key"] == "doc1:1"


def test_commit_json_file(monkeypatch):
    """POST /commit with a JSON array file returns correct section count."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = json.dumps(["Alpha", "Beta", "Gamma"]).encode()
    response = client.post(
        "/commit",
        data={"document_id": "docJ", "version": 2},
        files={"file": ("doc.json", content, "application/json")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["sections_count"] == 3


def test_commit_empty_file_returns_error(monkeypatch):
    """POST /commit with an empty file should return a 400 error."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    response = client.post(
        "/commit",
        data={"document_id": "empty", "version": 1},
        files={"file": ("doc.txt", b"\n\n\n", "text/plain")},
    )

    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_commit_disabled_returns_404(monkeypatch):
    """POST /commit returns 404 when debug UI is disabled."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", False)

    response = client.post(
        "/commit",
        data={"document_id": "x", "version": 1},
        files={"file": ("doc.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 404


# ── Committed sections endpoint ─────────────────────────────────────────────


def test_get_committed_sections(monkeypatch):
    """GET /committed/{doc_id}/{version}/sections returns stored sections."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    # Commit a document first
    content = b"Part A\nPart B\n"
    client.post(
        "/commit",
        data={"document_id": "docS", "version": 1},
        files={"file": ("doc.txt", content, "text/plain")},
    )

    response = client.get("/committed/docS/1/sections")
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["sections"] == ["Part A", "Part B"]
    assert len(data["blake3_root"]) == 64
    assert data["poseidon_root"].isdigit()


def test_get_committed_sections_not_found(monkeypatch):
    """GET /committed/{doc_id}/{version}/sections returns 404 if not committed."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    response = client.get("/committed/ghost/99/sections")
    assert response.status_code == 404
    assert response.json()["ok"] is False


# ── Redaction endpoint ──────────────────────────────────────────────────────


def test_redact_generates_proof_bundle(monkeypatch):
    """POST /redact returns a well-formed proof bundle."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = b"Section A\nSection B\nSection C\n"
    client.post(
        "/commit",
        data={"document_id": "docR", "version": 1},
        files={"file": ("doc.txt", content, "text/plain")},
    )

    response = client.post(
        "/redact",
        json={"document_id": "docR", "version": 1, "revealed_indices": [0, 2]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    bundle = data["bundle"]
    assert bundle["revealed_indices"] == [0, 2]
    assert bundle["revealed_content"] == ["Section A", "Section C"]
    assert bundle["total_parts"] == 3
    assert "smt_proof" in bundle
    assert "zk_public_inputs" in bundle
    assert bundle["zk_public_inputs"]["revealed_count"] == 2


def test_redact_out_of_range_index(monkeypatch):
    """POST /redact returns 400 for an out-of-range section index."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    client.post(
        "/commit",
        data={"document_id": "docOOR", "version": 1},
        files={"file": ("doc.txt", b"Only one section\n", "text/plain")},
    )

    response = client.post(
        "/redact",
        json={"document_id": "docOOR", "version": 1, "revealed_indices": [5]},
    )
    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_redact_unknown_commit(monkeypatch):
    """POST /redact returns 404 when document has not been committed."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    response = client.post(
        "/redact",
        json={"document_id": "nobody", "version": 1, "revealed_indices": [0]},
    )
    assert response.status_code == 404


# ── Verify endpoint ─────────────────────────────────────────────────────────


def test_verify_valid_smt_anchor(monkeypatch):
    """POST /verify passes SMT anchor check for a freshly generated bundle."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = b"Alpha\nBeta\nGamma\n"
    client.post(
        "/commit",
        data={"document_id": "docV", "version": 1},
        files={"file": ("doc.txt", content, "text/plain")},
    )
    redact_resp = client.post(
        "/redact",
        json={"document_id": "docV", "version": 1, "revealed_indices": [1]},
    )
    bundle = redact_resp.json()["bundle"]

    verify_resp = client.post("/verify", json=bundle)
    assert verify_resp.status_code == 200
    vdata = verify_resp.json()
    assert vdata["ok"] is True
    assert vdata["smt_anchor_verified"] is True
    assert vdata["revealed_sections"] == [{"index": 1, "content": "Beta"}]
    assert vdata["total_parts"] == 3


def test_verify_invalid_bundle(monkeypatch):
    """POST /verify returns 400 for a malformed proof bundle."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    response = client.post("/verify", json={"broken": True})
    assert response.status_code == 400
    assert response.json()["ok"] is False


def test_verify_disabled_returns_404(monkeypatch):
    """POST /verify returns 404 when debug UI is disabled."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", False)

    response = client.post("/verify", json={})
    assert response.status_code == 404


# ── Civic tooling endpoints ───────────────────────────────────────────────────


def test_voting_record_uses_openstates_data(monkeypatch):
    """GET /civic/voting-record normalizes OpenStates people and bill vote payloads."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    def fake_openstates(path: str, params: dict[str, object]):
        if path == "/people":
            return {
                "results": [
                    {
                        "id": "ocd-person/123",
                        "name": "Jane Doe",
                        "party": "Independent",
                        "current_role": {"district": "7", "title": "Representative"},
                    }
                ]
            }
        if path == "/bills":
            assert params["include"] == ["votes"]
            return {
                "results": [
                    {
                        "identifier": "HB 101",
                        "title": "Transit Expansion Act",
                        "classification": ["bill"],
                        "votes": [
                            {
                                "motion_text": "Final passage",
                                "date": "2026-02-01",
                                "result": "passed",
                                "organization": {"name": "House"},
                                "votes": [
                                    {"person_id": "ocd-person/123", "option": "yes"},
                                    {"person_id": "ocd-person/999", "option": "no"},
                                ],
                            }
                        ],
                    }
                ]
            }
        raise AssertionError(f"Unexpected path: {path}")

    monkeypatch.setattr(ui_app, "_fetch_openstates_json", fake_openstates)

    response = client.get("/civic/voting-record?name=Jane%20Doe&jurisdiction=Texas")

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["representative"]["name"] == "Jane Doe"
    assert data["source"]["provider"] == "OpenStates"
    assert data["votes"] == [
        {
            "bill_identifier": "HB 101",
            "bill_title": "Transit Expansion Act",
            "classification": ["bill"],
            "motion": "Final passage",
            "date": "2026-02-01",
            "result": "passed",
            "option": "yes",
            "organization": "House",
        }
    ]


def test_simplify_bill_returns_summary_and_prompt_chain(monkeypatch):
    """POST /civic/simplify-bill returns a deterministic summary with visible prompts."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    response = client.post(
        "/civic/simplify-bill",
        json={
            "text": (
                "The department shall publish an annual housing report by January 15, 2027. "
                "The agency may not spend more than $250,000 without council approval."
            )
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "must publish an annual housing report" in data["plain_english_summary"].lower()
    assert data["amounts"] == ["$250,000"]
    assert "January 15, 2027" in data["dates"][0]
    assert [stage["stage"] for stage in data["prompt_chain"]] == [
        "extract_obligations",
        "translate_for_constituents",
        "flag_open_questions",
    ]


def test_geofence_preview_returns_overlap_counts_and_svg(monkeypatch):
    """POST /civic/geofence-preview computes overlap and returns an SVG map preview."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    response = client.post(
        "/civic/geofence-preview",
        json={
            "district_geojson": {
                "type": "Polygon",
                "coordinates": [
                    [[-97.8, 30.2], [-97.7, 30.2], [-97.7, 30.3], [-97.8, 30.3], [-97.8, 30.2]]
                ],
            },
            "constituents": [
                {"name": "Inside Resident", "lat": 30.25, "lon": -97.75},
                {"name": "Outside Resident", "lat": 30.35, "lon": -97.75},
            ],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["district_count"] == 1
    assert data["overlap_count"] == 1
    assert data["outside_count"] == 1
    assert "<svg" in data["svg"]
    assert data["constituents"] == [
        {"name": "Inside Resident", "lat": 30.25, "lon": -97.75, "inside": True},
        {"name": "Outside Resident", "lat": 30.35, "lon": -97.75, "inside": False},
    ]


# ── New panel HTML presence ──────────────────────────────────────────────────


def test_index_has_commit_panel(monkeypatch):
    """Root page should include the Commit Document panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "Commit Document" in response.text
    assert "commit-form" in response.text


def test_index_has_verify_panel(monkeypatch):
    """Root page should include the Verify Proof panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "Verify Proof" in response.text
    assert "verify-form" in response.text


def test_index_has_redaction_panel(monkeypatch):
    """Root page should include the Redaction Interface panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "Redaction Interface" in response.text
    assert "redact-sections" in response.text


def test_index_has_civic_tooling_panels(monkeypatch):
    """Root page should include the new civic tooling prototype panels."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "Representative Voting Record Tracker" in response.text
    assert "Bill Text Simplifier Pipeline" in response.text
    assert "Geofence Boundary Visualizer" in response.text
    assert "votes-form" in response.text
    assert "simplify-form" in response.text
    assert "geofence-form" in response.text
