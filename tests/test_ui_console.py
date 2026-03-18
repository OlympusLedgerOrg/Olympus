"""Tests for developer debug console UI."""

import json
from urllib.error import HTTPError

import httpx
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
        if path == "/shards/s1/history?n=5":
            return {"headers": [{"seq": 2, "root_hash": "abc"}]}
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
        if path == "/shards/s1/history?n=5":
            return {"headers": [{"seq": 1, "root_hash": "abc"}]}
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
    assert client.get("/state-diff?shard_id=s&from_seq=1&to_seq=2").status_code == 404


def test_oracle_refine_rate_limited_per_ip(monkeypatch):
    """Oracle refine endpoint enforces per-IP sliding-window limits."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_oracle_rate_limit", {})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ORACLE_RATE_LIMIT_REQUESTS", "1")
    monkeypatch.setenv("ORACLE_RATE_LIMIT_WINDOW_SECONDS", "60")
    calls = {"count": 0}

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url: str, *, headers=None, content=None):  # noqa: ARG002
            calls["count"] += 1
            return httpx.Response(
                status_code=200,
                json={"content": [{"type": "text", "text": "Refined body"}]},
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda *args, **kwargs: FakeAsyncClient())

    payload = {"subject": "Budget", "description": "Need records", "agency": "City"}
    first = client.post("/oracle/refine", json=payload)
    second = client.post("/oracle/refine", json=payload)

    assert first.status_code == 200
    assert first.json()["refined"] == "Refined body"
    assert second.status_code == 429
    assert second.json()["detail"] == "Oracle rate limit exceeded. Try again later."
    assert calls["count"] == 1


def test_oracle_refine_maps_http_status_errors(monkeypatch):
    """Oracle refine endpoint maps Anthropic HTTP errors to 502 with body text."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_oracle_rate_limit", {})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ORACLE_RATE_LIMIT_REQUESTS", "10")
    monkeypatch.setenv("ORACLE_RATE_LIMIT_WINDOW_SECONDS", "60")

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url: str, *, headers=None, content=None):  # noqa: ARG002
            return httpx.Response(
                status_code=401,
                text="unauthorized",
                request=httpx.Request("POST", url),
            )

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda *args, **kwargs: FakeAsyncClient())

    response = client.post("/oracle/refine", json={"subject": "A", "description": "B"})

    assert response.status_code == 502
    assert response.json()["error"] == "Claude API error: unauthorized"


def test_oracle_appeal_maps_request_errors(monkeypatch):
    """Oracle appeal endpoint maps Anthropic request failures to 502."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_oracle_rate_limit", {})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("ORACLE_RATE_LIMIT_REQUESTS", "10")
    monkeypatch.setenv("ORACLE_RATE_LIMIT_WINDOW_SECONDS", "60")

    class FakeAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url: str, *, headers=None, content=None):  # noqa: ARG002
            raise httpx.RequestError("connection failed", request=httpx.Request("POST", url))

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda *args, **kwargs: FakeAsyncClient())

    response = client.post("/oracle/appeal", json={"subject": "A", "description": "B"})

    assert response.status_code == 502
    assert response.json()["error"] == "Claude API request failed: connection failed"


def test_console_shows_federation_dashboard(monkeypatch):
    """Root page should render federation agreement details when nodes are configured."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(
        ui_app,
        "FEDERATION_NODES",
        {
            "node1": "http://node1.example",
            "node2": "http://node2.example",
            "node3": "http://node3.example",
        },
    )
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    def fake_fetch(base_url: str, path: str):
        if path == "/health":
            return {"status": "healthy"}
        if path == "/shards":
            return [{"shard_id": "s1", "latest_seq": 2, "latest_root": "abc"}]
        if path == "/shards/s1/header/latest":
            return {"header_hash": "0" * 64, "signature": "0" * 128, "pubkey": "0" * 64}
        if path == "/ledger/s1/tail?n=10":
            return {"entries": [{"prev_entry_hash": "", "entry_hash": "e1"}]}
        if path == "/shards/s1/history?n=5":
            return {"headers": [{"seq": 2, "root_hash": "abc"}]}
        raise AssertionError(f"Unexpected path for {base_url}: {path}")

    monkeypatch.setattr(ui_app, "_fetch_json_from_base", fake_fetch)
    monkeypatch.setattr(ui_app, "_verify_signature", lambda header: True)

    response = client.get("/")

    assert response.status_code == 200
    assert "Federation Health Dashboard" in response.text
    assert "in sync" in response.text
    assert "seq 2" in response.text


def test_state_diff_proxy(monkeypatch):
    """The state diff proxy should return API diff payloads."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(
        ui_app,
        "_fetch_json",
        lambda path: {
            "from_root_hash": "aa" * 32,
            "to_root_hash": "bb" * 32,
            "summary": {"added": 1, "changed": 0, "removed": 0},
        },
    )

    response = client.get("/state-diff?shard_id=s1&from_seq=1&to_seq=2")

    assert response.status_code == 200
    assert response.json()["ok"] is True
    assert response.json()["diff"]["summary"]["added"] == 1


def test_public_verification_portal_available_without_debug(monkeypatch):
    """Public verification portal stays available even when debug tools are disabled."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", False)

    response = client.get("/verification-portal")

    assert response.status_code == 200
    assert "Public Verification Portal" in response.text
    assert "hash-verify-form" in response.text


def test_public_hash_lookup_proxies_api(monkeypatch):
    """Public hash verification proxy returns proof data from the API."""
    monkeypatch.setattr(
        ui_app,
        "_fetch_json",
        lambda path: {
            "proof_id": "proof-123",
            "record_id": "doc-123",
            "shard_id": "shard-1",
            "content_hash": "ab" * 32,
            "merkle_root": "cd" * 32,
            "merkle_proof": {
                "leaf_hash": "ef" * 32,
                "leaf_index": 0,
                "siblings": [],
                "root_hash": "cd" * 32,
            },
            "ledger_entry_hash": "12" * 32,
            "timestamp": "2026-01-01T00:00:00Z",
            "canonicalization": {"method": "demo"},
            "merkle_proof_valid": True,
        },
    )

    response = client.get(f"/verification-portal/hash/{'ab' * 32}")

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["verification"]["proof_id"] == "proof-123"
    assert data["verification"]["merkle_proof_valid"] is True


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


def test_theme_switcher_present(monkeypatch):
    """Root page should include the theme switcher UI component."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "theme-switcher" in response.text
    assert 'name="theme-mode"' in response.text
    assert 'value="fight-club"' in response.text
    assert 'value="professional"' in response.text
    assert 'value="minimal"' in response.text
    assert 'value="accessibility"' in response.text


def test_theme_fight_club_css_present(monkeypatch):
    """Root page should include Fight Club / Matrix theme CSS variables."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert '[data-theme="fight-club"]' in response.text
    assert "#00ff41" in response.text  # matrix green


def test_theme_accessibility_css_present(monkeypatch):
    """Root page should include Accessibility / High Contrast theme CSS."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert '[data-theme="accessibility"]' in response.text
    assert "#ffff00" in response.text  # high contrast yellow accent


def test_theme_minimal_css_present(monkeypatch):
    """Root page should include Minimal / Zen theme CSS."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert '[data-theme="minimal"]' in response.text


def test_glyph_rain_canvas_present(monkeypatch):
    """Root page should include the glyph rain canvas element."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="glyph-rain"' in response.text
    assert "startGlyphRain" in response.text
    assert "stopGlyphRain" in response.text


def test_color_scheme_options_present(monkeypatch):
    """Root page should include color scheme radio options."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert 'name="color-scheme"' in response.text
    assert 'value="amber"' in response.text
    assert 'value="blue"' in response.text
    assert '[data-color-scheme="amber"]' in response.text
    assert '[data-color-scheme="blue"]' in response.text


def test_layout_preferences_present(monkeypatch):
    """Root page should include layout preference checkboxes."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert 'id="pref-glyph-rain"' in response.text
    assert 'id="pref-compact"' in response.text


def test_theme_persistence_js_present(monkeypatch):
    """Root page should include localStorage-based theme persistence code."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "olympus-theme" in response.text
    assert "saveThemePrefs" in response.text
    assert "loadThemePrefs" in response.text
    assert "applyTheme" in response.text


def test_data_theme_attribute_on_html(monkeypatch):
    """HTML element should have a data-theme attribute for CSS targeting."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "data-theme=" in response.text


def test_verification_portal_has_theme_switcher(monkeypatch):
    """Verification portal page should also include theme switcher."""
    response = client.get("/verification-portal")

    assert response.status_code == 200
    assert "theme-switcher" in response.text


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
    assert data["receipt"]["receipt_type"] == "document_commitment"
    assert len(data["receipt"]["receipt_hash"]) == 64


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
    assert data["receipt"]["receipt_type"] == "document_commitment"


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


# ── Receipt + embargo management ──────────────────────────────────────────────


def test_commit_returns_receipt_and_embargo_metadata(monkeypatch):
    """POST /commit returns a receipt and configured embargo metadata."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    response = client.post(
        "/commit",
        data={
            "document_id": "embargo-doc",
            "version": 3,
            "release_at": "2026-03-10T15:00:00Z",
            "recipient_keys": "alice-key\nbob-key",
        },
        files={"file": ("doc.txt", b"One\nTwo\n", "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["receipt"]["payload"]["release_at"] == "2026-03-10T15:00:00Z"
    assert data["embargo"]["recipient_keys"] == ["alice-key", "bob-key"]
    assert data["embargo"]["active_recipient_keys"] == ["alice-key", "bob-key"]
    assert data["embargo"]["revoked_recipient_keys"] == []


def test_embargo_update_and_revoke(monkeypatch):
    """Embargo endpoints update recipients and support revocation."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    client.post(
        "/commit",
        data={"document_id": "docE", "version": 1},
        files={"file": ("doc.txt", b"First\nSecond\n", "text/plain")},
    )

    update_response = client.post(
        "/embargo/update",
        json={
            "document_id": "docE",
            "version": 1,
            "release_at": "2026-03-09T12:00:00Z",
            "recipient_keys": "key-a,key-b",
        },
    )
    assert update_response.status_code == 200
    update_data = update_response.json()
    assert update_data["embargo"]["release_at"] == "2026-03-09T12:00:00Z"
    assert update_data["embargo"]["active_recipient_keys"] == ["key-a", "key-b"]
    assert update_data["receipt"]["receipt_type"] == "embargo_update"
    assert len(update_data["receipt"]["receipt_hash"]) == 64

    revoke_response = client.post(
        "/embargo/revoke",
        json={"document_id": "docE", "version": 1, "recipient_key": "key-a"},
    )
    assert revoke_response.status_code == 200
    revoke_data = revoke_response.json()
    assert revoke_data["embargo"]["active_recipient_keys"] == ["key-b"]
    assert revoke_data["embargo"]["revoked_recipient_keys"] == ["key-a"]

    get_response = client.get("/embargo/docE/1")
    assert get_response.status_code == 200
    get_data = get_response.json()
    assert get_data["embargo"]["active_recipient_keys"] == ["key-b"]
    assert get_data["embargo"]["revoked_recipient_keys"] == ["key-a"]


# ── FOIA tracker ──────────────────────────────────────────────────────────────


def test_foia_request_response_and_delay_proof(monkeypatch):
    """FOIA tracker commits request metadata, logs responses, and returns delay proofs."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()
    ui_app._foia_store.clear()

    request_response = client.post(
        "/foia/request",
        json={
            "request_id": "foia-001",
            "agency": "Records Office",
            "requester": "Jane Citizen",
            "description": "Budget spreadsheet for 2025",
            "submitted_at": "2026-03-01T00:00:00Z",
            "response_due_at": "2026-03-05T00:00:00Z",
        },
    )
    assert request_response.status_code == 200
    request_data = request_response.json()
    assert request_data["request"]["request_id"] == "foia-001"
    assert request_data["request"]["request_receipt"]["receipt_type"] == "foia_request_submission"
    assert request_data["delay_proof"]["receipt_type"] == "foia_delay_snapshot"
    assert request_data["delay_proof"]["payload"]["proof_mode"] == "snapshot"
    assert request_data["delay_proof"]["payload"]["pending"] is True

    response_response = client.post(
        "/foia/response",
        json={
            "request_id": "foia-001",
            "response_received_at": "2026-03-07T00:00:00Z",
            "response_summary": "Released with redactions",
        },
    )
    assert response_response.status_code == 200
    response_data = response_response.json()
    assert response_data["request"]["response_received_at"] == "2026-03-07T00:00:00Z"
    assert response_data["request"]["response_receipt"]["receipt_type"] == "foia_response_log"
    assert response_data["delay_proof"]["receipt_type"] == "foia_delay_proof"
    assert response_data["delay_proof"]["payload"]["proof_mode"] == "response-anchored"
    assert response_data["delay_proof"]["payload"]["pending"] is False
    assert response_data["delay_proof"]["payload"]["delayed"] is True
    assert response_data["delay_proof"]["payload"]["delay_seconds"] == 172800

    proof_response = client.get("/foia/foia-001/delay-proof")
    assert proof_response.status_code == 200
    proof_data = proof_response.json()
    assert (
        proof_data["delay_proof"]["payload"]["request_receipt_hash"]
        == (request_data["request"]["request_receipt"]["receipt_hash"])
    )
    assert (
        proof_data["delay_proof"]["payload"]["response_receipt_hash"]
        == (response_data["request"]["response_receipt"]["receipt_hash"])
    )


def test_foia_response_before_due_date_is_not_delayed(monkeypatch):
    """FOIA delay proof should show no delay when the response arrives before the due date."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()
    ui_app._foia_store.clear()

    client.post(
        "/foia/request",
        json={
            "request_id": "foia-002",
            "agency": "City Clerk",
            "requester": "Alex Example",
            "description": "Meeting minutes",
            "submitted_at": "2026-03-01T00:00:00Z",
            "response_due_at": "2026-03-05T00:00:00Z",
        },
    )

    response = client.post(
        "/foia/response",
        json={
            "request_id": "foia-002",
            "response_received_at": "2026-03-04T12:00:00Z",
            "response_summary": "Released in full",
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["delay_proof"]["payload"]["delayed"] is False
    assert data["delay_proof"]["payload"]["delay_seconds"] == 0


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


def test_index_has_foia_and_embargo_panels(monkeypatch):
    """Root page should include FOIA tracker and embargo management panels."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "FOIA Request Tracker" in response.text
    assert "foia-request-form" in response.text
    assert "Embargo Management" in response.text
    assert "embargo-doc-id" in response.text


# ── /inspect-proof-bundle validation ─────────────────────────────────────────


def test_inspect_proof_bundle_rejects_non_object(monkeypatch):
    """Endpoint should reject non-object input with schema error."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    response = client.post("/inspect-proof-bundle", json="not an object")
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "Proof bundle must be a JSON object" in data["error"]


def test_inspect_proof_bundle_rejects_invalid_smt_proof_type(monkeypatch):
    """Endpoint should reject smt_proof that is not an object."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {"smt_proof": "not an object"}
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "smt_proof must be an object" in data["error"]


def test_inspect_proof_bundle_rejects_missing_smt_fields(monkeypatch):
    """Endpoint should reject smt_proof missing required fields."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {"smt_proof": {"root_hash": "abc123"}}  # missing key, value_hash, siblings
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "missing required field" in data["error"]


def test_inspect_proof_bundle_rejects_non_hex_root_hash(monkeypatch):
    """Endpoint should reject smt_proof.root_hash that is not hex."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "smt_proof": {
            "root_hash": "not-hex!",
            "key": "0" * 64,
            "value_hash": "0" * 64,
            "siblings": [],
        }
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "must be a valid hex string" in data["error"]


def test_inspect_proof_bundle_rejects_invalid_zk_public_inputs(monkeypatch):
    """Endpoint should reject zk_public_inputs that is not an object."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {"zk_public_inputs": "not an object"}
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "zk_public_inputs must be an object" in data["error"]


def test_inspect_proof_bundle_rejects_missing_zk_fields(monkeypatch):
    """Endpoint should reject zk_public_inputs missing required fields."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {"zk_public_inputs": {"original_root": "123"}}  # missing redacted_commitment, revealed_count
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "missing required field" in data["error"]


def test_inspect_proof_bundle_rejects_non_numeric_field_elements(monkeypatch):
    """Endpoint should reject field elements that are not numeric strings."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "zk_public_inputs": {
            "original_root": "not-a-number",
            "redacted_commitment": "456",
            "revealed_count": 3,
        }
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "must be a decimal integer string" in data["error"]


def test_inspect_proof_bundle_rejects_negative_field_elements(monkeypatch):
    """Endpoint should reject negative field elements."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "zk_public_inputs": {
            "original_root": "-123",
            "redacted_commitment": "456",
            "revealed_count": 3,
        }
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "must be non-negative" in data["error"]


def test_inspect_proof_bundle_rejects_invalid_revealed_count(monkeypatch):
    """Endpoint should reject revealed_count that is not an integer."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "zk_public_inputs": {
            "original_root": "123",
            "redacted_commitment": "456",
            "revealed_count": "not-an-int",
        }
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "must be an integer" in data["error"]


def test_inspect_proof_bundle_rejects_invalid_revealed_indices(monkeypatch):
    """Endpoint should reject revealed_indices with non-integer elements."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {"revealed_indices": [0, "not-an-int", 2]}
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "must be an integer" in data["error"]


def test_inspect_proof_bundle_accepts_valid_bundle(monkeypatch):
    """Endpoint should accept a well-formed proof bundle."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "smt_proof": {
            "root_hash": "0" * 64,
            "key": "0" * 64,
            "value_hash": "0" * 64,
            "siblings": [],
        },
        "zk_public_inputs": {
            "original_root": "123",
            "redacted_commitment": "456",
            "revealed_count": 3,
        },
        "zk_proof": {},
        "revealed_indices": [0, 1, 2],
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert "checks" in data
    assert "fields" in data


def test_inspect_proof_bundle_accepts_minimal_bundle(monkeypatch):
    """Endpoint should accept an empty bundle (all fields optional)."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {}
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True


def test_inspect_proof_bundle_accepts_forward_compatible_fields(monkeypatch):
    """Endpoint should accept bundles with additional unknown fields for forward compatibility.

    This ensures newer clients can send additional metadata (e.g., bundle_version,
    zk_proof_version, timestamps) without breaking existing integrations.
    """
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "smt_proof": {
            "root_hash": "0" * 64,
            "key": "0" * 64,
            "value_hash": "0" * 64,
            "siblings": [],
        },
        "bundle_version": "2.0.0",  # future field
        "metadata": {"client": "olympus-cli-v2"},  # future field
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True


def test_inspect_proof_bundle_rejects_malformed_hex_string(monkeypatch):
    """Endpoint should reject root_hash with non-hex characters like 'not-hex-at-all'."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "smt_proof": {
            "root_hash": "not-hex-at-all",
            "key": "0" * 64,
            "value_hash": "0" * 64,
            "siblings": [],
        }
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "must be a valid hex string" in data["error"]


def test_inspect_proof_bundle_rejects_revealed_count_mismatch(monkeypatch):
    """Endpoint should reject bundles where revealed_count != len(revealed_indices)."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "zk_public_inputs": {
            "original_root": "123",
            "redacted_commitment": "456",
            "revealed_count": 5,  # claims 5 revealed parts
        },
        "revealed_indices": [0, 1, 2],  # but only 3 indices provided
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 400
    data = response.json()
    assert data["ok"] is False
    assert "Semantic mismatch" in data["error"]
    assert "revealed_count (5)" in data["error"]
    assert "len(revealed_indices) (3)" in data["error"]


def test_inspect_proof_bundle_accepts_matching_revealed_count(monkeypatch):
    """Endpoint should accept bundles where revealed_count matches len(revealed_indices)."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    bundle = {
        "zk_public_inputs": {
            "original_root": "123",
            "redacted_commitment": "456",
            "revealed_count": 3,
        },
        "revealed_indices": [0, 1, 2],
    }
    response = client.post("/inspect-proof-bundle", json=bundle)
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
