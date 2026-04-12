"""Tests for developer debug console UI."""

import json
import socket
import unittest.mock

import httpx
import pytest
from fastapi.testclient import TestClient

import ui.app as ui_app


client = TestClient(ui_app.app)


def _make_http_status_error(status_code: int) -> httpx.HTTPStatusError:
    """Create an httpx.HTTPStatusError for test mocking."""
    response = httpx.Response(status_code)
    request = httpx.Request("GET", "http://test")
    return httpx.HTTPStatusError(
        f"HTTP {status_code}",
        request=request,
        response=response,
    )


def test_console_shows_db_unavailable_banner(monkeypatch):
    """Root page should show DB unavailable banner on 503 from API."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    def raise_503(path: str):
        raise _make_http_status_error(503)

    monkeypatch.setattr(ui_app, "_fetch_json", raise_503)

    response = client.get("/")

    assert response.status_code == 200
    assert "Database unavailable (503)." in response.text


def test_console_shows_api_unavailable_banner_on_timeout(monkeypatch):
    """Root page should show API unavailable banner on timeout."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    def raise_timeout(path: str):  # noqa: ARG001
        raise TimeoutError("timed out")

    monkeypatch.setattr(ui_app, "_fetch_json", raise_timeout)

    response = client.get("/")

    assert response.status_code == 200
    assert "API unavailable (connection failed)." in response.text


def test_debug_ui_csp_disallows_unsafe_inline_styles():
    response = client.get("/manifest.json")
    csp = response.headers.get("content-security-policy", "")
    assert "style-src 'self'" in csp
    assert "'unsafe-inline'" not in csp


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


def test_debug_ui_enabled_by_default(monkeypatch):
    """Debug console routes are accessible by default without any environment variable."""
    assert ui_app.DEBUG_UI_ENABLED is True


# ── Direct unit tests for shared helpers ─────────────────────────────────────


def test_verify_signature_accepts_valid_ed25519():
    """_verify_signature should return True for a correctly signed header."""
    import nacl.signing

    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    header_hash = "ab" * 32
    signature = signing_key.sign(bytes.fromhex(header_hash)).signature

    header = {
        "pubkey": verify_key.encode().hex(),
        "header_hash": header_hash,
        "signature": signature.hex(),
    }
    assert ui_app._verify_signature(header) is True


def test_verify_signature_rejects_bad_signature():
    """_verify_signature should return False when signature does not match."""
    import nacl.signing

    signing_key = nacl.signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    header_hash = "ab" * 32
    # Sign the hash then corrupt one byte of the signature
    signature = bytearray(signing_key.sign(bytes.fromhex(header_hash)).signature)
    signature[0] ^= 0xFF

    header = {
        "pubkey": verify_key.encode().hex(),
        "header_hash": header_hash,
        "signature": bytes(signature).hex(),
    }
    assert ui_app._verify_signature(header) is False


def test_verify_signature_rejects_wrong_key():
    """_verify_signature should return False when pubkey doesn't match signer."""
    import nacl.signing

    signer = nacl.signing.SigningKey.generate()
    wrong_key = nacl.signing.SigningKey.generate().verify_key
    header_hash = "cd" * 32
    signature = signer.sign(bytes.fromhex(header_hash)).signature

    header = {
        "pubkey": wrong_key.encode().hex(),
        "header_hash": header_hash,
        "signature": signature.hex(),
    }
    assert ui_app._verify_signature(header) is False


def test_verify_signature_returns_false_on_missing_key():
    """_verify_signature should return False when header lacks required keys."""
    assert ui_app._verify_signature({}) is False
    assert ui_app._verify_signature({"pubkey": "aa" * 32}) is False


def test_verify_signature_returns_false_on_bad_hex():
    """_verify_signature should return False for non-hex values."""
    header = {
        "pubkey": "not-valid-hex",
        "header_hash": "ab" * 32,
        "signature": "cd" * 64,
    }
    assert ui_app._verify_signature(header) is False


def test_is_chain_broken_empty_entries():
    """_is_chain_broken should return False for an empty list."""
    assert ui_app._is_chain_broken([]) is False


def test_is_chain_broken_single_entry():
    """_is_chain_broken should return False for a single entry (no pairs to check)."""
    assert ui_app._is_chain_broken([{"prev_entry_hash": "a", "entry_hash": "b"}]) is False


def test_is_chain_broken_valid_chain():
    """_is_chain_broken should return False when chain linkage is correct."""
    entries = [
        {"prev_entry_hash": "e1", "entry_hash": "e2"},
        {"prev_entry_hash": "e0", "entry_hash": "e1"},
    ]
    assert ui_app._is_chain_broken(entries) is False


def test_is_chain_broken_detects_break():
    """_is_chain_broken should return True when a link is broken."""
    entries = [
        {"prev_entry_hash": "wrong", "entry_hash": "e2"},
        {"prev_entry_hash": "e0", "entry_hash": "e1"},
    ]
    assert ui_app._is_chain_broken(entries) is True


def test_is_chain_broken_multi_entry_valid():
    """_is_chain_broken should validate all pairs in a longer chain."""
    entries = [
        {"prev_entry_hash": "e2", "entry_hash": "e3"},
        {"prev_entry_hash": "e1", "entry_hash": "e2"},
        {"prev_entry_hash": "e0", "entry_hash": "e1"},
    ]
    assert ui_app._is_chain_broken(entries) is False


def test_is_chain_broken_break_in_middle():
    """_is_chain_broken should detect a break in the middle of a chain."""
    entries = [
        {"prev_entry_hash": "e2", "entry_hash": "e3"},
        {"prev_entry_hash": "TAMPERED", "entry_hash": "e2"},
        {"prev_entry_hash": "e0", "entry_hash": "e1"},
    ]
    # entries[1]["prev_entry_hash"] ("TAMPERED") != entries[2]["entry_hash"] ("e1")
    assert ui_app._is_chain_broken(entries) is True


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
    assert "Federation" in response.text or "federation" in response.text


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
    """Root page should expose CSS custom properties for the terminal theme."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "--bg:" in response.text
    assert "--accent:" in response.text
    assert "--surface-muted:" in response.text
    assert "background: var(--bg);" in response.text
    assert "color: var(--text);" in response.text


def test_color_scheme_cycler_present(monkeypatch):
    """Root page should include color scheme cycler buttons (GREEN/AMBER/BLUE/WHITE)."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "GREEN" in response.text
    assert "AMBER" in response.text
    assert "BLUE" in response.text
    assert "WHITE" in response.text


def test_validate_federation_url_blocks_ipv4_mapped_ipv6():
    with unittest.mock.patch(
        "ui.app.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::ffff:127.0.0.1", 443, 0, 0))
        ],
    ):
        with pytest.raises(ValueError, match="blocked address range"):
            ui_app.validate_federation_url("https://example.invalid")


def test_terminal_theme_css_present(monkeypatch):
    """Root page should include terminal theme CSS with phosphor green."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert 'data-theme="terminal"' in response.text
    assert "#00ff41" in response.text  # phosphor green


def test_crt_scanlines_present(monkeypatch):
    """Root page should include CRT scanlines overlay."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "crt-overlay" in response.text or "scanline" in response.text.lower()


def test_share_tech_mono_font(monkeypatch):
    """Root page should load Share Tech Mono font."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "Share Tech Mono" in response.text


def test_matrix_rain_canvas_present(monkeypatch):
    """Root page should include the matrix rain canvas element."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "matrix-canvas" in response.text


def test_boot_sequence_present(monkeypatch):
    """Root page should include boot sequence animation."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "boot-screen" in response.text or "boot" in response.text.lower()
    assert "BLAKE3" in response.text


def test_tab_navigation_present(monkeypatch):
    """Root page should include terminal tab navigation."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "STATUS" in response.text
    assert "COMMIT" in response.text
    assert "REDACT" in response.text
    assert "VERIFY" in response.text
    assert "INSPECT" in response.text
    assert "DEBUG" in response.text


def test_theme_persistence_js_present(monkeypatch):
    """Root page should include localStorage-based theme persistence code."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert "localStorage" in response.text


def test_data_theme_attribute_on_html(monkeypatch):
    """HTML element should have a data-theme attribute for CSS targeting."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")

    assert response.status_code == 200
    assert 'data-theme="terminal"' in response.text


def test_verification_portal_renders(monkeypatch):
    """Verification portal page should render successfully."""
    response = client.get("/verification-portal")

    assert response.status_code == 200
    assert "data-theme" in response.text


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


def test_commit_binary_file(monkeypatch):
    """POST /commit with a binary (non-UTF-8) file should succeed with one section."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    binary_content = bytes(range(256))  # contains non-UTF-8 bytes
    response = client.post(
        "/commit",
        data={"document_id": "binfile", "version": 1},
        files={"file": ("data.bin", binary_content, "application/octet-stream")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["sections_count"] == 1
    assert len(data["blake3_root"]) == 64
    assert data["poseidon_root"].isdigit()


def test_commit_txt_file_provenance_pinned(monkeypatch):
    """Plain-text commits must include plaintext_lines_v1 provenance with version pins."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = b"Line one\nLine two\nLine three\n"
    response = client.post(
        "/commit",
        data={"document_id": "prov-txt", "version": 1},
        files={"file": ("doc.txt", content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    prov = data["canon_provenance"]
    assert prov["format"] == "text/plain"
    assert prov["normalization_mode"] == "plaintext_lines_v1"
    assert prov["fallback_reason"] is None
    assert "canonicalizer_versions" in prov


def test_commit_json_file_provenance_pinned(monkeypatch):
    """JSON-array commits must include json_array_v1 provenance with version pins."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = json.dumps(["Alpha", "Beta"]).encode()
    response = client.post(
        "/commit",
        data={"document_id": "prov-json", "version": 1},
        files={"file": ("doc.json", content, "application/json")},
    )

    assert response.status_code == 200
    data = response.json()
    prov = data["canon_provenance"]
    assert prov["format"] == "application/json"
    assert prov["normalization_mode"] == "json_array_v1"
    assert "canonicalizer_versions" in prov


def test_commit_binary_file_provenance_pinned(monkeypatch):
    """Generic binary commits must include blake3_raw provenance with version pins."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    binary_content = bytes(range(256))
    response = client.post(
        "/commit",
        data={"document_id": "prov-bin", "version": 1},
        files={"file": ("data.bin", binary_content, "application/octet-stream")},
    )

    assert response.status_code == 200
    data = response.json()
    prov = data["canon_provenance"]
    assert prov["normalization_mode"] == "blake3_raw"
    assert "canonicalizer_versions" in prov


def test_commit_provenance_stored_in_receipt(monkeypatch):
    """Provenance must be embedded in the receipt metadata so it is part of the hash."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    content = b"Section one\nSection two\n"
    response = client.post(
        "/commit",
        data={"document_id": "prov-receipt", "version": 1},
        files={"file": ("doc.txt", content, "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    # The receipt payload metadata must carry the same provenance object
    receipt_prov = data["receipt"]["payload"]["metadata"]["canon_provenance"]
    assert receipt_prov == data["canon_provenance"]


def test_commit_always_accessible(monkeypatch):
    """POST /commit is always accessible regardless of DEBUG_UI_ENABLED."""
    ui_app._commit_store.clear()

    response = client.post(
        "/commit",
        data={"document_id": "x", "version": 1},
        files={"file": ("doc.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 200


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


def test_verify_always_accessible():
    """POST /verify is always accessible regardless of DEBUG_UI_ENABLED."""
    response = client.post("/verify", json={})
    assert response.status_code in (200, 400, 422)


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


def test_commit_persists_to_ledger_api(monkeypatch):
    """POST /commit POSTs blake3_root to API /doc/commit and returns ledger_commit_id."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {"commit_id": "ledger-id-abc123"}
    mock_response.raise_for_status = unittest.mock.MagicMock()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(return_value=mock_response)

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/commit",
        data={"document_id": "docL", "version": 1},
        files={"file": ("doc.txt", b"Section one\nSection two\n", "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["ledger_commit_id"] == "ledger-id-abc123"
    mock_client.post.assert_awaited_once_with(
        f"{ui_app.API_BASE}/doc/commit",
        json={"doc_hash": data["blake3_root"]},
    )


def test_commit_forwards_api_auth_headers_to_ledger_api(monkeypatch):
    """POST /commit forwards API auth headers to the backend commit endpoint."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {"commit_id": "ledger-id-forwarded"}
    mock_response.raise_for_status = unittest.mock.MagicMock()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(return_value=mock_response)

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/commit",
        headers={"X-API-Key": "ui-test-api-key", "Authorization": "Bearer ledger-token"},
        data={"document_id": "docAuth", "version": 1},
        files={"file": ("doc.txt", b"Section one\nSection two\n", "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    mock_client.post.assert_awaited_once_with(
        f"{ui_app.API_BASE}/doc/commit",
        json={"doc_hash": data["blake3_root"]},
        headers={"x-api-key": "ui-test-api-key", "authorization": "Bearer ledger-token"},
    )


def test_commit_does_not_forward_basic_auth_to_ledger_api(monkeypatch):
    """POST /commit must not forward UI basic-auth credentials to the API."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {"commit_id": "ledger-id-basic"}
    mock_response.raise_for_status = unittest.mock.MagicMock()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(return_value=mock_response)

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/commit",
        headers={"Authorization": "Basic dWk6cGFzcw=="},
        data={"document_id": "docBasic", "version": 1},
        files={"file": ("doc.txt", b"Section one\nSection two\n", "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    mock_client.post.assert_awaited_once_with(
        f"{ui_app.API_BASE}/doc/commit",
        json={"doc_hash": data["blake3_root"]},
    )


def test_commit_ledger_api_unavailable_returns_null_commit_id(monkeypatch):
    """POST /commit returns ledger_commit_id=null gracefully when API is unreachable."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    ui_app._commit_store.clear()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(
        side_effect=ui_app.httpx.ConnectError("connection refused")
    )

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/commit",
        data={"document_id": "docM", "version": 1},
        files={"file": ("doc.txt", b"Alpha\nBeta\n", "text/plain")},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is True
    assert data["ledger_commit_id"] is None


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


# ── Panel HTML presence ──────────────────────────────────────────────────


def test_index_has_commit_panel(monkeypatch):
    """Root page should include the Commit Document panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "commit" in response.text.lower()
    assert "commit-doc-id" in response.text


def test_index_has_verify_panel(monkeypatch):
    """Root page should include the Verify Proof panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "verify" in response.text.lower()
    assert "verify-bundle" in response.text


def test_index_has_redaction_panel(monkeypatch):
    """Root page should include the Redaction Interface panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "redact" in response.text.lower()
    assert "redact-doc-id" in response.text


def test_index_has_embargo_panel(monkeypatch):
    """Root page should include embargo management panel."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)
    monkeypatch.setattr(ui_app, "_fetch_json", lambda path: [])

    response = client.get("/")
    assert response.status_code == 200
    assert "embargo" in response.text.lower()
    assert "embargo-doc-id" in response.text


def test_foia_routes_removed():
    """FOIA routes should no longer exist."""
    response = client.post("/foia/request", json={"request_id": "test"})
    assert response.status_code in (404, 405)

    response = client.post("/oracle/refine", json={"subject": "test"})
    assert response.status_code in (404, 405)

    response = client.get("/public-records/requests")
    assert response.status_code in (404, 405)


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

    bundle = {
        "zk_public_inputs": {"original_root": "123"}
    }  # missing redacted_commitment, revealed_count
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


# ── Ledger Verification Proxy ────────────────────────────────────────────


def test_proxy_verify_simple_forwards_doc_hash(monkeypatch):
    """Proxy should forward doc_hash using httpx native data= parameter."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {"verified": False, "confidence": "none"}
    mock_response.raise_for_status = unittest.mock.MagicMock()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(return_value=mock_response)

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/ledger/verify/simple",
        data={"doc_hash": "ab" * 32},
    )

    assert response.status_code == 200
    call_kwargs = mock_client.post.call_args
    assert call_kwargs.kwargs["data"] == {"doc_hash": "ab" * 32}
    assert call_kwargs.kwargs["files"] is None


def test_proxy_verify_simple_forwards_file_upload(monkeypatch):
    """Proxy should forward file uploads using httpx native files= parameter."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {"verified": True, "confidence": "certain"}
    mock_response.raise_for_status = unittest.mock.MagicMock()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(return_value=mock_response)

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/ledger/verify/simple",
        files={"file": ("test.txt", b"hello", "text/plain")},
    )

    assert response.status_code == 200
    call_kwargs = mock_client.post.call_args
    sent_files = call_kwargs.kwargs["files"]
    assert "file" in sent_files
    filename, content, ctype = sent_files["file"]
    assert filename == "test.txt"
    assert content == b"hello"
    assert ctype == "text/plain"


def test_proxy_verify_simple_handles_api_error(monkeypatch):
    """Proxy should relay HTTP error status and body from the API."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    error_resp = unittest.mock.MagicMock()
    error_resp.status_code = 400
    error_resp.json.return_value = {"detail": {"code": "MISSING_INPUT"}}

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(
        side_effect=ui_app.httpx.HTTPStatusError(
            "400", request=unittest.mock.MagicMock(), response=error_resp
        )
    )

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post("/ledger/verify/simple", data={"doc_hash": "ff" * 32})

    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "MISSING_INPUT"


def test_proxy_verify_simple_forwards_auth_headers(monkeypatch):
    """Proxy should forward X-API-Key and Authorization headers to the API (H2)."""
    monkeypatch.setattr(ui_app, "DEBUG_UI_ENABLED", True)

    mock_response = unittest.mock.MagicMock()
    mock_response.json.return_value = {"verified": True, "confidence": "certain"}
    mock_response.raise_for_status = unittest.mock.MagicMock()

    mock_client = unittest.mock.AsyncMock()
    mock_client.__aenter__ = unittest.mock.AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = unittest.mock.AsyncMock(return_value=False)
    mock_client.post = unittest.mock.AsyncMock(return_value=mock_response)

    monkeypatch.setattr(ui_app.httpx, "AsyncClient", lambda **kwargs: mock_client)

    response = client.post(
        "/ledger/verify/simple",
        headers={"X-API-Key": "my-secret-key", "Authorization": "Bearer my-token"},
        data={"doc_hash": "cd" * 32},
    )

    assert response.status_code == 200
    call_kwargs = mock_client.post.call_args
    forwarded_headers = call_kwargs.kwargs["headers"]
    assert forwarded_headers is not None
    assert forwarded_headers["x-api-key"] == "my-secret-key"
    assert forwarded_headers["authorization"] == "Bearer my-token"


# ── PWA integration tests ──


def test_sw_js_served_from_root():
    """Service worker must be served from / for full-scope registration."""
    response = client.get("/sw.js")
    assert response.status_code == 200
    assert "application/javascript" in response.headers["content-type"]
    assert "CACHE_NAME" in response.text


def test_manifest_json_served_from_root():
    """Web app manifest must be served from root for Android install prompts."""
    response = client.get("/manifest.json")
    assert response.status_code == 200
    assert "manifest" in response.headers["content-type"]
    data = response.json()
    assert data["display"] == "standalone"
    assert data["start_url"] == "/"
    assert any(icon["sizes"] == "192x192" for icon in data["icons"])
    assert any(icon["sizes"] == "512x512" for icon in data["icons"])


def test_static_icons_served():
    """PWA icon assets must be reachable via the /static mount."""
    for path in ["/static/icon.svg", "/static/icon-192.png", "/static/icon-512.png"]:
        response = client.get(path)
        assert response.status_code == 200, f"{path} returned {response.status_code}"


def test_pwa_head_tags_in_html():
    """HTML must include manifest link, apple-touch-icon, and SW registration."""
    response = client.get("/verification-portal")
    assert response.status_code == 200
    assert 'rel="manifest"' in response.text
    assert 'href="/manifest.json"' in response.text
    assert 'rel="apple-touch-icon"' in response.text
    assert 'href="/static/icon-192.png"' in response.text
    assert 'register("/sw.js")' in response.text
