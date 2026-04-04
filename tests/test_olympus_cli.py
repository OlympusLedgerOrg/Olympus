"""
Tests for the unified olympus CLI.
"""

import json
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import blake3


CLI_PATH = Path(__file__).parent.parent / "tools" / "olympus.py"
REGISTRY_PATH = Path(__file__).parent.parent / "examples" / "federation_registry.json"


def test_olympus_canon_outputs_canonical_json(tmp_path):
    """olympus canon normalizes whitespace and preserves deterministic output."""
    input_file = tmp_path / "input.json"
    input_file.write_text(json.dumps({"body": "Hello  world", "title": "Example"}))

    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "canon", str(input_file), "--format", "json"],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    canonical = json.loads(result.stdout)
    assert canonical["body"] == "Hello world"


def test_olympus_node_list_outputs_registry_nodes() -> None:
    """olympus node list should print the static federation registry."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "node", "list", "--registry", str(REGISTRY_PATH)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "olympus-node-1" in result.stdout
    assert "City Records Office" in result.stdout
    assert "State Auditor" in result.stdout


def test_olympus_federation_status_reports_counts_without_live_nodes() -> None:
    """olympus federation status should report registry counts even without live endpoints."""
    result = subprocess.run(
        [sys.executable, str(CLI_PATH), "federation", "status", "--registry", str(REGISTRY_PATH)],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "Federation Status" in result.stdout
    assert "Nodes: 3" in result.stdout
    assert "Active: 3" in result.stdout
    assert "Quorum: 2" in result.stdout


# ---------------------------------------------------------------------------
# commit subcommand tests
# ---------------------------------------------------------------------------


def _make_stub_api(proof_id: str, status: int = 200) -> tuple[HTTPServer, int]:
    """Spin up a minimal HTTP stub that returns a fixed commit response."""

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            if status == 200:
                body = json.dumps({"proof_id": proof_id}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

        def log_message(self, *args: object) -> None:  # suppress access logs
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]


def test_olympus_commit_hashes_file_and_returns_proof_id(tmp_path: Path) -> None:
    """commit subcommand should hash a file, POST to /ingest/commit, and print proof_id."""
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"fake release artifact content")
    expected_proof_id = str(uuid.uuid4())

    server, port = _make_stub_api(expected_proof_id)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "commit",
                str(artifact),
                "--namespace",
                "github",
                "--id",
                "org/repo/v1.0.0",
                "--api-url",
                f"http://127.0.0.1:{port}",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()

    assert result.returncode == 0
    assert result.stdout.strip() == expected_proof_id


def test_olympus_commit_missing_file_returns_nonzero(tmp_path: Path) -> None:
    """commit should exit with code 1 when the file does not exist."""
    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(tmp_path / "nonexistent.zip"),
            "--api-url",
            "http://127.0.0.1:1",  # unreachable; should fail at file read
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "not found" in result.stderr.lower()


def test_olympus_commit_api_error_returns_nonzero(tmp_path: Path) -> None:
    """commit should exit with code 1 when the API returns an error status."""
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"data")

    server, port = _make_stub_api("", status=500)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "commit",
                str(artifact),
                "--api-url",
                f"http://127.0.0.1:{port}",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()

    assert result.returncode != 0


def test_olympus_commit_unreachable_api_returns_nonzero(tmp_path: Path) -> None:
    """commit should exit with code 1 when the API is unreachable."""
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"data")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(artifact),
            "--api-url",
            "http://127.0.0.1:1",  # nothing listening on port 1
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode != 0


def test_olympus_commit_rejects_non_http_api_url(tmp_path: Path) -> None:
    """commit should reject non-http(s) API URLs before making a request."""
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"data")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            "commit",
            str(artifact),
            "--api-url",
            "ftp://127.0.0.1:8000",
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "http or https" in result.stderr.lower()


def test_olympus_commit_accepts_api_key(tmp_path: Path) -> None:
    """commit should forward --api-key in the request payload."""
    artifact = tmp_path / "artifact.zip"
    artifact.write_bytes(b"payload")
    expected_proof_id = str(uuid.uuid4())
    received_bodies: list[bytes] = []

    class _CapturingHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received_bodies.append(self.rfile.read(length))
            body = json.dumps({"proof_id": expected_proof_id}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _CapturingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "commit",
                str(artifact),
                "--api-key",
                "test-secret",
                "--namespace",
                "github",
                "--id",
                "org/repo/v2.0.0",
                "--api-url",
                f"http://127.0.0.1:{port}",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()

    assert result.returncode == 0
    assert len(received_bodies) == 1
    payload = json.loads(received_bodies[0])
    assert payload["api_key"] == "test-secret"
    assert payload["namespace"] == "github"
    assert payload["id"] == "org/repo/v2.0.0"
    assert len(payload["artifact_hash"]) == 64  # 32-byte BLAKE3 hex


def test_olympus_ingest_can_generate_proof_and_verify(tmp_path: Path) -> None:
    """ingest should orchestrate commit, proof retrieval, and verification."""
    artifact = tmp_path / "document.pdf"
    artifact.write_bytes(b"demo document payload")
    expected_proof_id = str(uuid.uuid4())

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/ingest/commit":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps({"proof_id": expected_proof_id}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == f"/ingest/records/{expected_proof_id}/proof":
                body = json.dumps(
                    {
                        "proof_id": expected_proof_id,
                        "record_id": "document.pdf",
                        "shard_id": "demo",
                        "content_hash": "ab" * 32,
                        "merkle_root": "cd" * 32,
                        "merkle_proof": {
                            "leaf_hash": "ef" * 32,
                            "leaf_index": 0,
                            "siblings": [],
                            "root_hash": "cd" * 32,
                            "proof_version": "1.0",
                            "tree_version": "1.0",
                            "epoch": 0,
                            "tree_size": 1,
                        },
                        "ledger_entry_hash": "12" * 32,
                        "timestamp": "2026-01-01T00:00:00Z",
                        "canonicalization": {"content_type": "application/octet-stream"},
                        "batch_id": "demo-batch",
                        "poseidon_root": None,
                    }
                ).encode()
            elif self.path.startswith("/ingest/records/hash/") and self.path.endswith("/verify"):
                body = json.dumps(
                    {
                        "proof_id": expected_proof_id,
                        "record_id": "document.pdf",
                        "shard_id": "demo",
                        "content_hash": "ab" * 32,
                        "merkle_root": "cd" * 32,
                        "merkle_proof": {
                            "leaf_hash": "ef" * 32,
                            "leaf_index": 0,
                            "siblings": [],
                            "root_hash": "cd" * 32,
                            "proof_version": "1.0",
                            "tree_version": "1.0",
                            "epoch": 0,
                            "tree_size": 1,
                        },
                        "ledger_entry_hash": "12" * 32,
                        "timestamp": "2026-01-01T00:00:00Z",
                        "canonicalization": {"content_type": "application/octet-stream"},
                        "batch_id": "demo-batch",
                        "poseidon_root": None,
                        "merkle_proof_valid": True,
                    }
                ).encode()
            else:
                self.send_response(404)
                self.end_headers()
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "ingest",
                str(artifact),
                "--api-url",
                f"http://127.0.0.1:{port}",
                "--generate-proof",
                "--verify",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()

    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data["commit"]["proof_id"] == expected_proof_id
    assert data["proof"]["proof_id"] == expected_proof_id
    assert data["verification"]["merkle_proof_valid"] is True


def test_olympus_ingest_forwards_source_url_and_raw_pdf_hash(tmp_path: Path) -> None:
    """ingest should send source-url/raw-pdf metadata and print raw BLAKE3 checksums."""
    artifact = tmp_path / "document.txt"
    artifact.write_bytes(b"ocr text output")
    raw_pdf = tmp_path / "document.pdf"
    raw_pdf.write_bytes(b"%PDF-1.7 raw scan bytes")
    expected_proof_id = str(uuid.uuid4())
    received_bodies: list[dict[str, object]] = []

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            received_bodies.append(json.loads(self.rfile.read(length).decode("utf-8")))
            body = json.dumps({"proof_id": expected_proof_id}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    server = HTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    expected_artifact_hash = blake3.blake3(artifact.read_bytes()).hexdigest()
    expected_raw_pdf_hash = blake3.blake3(raw_pdf.read_bytes()).hexdigest()

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(CLI_PATH),
                "ingest",
                str(artifact),
                "--api-url",
                f"http://127.0.0.1:{port}",
                "--source-url",
                "https://example.com/archive/document.pdf",
                "--raw-pdf",
                str(raw_pdf),
                "--json",
            ],
            capture_output=True,
            text=True,
        )
    finally:
        server.shutdown()

    assert result.returncode == 0
    assert len(received_bodies) == 1
    payload = received_bodies[0]
    assert payload["artifact_hash"] == expected_artifact_hash
    assert payload["source_url"] == "https://example.com/archive/document.pdf"
    assert payload["raw_pdf_hash"] == expected_raw_pdf_hash

    data = json.loads(result.stdout)
    assert data["artifact_hash"] == expected_artifact_hash
    assert data["source_url"] == "https://example.com/archive/document.pdf"
    assert data["raw_pdf_hash"] == expected_raw_pdf_hash
