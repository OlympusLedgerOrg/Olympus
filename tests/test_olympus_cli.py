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
