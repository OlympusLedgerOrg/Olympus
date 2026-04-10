"""Tests for the FastAPI application."""

from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

# Skip if test dependencies not available
pytest.importorskip("httpx")


class TestHealthEndpoint:
    """Tests for the /health endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create a test client."""
        from ingest_parser.main import app

        return TestClient(app)

    def test_health_check(self, client: TestClient) -> None:
        """Test health check returns healthy status."""
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert "parser_name" in data
        assert "parser_version" in data
        assert "model_hash" in data
        assert data["cpu_only"] is True


class TestParseEndpoint:
    """Tests for the /parse endpoint."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create a test client."""
        from ingest_parser.main import app

        return TestClient(app)

    def test_parse_text_file(self, client: TestClient) -> None:
        """Test parsing a plain text file."""
        content = b"Hello, this is a test document."
        files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

        response = client.post("/parse", files=files)
        assert response.status_code == 200

        data = response.json()
        assert "provenance" in data
        assert "document" in data
        assert data["provenance"]["raw_file_blake3"].startswith("blake3_")
        assert data["document"]["total_pages"] >= 1

    def test_parse_with_expected_hash(self, client: TestClient) -> None:
        """Test parsing with hash verification."""
        from ingest_parser.crypto import compute_blake3

        content = b"Content with known hash"
        expected_hash = compute_blake3(content)

        files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/parse",
            files=files,
            data={"expected_blake3": expected_hash},
        )
        assert response.status_code == 200

    def test_parse_hash_mismatch(self, client: TestClient) -> None:
        """Test that hash mismatch returns 422."""
        content = b"Some content"
        wrong_hash = "blake3_" + "0" * 64

        files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

        response = client.post(
            "/parse",
            files=files,
            data={"expected_blake3": wrong_hash},
        )
        assert response.status_code == 422
        assert "mismatch" in response.json()["detail"].lower()

    def test_parse_unsupported_type(self, client: TestClient) -> None:
        """Test that unsupported content type returns 415."""
        content = b"Some binary content"
        files = {"file": ("test.bin", io.BytesIO(content), "application/octet-stream")}

        response = client.post("/parse", files=files)
        assert response.status_code == 415


class TestDeterminism:
    """Tests for deterministic output."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create a test client."""
        from ingest_parser.main import app

        return TestClient(app)

    def test_same_input_same_output(self, client: TestClient) -> None:
        """Test that same input produces identical output."""
        content = b"Determinism test content with some text."
        files1 = {"file": ("test.txt", io.BytesIO(content), "text/plain")}
        files2 = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

        response1 = client.post("/parse", files=files1)
        response2 = client.post("/parse", files=files2)

        assert response1.status_code == 200
        assert response2.status_code == 200

        # The responses should be identical
        data1 = response1.json()
        data2 = response2.json()

        assert data1["provenance"]["raw_file_blake3"] == data2["provenance"]["raw_file_blake3"]
        assert data1["document"] == data2["document"]

    def test_bbox_precision(self, client: TestClient) -> None:
        """Test that bounding box coordinates have correct precision."""
        content = b"Test content"
        files = {"file": ("test.txt", io.BytesIO(content), "text/plain")}

        response = client.post("/parse", files=files)
        assert response.status_code == 200

        data = response.json()
        for page in data["document"]["pages"]:
            for block in page["blocks"]:
                for coord in block["bbox"]:
                    # Check that coordinate has at most 4 decimal places
                    str_coord = str(coord)
                    if "." in str_coord:
                        decimals = len(str_coord.split(".")[1])
                        assert decimals <= 4, f"Coordinate {coord} has more than 4 decimal places"
