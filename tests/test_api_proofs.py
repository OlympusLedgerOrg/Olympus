"""
Tests for API proof endpoints

IN-MEMORY PROOF LOGIC TESTING (NO DATABASE)
============================================

This test validates proof generation logic using in-memory SparseMerkleTree instances.
It does NOT test the production storage layer or database transactions.

DATABASE: None (in-memory state via app_testonly/state.py)
CODE PATH: app_testonly/main.py (test API) + app_testonly/state.py (in-memory)
WHAT IS TESTED:
  ✅ protocol/ssmf.py proof generation logic
  ✅ Unified proof behavior (exists field)
  ✅ API endpoint response structure
  ❌ NOT tested: PostgreSQL storage layer
  ❌ NOT tested: Transaction semantics
  ❌ NOT tested: Persistence

For production storage layer testing, see test_storage.py and test_e2e_audit.py.

NOTE: The 'SQLite' file path created in setup_test_db() is VESTIGIAL and NOT USED.
The test API (app_testonly/main.py) uses in-memory SparseMerkleTree instances, not a database.

See docs/08_database_strategy.md for complete database strategy documentation.
"""

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from protocol.hashes import hash_bytes, record_key


@pytest.fixture(autouse=True)
def setup_test_db():
    """
    Create a temporary database file path for tests.

    NOTE: This file path is VESTIGIAL and NOT USED for actual database operations.
    The test API (app_testonly/main.py) uses in-memory SparseMerkleTree instances.
    No database reads or writes occur.

    This fixture exists for API compatibility only.
    """
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        db_path = f.name

    # Set the environment variable before importing the app
    os.environ["OLY_DB_PATH"] = db_path

    yield db_path

    # Clean up
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    # Import here to ensure the environment variable is set
    from app_testonly.main import app

    return TestClient(app)


def test_proof_existence_endpoint_returns_nonexistence_proof_for_missing_key(client):
    """
    Test that /proof/existence returns NonExistenceProof (exists=False)
    with HTTP 200 for a missing key.
    """
    # Query for a key that doesn't exist
    key = record_key("document", "missing_doc", 1)
    response = client.get(f"/shards/shard1/proof/existence?key={key.hex()}")

    # Should return 200 (not 404)
    assert response.status_code == 200

    # Should be a structured proof
    proof = response.json()
    assert "exists" in proof
    assert proof["exists"] is False  # Key doesn't exist
    assert "key" in proof
    assert proof["key"] == key.hex()
    assert "root_hash" in proof
    assert "siblings" in proof
    assert len(proof["siblings"]) == 256


def test_proof_nonexistence_endpoint_returns_nonexistence_proof_for_missing_key(client):
    """
    Test that /proof/nonexistence returns NonExistenceProof (exists=False)
    with HTTP 200 for a missing key.
    """
    # Query for a key that doesn't exist
    key = record_key("document", "missing_doc2", 1)
    response = client.get(f"/shards/shard1/proof/nonexistence?key={key.hex()}")

    # Should return 200
    assert response.status_code == 200

    # Should be a structured proof
    proof = response.json()
    assert "exists" in proof
    assert proof["exists"] is False  # Key doesn't exist
    assert "key" in proof
    assert proof["key"] == key.hex()


def test_proof_existence_endpoint_returns_existence_proof_for_existing_key(client):
    """
    Test that /proof/existence returns ExistenceProof (exists=True)
    with HTTP 200 for an existing key.
    """
    # First, we need to add a key to the shard
    # Since we don't have a write endpoint, we'll access the state directly
    from app_testonly.main import state

    key = record_key("document", "doc1", 1)
    value_hash = hash_bytes(b"test value")

    # Add the key to the shard
    shard = state._shard("shard2")
    shard.tree.update(key, value_hash)

    # Now query for the key
    response = client.get(f"/shards/shard2/proof/existence?key={key.hex()}")

    # Should return 200
    assert response.status_code == 200

    # Should be an existence proof
    proof = response.json()
    assert "exists" in proof
    assert proof["exists"] is True  # Key exists
    assert "key" in proof
    assert proof["key"] == key.hex()
    assert "value_hash" in proof
    assert proof["value_hash"] == value_hash.hex()
    assert "root_hash" in proof
    assert "siblings" in proof
    assert len(proof["siblings"]) == 256


def test_proof_nonexistence_endpoint_returns_existence_proof_for_existing_key(client):
    """
    Test that /proof/nonexistence returns ExistenceProof (exists=True)
    with HTTP 200 for an existing key.

    Key point: Both endpoints return the same unified proof structure.
    """
    # Add a key to the shard
    from app_testonly.main import state

    key = record_key("document", "doc2", 1)
    value_hash = hash_bytes(b"another value")

    shard = state._shard("shard3")
    shard.tree.update(key, value_hash)

    # Query via /proof/nonexistence endpoint
    response = client.get(f"/shards/shard3/proof/nonexistence?key={key.hex()}")

    # Should return 200 (not 409 or error)
    assert response.status_code == 200

    # Should still be an existence proof
    proof = response.json()
    assert proof["exists"] is True  # Key exists, even though endpoint is "nonexistence"
    assert proof["key"] == key.hex()
    assert proof["value_hash"] == value_hash.hex()


def test_invalid_key_returns_400(client):
    """Test that invalid hex keys return HTTP 400."""
    response = client.get("/shards/shard1/proof/existence?key=not_hex")
    assert response.status_code == 400
    assert "key must be hex" in response.json()["detail"]


def test_proof_existence_missing_key_returns_422(client):
    """Test that missing key parameter returns HTTP 422."""
    response = client.get("/shards/shard1/proof/existence")
    assert response.status_code == 422


def test_health_check(client):
    """Test the root health check endpoint."""
    response = client.get("/status")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_database_is_file_backed():
    """
    Test that the database is file-backed (not :memory:).

    This is critical for e2e tests where multiple connections need to
    share the same database.
    """
    # Import after setting the environment variable
    from app_testonly.main import state

    # Check that the database path is NOT :memory:
    assert state.db_path != ":memory:"

    # Check that it's a valid file path (not empty or None)
    assert state.db_path
    assert isinstance(state.db_path, str)
    assert len(state.db_path) > 0


def test_roots_endpoint(client):
    """Test the /roots endpoint returns global and shard roots."""
    # Add some data to create shards
    from app_testonly.main import state

    key1 = record_key("document", "doc1", 1)
    value_hash1 = hash_bytes(b"value1")
    shard1 = state._shard("shard_a")
    shard1.tree.update(key1, value_hash1)

    key2 = record_key("document", "doc2", 1)
    value_hash2 = hash_bytes(b"value2")
    shard2 = state._shard("shard_b")
    shard2.tree.update(key2, value_hash2)

    # Query the /roots endpoint
    response = client.get("/roots")
    assert response.status_code == 200

    data = response.json()
    assert "global_root" in data
    assert "shards" in data
    assert "shard_a" in data["shards"]
    assert "shard_b" in data["shards"]
    assert isinstance(data["shards"]["shard_a"], str)
    assert isinstance(data["shards"]["shard_b"], str)


def test_list_shards_endpoint(client):
    """Test the /shards endpoint returns list of shard IDs."""
    # Add some shards
    from app_testonly.main import state

    key1 = record_key("document", "doc_x", 1)
    value_hash1 = hash_bytes(b"value_x")
    shard1 = state._shard("shard_x")
    shard1.tree.update(key1, value_hash1)

    key2 = record_key("document", "doc_y", 1)
    value_hash2 = hash_bytes(b"value_y")
    shard2 = state._shard("shard_y")
    shard2.tree.update(key2, value_hash2)

    # Query the /shards endpoint
    response = client.get("/shards")
    assert response.status_code == 200

    data = response.json()
    assert "shards" in data
    assert isinstance(data["shards"], list)
    assert "shard_x" in data["shards"]
    assert "shard_y" in data["shards"]


def test_shard_header_latest_returns_404_for_nonexistent_shard(client):
    """Test that /shards/{shard_id}/header/latest returns 404 for non-existent shard."""
    response = client.get("/shards/nonexistent_shard/header/latest")
    assert response.status_code == 404
    assert "shard not found" in response.json()["detail"]


def test_shard_header_latest_returns_header_for_existing_shard(client):
    """Test that /shards/{shard_id}/header/latest returns header for existing shard."""
    from app_testonly.main import state

    # Create a shard with data
    key = record_key("document", "doc_header", 1)
    value_hash = hash_bytes(b"header_value")
    shard = state._shard("shard_with_header")
    shard.tree.update(key, value_hash)

    # Query the header
    response = client.get("/shards/shard_with_header/header/latest")
    assert response.status_code == 200

    data = response.json()
    assert "shard_id" in data
    assert data["shard_id"] == "shard_with_header"
    assert "root_hash" in data
    assert isinstance(data["root_hash"], str)


def test_proof_nonexistence_invalid_key_returns_400(client):
    """Test that /proof/nonexistence returns 400 for invalid hex key."""
    response = client.get("/shards/shard1/proof/nonexistence?key=invalid_hex_key")
    assert response.status_code == 400
    assert "key must be hex" in response.json()["detail"]


def test_list_shards_when_empty(client):
    """Test that list_shards returns empty list when no shards exist."""
    # Create a fresh state with no shards
    from app_testonly.state import OlympusState

    # Create new state temporarily
    fresh_state = OlympusState("/tmp/test_empty.sqlite")

    # Test the list_shards method directly
    assert fresh_state.list_shards() == []


def test_header_latest_returns_none_for_missing_shard():
    """Test that header_latest returns None when shard doesn't exist."""
    from app_testonly.state import OlympusState

    state = OlympusState("/tmp/test_header.sqlite")
    header = state.header_latest("nonexistent_shard")
    assert header is None
