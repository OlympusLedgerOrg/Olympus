"""
Tests for API proof endpoints

This test validates that the proof endpoints return structured proofs
without raising exceptions for both existing and non-existing keys.
"""

import pytest
import os
import tempfile
from fastapi.testclient import TestClient
from protocol.hashes import record_key, hash_bytes


# Set up test environment with a temporary database
@pytest.fixture(autouse=True)
def setup_test_db():
    """Create a temporary database for tests."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sqlite', delete=False) as f:
        db_path = f.name
    
    # Set the environment variable before importing the app
    os.environ['OLY_DB_PATH'] = db_path
    
    yield db_path
    
    # Clean up
    if os.path.exists(db_path):
        os.unlink(db_path)


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    # Import here to ensure the environment variable is set
    from app.main import app
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
    from app.main import state
    
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
    from app.main import state
    
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
    from app.main import state
    
    # Check that the database path is NOT :memory:
    assert state.db_path != ":memory:"
    
    # Check that it's a valid file path (should start with /tmp/)
    assert state.db_path.startswith("/tmp/") or state.db_path.startswith("/var/")
