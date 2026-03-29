"""
End-to-end audit test for Phase 0.5

FULL PRODUCTION STACK TESTING (PostgreSQL REQUIRED)
====================================================

This test validates the complete production audit flow from record insertion
through API serving to offline cryptographic verification.

DATABASE: PostgreSQL 16+ (via storage.postgres.StorageLayer)
CODE PATH: storage/postgres.py + api/app.py (full production stack)
WHAT IS TESTED:
  ✅ Complete write path (append_record transactions)
  ✅ Ledger chain integrity and linkage
  ✅ Shard header chain and Ed25519 signatures
  ✅ Production API endpoints (api/app.py)
  ✅ Offline proof verification
  ✅ Offline signature verification
  ✅ Offline ledger chain verification

TABLES EXERCISED:
  - All four production tables: smt_leaves, smt_nodes, shard_headers, ledger_entries
  - Full transaction atomicity across all tables
  - Chain linkage preservation

NO DB SHORTCUTS, NO MOCKS BEYOND HTTP.

SETUP:
  export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
  pytest tests/test_e2e_audit.py -v

See docs/08_database_strategy.md for complete database strategy documentation.
"""

import os
from datetime import datetime


try:
    from datetime import UTC
except ImportError:  # Python < 3.11
    from datetime import timezone

    UTC = timezone.utc
from urllib.parse import urlparse, urlunparse
from uuid import uuid4

import nacl.signing
import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import conninfo, sql

from protocol.canonical_json import canonical_json_encode
from protocol.hashes import LEDGER_PREFIX, blake3_hash, hash_bytes
from protocol.shards import verify_header
from protocol.ssmf import ExistenceProof, verify_proof
from storage.postgres import StorageLayer


# Test database connection string
TEST_DB = os.environ.get("TEST_DATABASE_URL", "")

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        not TEST_DB,
        reason="TEST_DATABASE_URL is not set; skipping PostgreSQL end-to-end tests.",
    ),
]


def _create_isolated_database(base_url: str) -> tuple[str, callable]:
    """
    Create a temporary database for an isolated test run.

    Returns a tuple of (database_url, drop_fn).
    """
    parsed = urlparse(base_url)
    if not parsed.path or not parsed.username:
        raise ValueError("TEST_DATABASE_URL must include username/password and a database name")

    base_db = parsed.path.lstrip("/")
    temp_db = f"{base_db}_e2e_{uuid4().hex}"

    admin_cfg = {
        "user": parsed.username,
        "password": parsed.password or "",
        "host": parsed.hostname or "localhost",
        "port": parsed.port or 5432,
        "dbname": "postgres",
    }
    admin_dsn = conninfo.make_conninfo(**admin_cfg)

    temp_url = urlunparse(parsed._replace(path=f"/{temp_db}"))

    with psycopg.connect(admin_dsn) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(temp_db)))

    def drop_db() -> None:
        try:
            with psycopg.connect(admin_dsn) as conn:
                conn.autocommit = True
                with conn.cursor() as cur:
                    cur.execute(
                        sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(temp_db))
                    )
        except Exception:
            pass

    return temp_url, drop_db


@pytest.fixture(scope="module")
def isolated_db_url():
    """Provide an isolated test database URL and clean it up afterwards."""
    db_url, drop_db = _create_isolated_database(TEST_DB)
    try:
        yield db_url
    finally:
        drop_db()


@pytest.fixture
def storage(isolated_db_url):
    """Create a storage layer for testing."""
    storage = StorageLayer(isolated_db_url)
    storage.init_schema()
    return storage


@pytest.fixture
def signing_key():
    """Create a signing key for testing."""
    seed = hash_bytes(b"test seed for e2e audit test")
    return nacl.signing.SigningKey(seed)


@pytest.fixture
def client(storage, isolated_db_url):
    """Create test client for API."""
    # Import here to avoid connecting to Postgres during test collection
    import api.app as api_app
    from api.app import app

    # Override DATABASE_URL for the API
    os.environ["DATABASE_URL"] = isolated_db_url
    os.environ["TEST_DATABASE_URL"] = isolated_db_url

    # Reset lazy storage state so tests start fresh
    api_app._storage = None
    api_app._db_error = None

    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()


def test_end_to_end_audit_flow(storage, signing_key, client):
    """
    Golden path test: Full audit flow from record insertion to offline verification.

    This test:
    1. Appends multiple records with different versions
    2. Verifies ledger entries are chained correctly
    3. Verifies shard headers are chained correctly
    4. Fetches proofs via API
    5. Verifies proofs offline
    6. Verifies signatures offline
    7. Verifies ledger chain offline
    """
    shard_id = f"audit_test_shard_{datetime.now(UTC).timestamp()}"

    # Step 1: Append multiple records
    print(f"\n=== Step 1: Appending records to shard {shard_id} ===")

    records = [
        ("document", "doc1", 1, b"content version 1"),
        ("document", "doc1", 2, b"content version 2"),
        ("document", "doc2", 1, b"another document"),
        ("policy", "policy1", 1, b"policy content"),
        ("document", "doc1", 3, b"content version 3"),
    ]

    results = []
    for record_type, record_id, version, content in records:
        value_hash = hash_bytes(content)
        root, proof, header, signature, ledger_entry = storage.append_record(
            shard_id=shard_id,
            record_type=record_type,
            record_id=record_id,
            version=version,
            value_hash=value_hash,
            signing_key=signing_key,
        )
        results.append(
            {
                "record_type": record_type,
                "record_id": record_id,
                "version": version,
                "content": content,
                "value_hash": value_hash,
                "root": root,
                "proof": proof,
                "header": header,
                "signature": signature,
                "ledger_entry": ledger_entry,
            }
        )
        print(f"  Appended: {record_type}:{record_id}:v{version} -> {value_hash.hex()[:16]}...")

    # Step 2: Verify ledger chain linkage
    print("\n=== Step 2: Verifying ledger chain linkage ===")
    assert results[0]["ledger_entry"].prev_entry_hash == "", (
        "First entry should have empty prev_entry_hash"
    )

    for i in range(1, len(results)):
        prev_hash = results[i - 1]["ledger_entry"].entry_hash
        curr_prev = results[i]["ledger_entry"].prev_entry_hash
        assert curr_prev == prev_hash, f"Entry {i} should link to entry {i - 1}"
        print(f"  Entry {i} correctly links to entry {i - 1}")

    # Step 3: Verify shard header chain linkage
    print("\n=== Step 3: Verifying shard header chain linkage ===")
    assert results[0]["header"]["previous_header_hash"] == "", (
        "First header should have empty previous_header_hash"
    )

    for i in range(1, len(results)):
        prev_hash = results[i - 1]["header"]["header_hash"]
        curr_prev = results[i]["header"]["previous_header_hash"]
        assert curr_prev == prev_hash, f"Header {i} should link to header {i - 1}"
        print(f"  Header {i} correctly links to header {i - 1}")

    # Step 4: Fetch proofs via API
    print("\n=== Step 4: Fetching proofs via API ===")
    for i, result in enumerate(results):
        response = client.get(
            f"/shards/{shard_id}/proof",
            params={
                "record_type": result["record_type"],
                "record_id": result["record_id"],
                "version": result["version"],
            },
        )
        assert response.status_code == 200, f"Failed to fetch proof for record {i}"
        proof_data = response.json()

        # Verify it's an existence proof
        assert "value_hash" in proof_data, "Should be an existence proof"
        assert proof_data["shard_id"] == shard_id
        assert proof_data["record_type"] == result["record_type"]
        assert proof_data["record_id"] == result["record_id"]
        assert proof_data["version"] == result["version"]
        print(
            f"  Fetched proof for {result['record_type']}:{result['record_id']}:v{result['version']}"
        )

    # Step 5: Verify proofs offline
    print("\n=== Step 5: Verifying proofs offline ===")
    for i, result in enumerate(results):
        response = client.get(
            f"/shards/{shard_id}/proof",
            params={
                "record_type": result["record_type"],
                "record_id": result["record_id"],
                "version": result["version"],
            },
        )
        proof_data = response.json()

        # Reconstruct ExistenceProof from API response
        api_proof = ExistenceProof(
            key=bytes.fromhex(proof_data["key"]),
            value_hash=bytes.fromhex(proof_data["value_hash"]),
            siblings=[bytes.fromhex(s) for s in proof_data["siblings"]],
            root_hash=bytes.fromhex(proof_data["root_hash"]),
        )

        # Verify proof offline
        assert verify_proof(api_proof) is True, f"Proof verification failed for record {i}"
        print(
            f"  ✓ Proof verified for {result['record_type']}:{result['record_id']}:v{result['version']}"
        )

    # Step 6: Verify signatures offline
    print("\n=== Step 6: Verifying signatures offline ===")
    response = client.get(f"/shards/{shard_id}/header/latest")
    assert response.status_code == 200
    header_data = response.json()

    # Reconstruct header for verification — must include all fields that
    # were part of the original hash commitment (tree_size, height, round).
    header_for_verification = {
        "shard_id": header_data["shard_id"],
        "root_hash": header_data["root_hash"],
        "tree_size": header_data["tree_size"],
        "timestamp": header_data["timestamp"],
        "height": header_data.get("height", 0),
        "round": header_data.get("round", 0),
        "previous_header_hash": header_data["previous_header_hash"],
        "header_hash": header_data["header_hash"],
    }

    # Verify signature offline
    verify_key = nacl.signing.VerifyKey(bytes.fromhex(header_data["pubkey"]))
    is_valid = verify_header(header_for_verification, header_data["signature"], verify_key)
    assert is_valid is True, "Signature verification failed"
    print(f"  ✓ Signature verified for latest header (seq={header_data['seq']})")

    # Step 7: Verify ledger entries offline
    print("\n=== Step 7: Verifying ledger entries offline ===")
    response = client.get(f"/ledger/{shard_id}/tail", params={"n": len(results)})
    assert response.status_code == 200
    ledger_data = response.json()

    entries = ledger_data["entries"]
    assert len(entries) == len(results), "Should get all entries"

    # Entries are in reverse order (most recent first)
    entries = list(reversed(entries))

    # Verify each entry's hash
    for i, entry in enumerate(entries):
        # Recompute entry hash
        payload = {
            "ts": entry["ts"],
            "record_hash": entry["record_hash"],
            "shard_id": entry["shard_id"],
            "shard_root": entry["shard_root"],
            "canonicalization": entry["canonicalization"],
            "prev_entry_hash": entry["prev_entry_hash"],
        }
        canonical_json = canonical_json_encode(payload)
        expected_hash = blake3_hash([LEDGER_PREFIX, canonical_json.encode("utf-8")]).hex()

        assert entry["entry_hash"] == expected_hash, f"Entry hash mismatch for entry {i}"
        print(f"  ✓ Entry {i} hash verified: {entry['entry_hash'][:16]}...")

    # Verify chain linkage
    assert entries[0]["prev_entry_hash"] == "", "First entry should have empty prev_entry_hash"
    for i in range(1, len(entries)):
        assert entries[i]["prev_entry_hash"] == entries[i - 1]["entry_hash"], (
            f"Chain break at entry {i}"
        )
    print(f"  ✓ Ledger chain linkage verified ({len(entries)} entries)")

    print("\n=== ✓ All verification steps passed! ===")


def test_nonexistence_proof_via_api(storage, signing_key, client):
    """
    Test that non-existence proofs work via the API.
    """
    shard_id = f"nonexist_test_shard_{datetime.now(UTC).timestamp()}"

    # Append one record to create the shard
    storage.append_record(
        shard_id=shard_id,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"content"),
        signing_key=signing_key,
    )

    # Request proof for non-existent record
    response = client.get(
        f"/shards/{shard_id}/proof",
        params={"record_type": "document", "record_id": "nonexistent", "version": 1},
    )
    assert response.status_code == 200
    proof_data = response.json()

    # Should be a non-existence proof (no value_hash field)
    assert "value_hash" not in proof_data, "Should be a non-existence proof"
    assert proof_data["shard_id"] == shard_id
    assert proof_data["record_type"] == "document"
    assert proof_data["record_id"] == "nonexistent"
    assert len(proof_data["siblings"]) == 256

    print("✓ Non-existence proof received for nonexistent record")


def test_list_shards_via_api(storage, signing_key, client):
    """
    Test that listing shards works via the API.
    """
    # Create two shards
    shard1 = f"list_test_shard_1_{datetime.now(UTC).timestamp()}"
    shard2 = f"list_test_shard_2_{datetime.now(UTC).timestamp()}"

    storage.append_record(
        shard_id=shard1,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"content1"),
        signing_key=signing_key,
    )

    storage.append_record(
        shard_id=shard2,
        record_type="document",
        record_id="doc1",
        version=1,
        value_hash=hash_bytes(b"content2"),
        signing_key=signing_key,
    )

    # List shards
    response = client.get("/shards")
    assert response.status_code == 200
    shards = response.json()

    shard_ids = [s["shard_id"] for s in shards]
    assert shard1 in shard_ids
    assert shard2 in shard_ids

    print(f"✓ Listed {len(shards)} shards via API")


def test_api_root_and_health(client):
    """
    Test that API root and health check work.
    """
    # Test root
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Olympus FOIA Ledger"
    assert "version" in data

    # Test health
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"

    print("✓ API root and health check working")
