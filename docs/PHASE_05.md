# Olympus Phase 0.5: Verifiable Protocol Implementation

This document describes the Phase 0.5 implementation that makes the Olympus protocol publicly verifiable end-to-end.

## Overview

Phase 0.5 adds:
- **Postgres persistence** for Sparse Merkle State Forest, shard headers, and ledger entries
- **Public audit API** (FastAPI) for third-party verification
- **End-to-end tests** validating the complete audit flow
- **CI/CD pipeline** with pytest, ruff, and mypy

**Database Backend**: PostgreSQL 16+ is the only supported production database. See `08_database_strategy.md` for rationale and testing strategy.

## Architecture

```
┌─────────────────┐
│  Public Auditor │ (HTTP client, offline verifier)
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  FastAPI Server │ (Read-only endpoints)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Storage Layer   │ (Append-only operations)
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Postgres DB   │ (Immutable tables)
└─────────────────┘
```

## Database Schema

### Tables (All Append-Only)

1. **`smt_leaves`** - Sparse Merkle tree leaf nodes
   - Primary key: `(shard_id, key, version)`
   - Stores 32-byte keys and value hashes

2. **`smt_nodes`** - Sparse Merkle tree internal nodes
   - Primary key: `(shard_id, level, index)`
   - Stores 32-byte node hashes

3. **`shard_headers`** - Signed shard root commitments
   - Primary key: `(shard_id, seq)`
   - Stores Ed25519 signatures and public keys
   - Links to previous header (chain)

4. **`ledger_entries`** - Global append-only ledger
   - Primary key: `(shard_id, seq)`
   - Links to previous entry (chain)
   - Stores canonical JSON payload

### Schema Invariants

- ✅ INSERT only (no UPDATE or DELETE)
- ✅ Explicit sequence numbers (`seq`) computed with `SELECT MAX(seq)+1`
- ✅ All hash fields are 32-byte BYTEA
- ✅ Primary keys prevent history rewrites
- ✅ No SERIAL, IDENTITY, or auto-increment columns

## API Endpoints

All endpoints are **read-only** and return data for **offline verification**.

### `GET /shards`
Lists all shards with their latest state.

**Response:**
```json
[
  {
    "shard_id": "shard1",
    "latest_seq": 42,
    "latest_root": "a1b2c3..."
  }
]
```

### `GET /shards/{shard_id}/header/latest`
Returns the latest shard header with signature.

**Response:**
```json
{
  "shard_id": "shard1",
  "seq": 42,
  "root_hash": "a1b2c3...",
  "header_hash": "d4e5f6...",
  "previous_header_hash": "g7h8i9...",
  "timestamp": "2024-01-01T00:00:00Z",
  "signature": "sig_hex...",
  "pubkey": "pubkey_hex...",
  "canonical_header_json": "{...}"
}
```

**Offline Verification:**
1. Verify `header_hash` matches hash of `canonical_header_json`
2. Verify Ed25519 signature over `header_hash` using `pubkey`

### `GET /shards/{shard_id}/proof?record_type=&record_id=&version=`
Returns existence or non-existence proof for a record.

**Existence Proof Response:**
```json
{
  "shard_id": "shard1",
  "record_type": "document",
  "record_id": "doc1",
  "version": 1,
  "key": "key_hex...",
  "value_hash": "value_hex...",
  "siblings": ["s0_hex...", "s1_hex...", ...],  // 256 entries
  "root_hash": "root_hex...",
  "shard_header": {...}
}
```

**Offline Verification:**
1. Compute `leaf_hash(key, value_hash)`
2. Walk up the tree using `siblings` to recompute root
3. Verify computed root matches `root_hash`
4. Verify `root_hash` matches `shard_header.root_hash`
5. Verify shard header signature

### `GET /ledger/{shard_id}/tail?n=10`
Returns the last N ledger entries for a shard.

**Response:**
```json
{
  "shard_id": "shard1",
  "entries": [
    {
      "ts": "2024-01-01T00:00:00Z",
      "doc_id": "doc1",
      "record_hash": "hash_hex...",
      "shard_id": "shard1",
      "shard_root": "root_hex...",
      "prev_entry_hash": "prev_hex...",
      "entry_hash": "entry_hex..."
    }
  ]
}
```

**Offline Verification:**
1. For each entry, recompute `entry_hash` from canonical JSON of payload fields
2. Verify each entry links to previous entry via `prev_entry_hash`
3. Verify first entry has empty `prev_entry_hash`

## Running the System

### Prerequisites

- Python 3.12+
- PostgreSQL 16+

### Installation

```bash
# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set database URL
export DATABASE_URL='postgresql://user:pass@localhost:5432/olympus'
```

### Running the API

```bash
python run_api.py --host 0.0.0.0 --port 8000
```

Or with uvicorn directly:
```bash
uvicorn api.app:app --host 0.0.0.0 --port 8000
```

### Running Tests

```bash
# Set test database URL
export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus_test'

# Run all tests
pytest tests/ -v

# Run only e2e tests
pytest tests/test_e2e_audit.py -v

# Run with coverage
pytest tests/ --cov=protocol --cov=storage --cov=api
```

### Linting and Type Checking

```bash
# Run ruff
ruff check protocol/ storage/ api/ tests/

# Run mypy
mypy protocol/ storage/ api/ --ignore-missing-imports
```

## Example Usage

### Appending a Record

```python
from storage.postgres import StorageLayer
from protocol.hashes import hash_bytes
import nacl.signing

# Initialize storage
storage = StorageLayer('postgresql://user:pass@localhost:5432/olympus')
storage.init_schema()

# Create signing key
signing_key = nacl.signing.SigningKey.generate()

# Append a record
root, proof, header, signature, ledger_entry = storage.append_record(
    shard_id="my_shard",
    record_type="document",
    record_id="doc1",
    version=1,
    value_hash=hash_bytes(b"document content"),
    signing_key=signing_key
)

print(f"Root: {root.hex()}")
print(f"Entry hash: {ledger_entry.entry_hash}")
```

### Verifying a Proof (Offline)

```python
import requests
from protocol.ssmf import verify_proof, ExistenceProof
from protocol.shards import verify_header
import nacl.signing

# Fetch proof from API
response = requests.get(
    'http://localhost:8000/shards/my_shard/proof',
    params={'record_type': 'document', 'record_id': 'doc1', 'version': 1}
)
proof_data = response.json()

# Reconstruct proof
proof = ExistenceProof(
    key=bytes.fromhex(proof_data['key']),
    value_hash=bytes.fromhex(proof_data['value_hash']),
    siblings=[bytes.fromhex(s) for s in proof_data['siblings']],
    root_hash=bytes.fromhex(proof_data['root_hash'])
)

# Verify proof offline
assert verify_proof(proof) is True

# Verify shard header signature
header = proof_data['shard_header']
verify_key = nacl.signing.VerifyKey(bytes.fromhex(header['pubkey']))
is_valid = verify_header(
    {
        'shard_id': header['shard_id'],
        'root_hash': header['root_hash'],
        'timestamp': header['timestamp'],
        'previous_header_hash': header['previous_header_hash'],
        'header_hash': header['header_hash']
    },
    header['signature'],
    verify_key
)
assert is_valid is True

print("✓ Proof and signature verified offline!")
```

## Security Properties

### Guaranteed by Design

1. **Append-Only Ledger**: No records can be deleted or modified
2. **Tamper Evidence**: Any modification breaks cryptographic chain
3. **Deterministic Replay**: Ledger can be replayed to verify all hashes
4. **Offline Verification**: No trust in API server required
5. **Transparent History**: All historical states are preserved

### Not Guaranteed

1. **Completeness**: System doesn't prove all records were published
2. **Availability**: API server may be down (but data is verifiable offline)
3. **Privacy**: All data is public by design

## Storage Layer Freeze

The storage layer (`storage/postgres.py` and `migrations/001_init_schema.sql`) is **FROZEN** as of Phase 0.5.

Any modifications require:
- Protocol version bump
- New migration script
- Full audit trail

## Next Steps

Phase 0.5 is complete when:
- [x] Database schema is append-only
- [x] Storage layer supports all operations
- [x] API endpoints return offline-verifiable data
- [x] End-to-end tests pass
- [x] CI pipeline is green

## Phase 1+ Features (Not Included in v1.0)

The following features are planned for Phase 1+ and are **not implemented in v1.0**:

- **Guardian replication protocol (Phase 1+ only)** — M-of-N multi-node replication with signed acknowledgments
- **BFT finality consensus** — Byzantine fault tolerance and fork detection
- **JavaScript/TypeScript client library** — Browser-based verification
- **Privacy-preserving proofs** — Zero-knowledge proof extensions

**v1.0 Scope:** Single-node operation with Ed25519 signatures, Sparse Merkle Forest, and offline verifiable proofs.

See `docs/04_ledger_protocol.md` for detailed annotations on which features are Phase 1+.
