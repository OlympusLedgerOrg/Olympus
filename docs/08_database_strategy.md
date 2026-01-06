# Database Strategy

## Overview

Olympus uses **PostgreSQL** as its **only production database backend**. SQLite is supported **exclusively for lightweight testing** of proof generation logic.

This document provides an unambiguous specification of:

1. **Production database requirements** (PostgreSQL 16+)
2. **Transaction boundaries and guarantees**
3. **Table-level persistence semantics**
4. **Test strategy alignment**
5. **Code path consistency**

**Purpose**: Eliminate ambiguity about database usage for v1.0 release. An external auditor should be able to understand the complete database model without reading commit history.

---

## Production Backend: PostgreSQL

### Authoritative Statement

**PostgreSQL 16+ is the ONLY supported production database for Olympus.**

All production code MUST use `storage.postgres.StorageLayer`. No other database backend is supported, tested, or recommended for production deployments.

### Rationale

PostgreSQL is required for production because:

1. **ACID Guarantees**: Full transaction support ensures atomic append operations across all tables
2. **Concurrent Access**: Multiple processes can safely read/write simultaneously without lock contention
3. **Performance at Scale**: Efficiently handles millions of ledger entries and tree nodes with proper indexing
4. **Schema Enforcement**: Strong typing, BYTEA for cryptographic hashes, and CHECK constraints prevent data corruption
5. **Operational Maturity**: Battle-tested in production environments worldwide with well-understood failure modes

### Schema Tables

The Postgres schema is defined in `/migrations/001_init_schema.sql` and consists of four append-only tables:

#### `smt_leaves`
- **Purpose**: Sparse Merkle Tree leaf nodes (key-value pairs)
- **Primary Key**: `(shard_id, key, version)` - prevents duplicate records
- **Constraints**: 32-byte key and value_hash enforced by CHECK constraints
- **Append-Only**: INSERT only, no UPDATE or DELETE
- **Transaction Boundary**: Inserted within `append_record()` transaction

#### `smt_nodes`
- **Purpose**: Sparse Merkle Tree internal nodes (path to hash mappings)
- **Primary Key**: `(shard_id, level, index)` - prevents duplicate nodes at same position
- **Constraints**: Level ∈ [0, 256], 32-byte hash enforced by CHECK constraints
- **Append-Only**: INSERT only, no UPDATE or DELETE
- **Transaction Boundary**: Inserted within `append_record()` transaction
- **Note**: Duplicate INSERT attempts are silently ignored (node already exists)

#### `shard_headers`
- **Purpose**: Signed shard root commitments with chain linkage
- **Primary Key**: `(shard_id, seq)` - monotonically increasing sequence numbers
- **Constraints**: 32-byte root, header_hash, and signature enforced by CHECK constraints
- **Append-Only**: INSERT only, no UPDATE or DELETE
- **Transaction Boundary**: Inserted within `append_record()` transaction
- **Chain Linkage**: `previous_header_hash` links to prior header, empty for genesis

#### `ledger_entries`
- **Purpose**: Append-only ledger chain linking record hashes to shard roots
- **Primary Key**: `(shard_id, seq)` - monotonically increasing sequence numbers
- **Constraints**: 32-byte entry_hash and prev_entry_hash enforced by CHECK constraints
- **Append-Only**: INSERT only, no UPDATE or DELETE
- **Transaction Boundary**: Inserted within `append_record()` transaction
- **Chain Linkage**: `prev_entry_hash` links to prior entry, empty for genesis

### Transaction Semantics

All write operations in Olympus are **transactionally consistent** and **atomic**:

#### Write Transaction (`append_record`)

A single call to `storage.append_record()` performs the following operations **atomically**:

```
BEGIN TRANSACTION;
  -- 1. Load current tree state (SELECT from smt_leaves, smt_nodes)
  -- 2. Verify key doesn't exist
  -- 3. Update in-memory tree
  -- 4. INSERT new leaf into smt_leaves
  -- 5. INSERT/UPDATE affected nodes in smt_nodes
  -- 6. SELECT MAX(seq)+1 for next shard header sequence
  -- 7. INSERT new shard header into shard_headers
  -- 8. SELECT MAX(seq)+1 for next ledger entry sequence
  -- 9. INSERT new ledger entry into ledger_entries
COMMIT;
```

**Guarantees**:
- All four tables are updated atomically or none are updated (rollback on exception)
- Sequence numbers are consistent (SELECT MAX inside transaction prevents race conditions)
- Chain linkage is preserved (previous hashes are consistent within transaction)
- No partial updates visible to other connections

**Isolation Level**: PostgreSQL default (READ COMMITTED)
- Sufficient for append-only workloads
- `SELECT MAX(seq)+1` pattern prevents sequence number collisions
- Explicit locks not required due to append-only semantics

#### Read Transactions

All read operations (`get_proof`, `get_latest_header`, `get_ledger_tail`, etc.) are **read-only** and do not require explicit commits:

```
BEGIN TRANSACTION (implicit);
  -- SELECT queries only
  -- No writes, no commit needed
ROLLBACK (implicit on context exit);
```

**Guarantees**:
- Consistent snapshot of data at transaction start time
- No interference with concurrent writes
- Automatic rollback on context manager exit (cleanup)

### Production Usage

```python
from storage.postgres import StorageLayer

# Production connection string (MUST include explicit credentials)
DATABASE_URL = 'postgresql://olympus:olympus@localhost:5432/olympus'
storage = StorageLayer(DATABASE_URL)

# Initialize schema (idempotent, safe to call multiple times)
storage.init_schema()

# Append a record (atomic transaction across all tables)
root, proof, header, signature, ledger_entry = storage.append_record(
    shard_id="documents",
    record_type="document",
    record_id="doc123",
    version=1,
    value_hash=document_hash,  # 32-byte hash
    signing_key=signing_key    # Ed25519 signing key
)

# All queries are read-only (no transaction management needed)
proof = storage.get_proof("documents", "document", "doc123", 1)
header = storage.get_latest_header("documents")
entries = storage.get_ledger_tail("documents", n=10)
```

---

## Two FastAPI Applications: Production vs Testing

Olympus contains **two separate FastAPI applications** that serve different purposes:

### Production API: `api/app.py`

**Purpose**: Production-ready public audit API backed by PostgreSQL

**Database**: Uses `storage.postgres.StorageLayer` (PostgreSQL only)

**Usage**: Run with `run_api.py` script

**Endpoints**:
- `GET /shards` - List all shards
- `GET /shards/{shard_id}/header/latest` - Get latest signed shard header
- `GET /shards/{shard_id}/proof` - Get existence/non-existence proofs
- `GET /ledger/{shard_id}/tail` - Get recent ledger entries

**Environment Variables**:
- `DATABASE_URL` - **Required**, must be PostgreSQL connection string

**Production Deployment**:
```bash
export DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
python run_api.py --host 0.0.0.0 --port 8000
```

### Test API: `app/main.py`

**Purpose**: Lightweight proof testing without database setup

**Database**: Uses `app/state.py` (in-memory SparseMerkleTree, no actual database)

**Usage**: Only for `test_api_proofs.py` tests

**Endpoints**:
- `GET /status` - Health check
- `GET /roots` - Get shard roots
- `GET /shards` - List shards
- `GET /shards/{shard_id}/header/latest` - Get header (minimal)
- `GET /shards/{shard_id}/proof/existence` - Unified proof endpoint
- `GET /shards/{shard_id}/proof/nonexistence` - Unified proof endpoint

**Environment Variables**:
- `OLY_DB_PATH` - Optional, path for in-memory state file (test-only)

**Testing Only**:
```python
# test_api_proofs.py uses this FastAPI app
from app.main import app
client = TestClient(app)
```

### Critical Distinction

| Aspect | Production API (`api/app.py`) | Test API (`app/main.py`) |
|--------|-------------------------------|--------------------------|
| **Database** | PostgreSQL (via `StorageLayer`) | In-memory (via `OlympusState`) |
| **Persistence** | Full ACID transactions | No persistence |
| **Ledger Entries** | Yes, stored in `ledger_entries` table | No |
| **Shard Headers** | Yes, stored and signed in `shard_headers` table | Minimal, not signed |
| **SMT Nodes** | Yes, stored in `smt_nodes` and `smt_leaves` tables | In-memory only |
| **Concurrent Access** | Safe with PostgreSQL | Not supported |
| **Production Use** | ✅ Yes | ❌ No |
| **Testing Use** | ✅ E2E tests (`test_e2e_audit.py`) | ✅ Proof logic tests (`test_api_proofs.py`) |

**Key Insight**: `app/main.py` does NOT use a database. The `db_path` parameter in `OlympusState` is vestigial and unused. The in-memory `SparseMerkleTree` instances in `app/state.py` are ephemeral and only used for proof generation testing.

---

## Test Backend: SQLite (Limited Use)

### Authoritative Statement

**SQLite is NOT a supported database backend for Olympus.**

SQLite is used **only** as a placeholder in test configuration for `test_api_proofs.py`, but even there, **no actual database operations occur**. The test API (`app/main.py`) uses in-memory data structures (`SparseMerkleTree`) and does not perform database reads or writes.

### Why SQLite Appears in Tests

The `OLY_DB_PATH` environment variable in `test_api_proofs.py` exists for **API compatibility only**:

```python
# This file path is NEVER USED for actual database operations
with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
    db_path = f.name
os.environ['OLY_DB_PATH'] = db_path
```

The test API (`app/main.py`) creates `OlympusState(db_path)`, but this path is **ignored**. All state is held in-memory in Python dictionaries and `SparseMerkleTree` instances.

### Limitations

SQLite is **NOT suitable for production** because:

- No true concurrent writes (locks entire database file)
- Weaker type enforcement compared to PostgreSQL
- Cannot guarantee the same ACID semantics under load
- **Not tested for the full production storage layer**
- **Not used by any production code paths**

### When SQLite References are Acceptable

SQLite file paths are acceptable **only** in:
- `test_api_proofs.py` test configuration (vestigial, not actually used)
- Never in production code
- Never in code that imports `storage.postgres`

---

## Test Strategy

### PostgreSQL Tests (Production Code Paths)

**Files**: `test_e2e_audit.py`, `test_storage.py`

**Database**: PostgreSQL (via `storage.postgres.StorageLayer`)

These tests validate the **full production stack**:
- PostgreSQL storage layer (`storage/postgres.py`)
- Ledger chain integrity (atomic transactions across `ledger_entries`)
- Shard header signing and chain linkage (`shard_headers`)
- SMT node persistence (`smt_nodes`, `smt_leaves`)
- API proof endpoints backed by PostgreSQL (`api/app.py`)

**Setup**:
```bash
export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
pytest tests/test_e2e_audit.py tests/test_storage.py -v
```

**What These Tests Validate**:
- ✅ Transaction atomicity across all four tables
- ✅ Sequence number generation (`SELECT MAX(seq)+1` pattern)
- ✅ Chain linkage preservation (prev_entry_hash, previous_header_hash)
- ✅ Constraint enforcement (32-byte hashes, key lengths)
- ✅ Concurrent access safety (multiple connections)
- ✅ Production API endpoints (`api/app.py`)

**Test Marker**: `@pytest.mark.postgres`

### In-Memory Proof Tests (Proof Logic Only)

**Files**: `test_api_proofs.py`

**Database**: None (in-memory `SparseMerkleTree` via `app/state.py`)

These tests validate **proof generation logic only**:
- Unified existence/non-existence proofs
- API endpoint behavior (200 vs 404, error handling)
- Proof structure validation (siblings, root_hash fields)
- **Does NOT test production storage layer**
- **Does NOT test transaction semantics**
- **Does NOT test persistence**

**Setup**: Automatic via `setup_test_db()` fixture (creates unused SQLite file path)

**What These Tests Validate**:
- ✅ `protocol.ssmf.SparseMerkleTree` proof generation
- ✅ `app/main.py` proof endpoint responses
- ✅ Unified proof structure (exists field)
- ❌ Does NOT validate PostgreSQL storage layer
- ❌ Does NOT validate transaction semantics
- ❌ Does NOT validate persistence

**Test Marker**: No marker (runs in default test suite)

### Test Coverage Matrix

| Test File | Database | Code Path | Validates |
|-----------|----------|-----------|-----------|
| `test_storage.py` | PostgreSQL | `storage/postgres.py` | Storage layer, transactions, persistence |
| `test_e2e_audit.py` | PostgreSQL | `storage/postgres.py` + `api/app.py` | Full production stack, API endpoints |
| `test_api_proofs.py` | None (in-memory) | `app/state.py` + `app/main.py` | Proof generation logic only |

### Critical Testing Insights

1. **Production Storage Validation**: Only `test_storage.py` and `test_e2e_audit.py` validate the production storage layer
2. **Transaction Testing**: Only PostgreSQL tests validate transaction boundaries and atomicity
3. **API Testing**: Both `test_e2e_audit.py` (production API) and `test_api_proofs.py` (test API) test HTTP endpoints, but **different APIs**
4. **Proof Logic Testing**: `test_api_proofs.py` tests proof generation in isolation without storage layer complexity

---

## CI Configuration

The CI pipeline in `.github/workflows/ci.yml` uses **PostgreSQL exclusively** for production code path validation:

```yaml
services:
  postgres:
    image: postgres:16
    env:
      POSTGRES_USER: olympus
      POSTGRES_PASSWORD: olympus
      POSTGRES_DB: olympus
```

**Environment Variables**:
```yaml
env:
  DATABASE_URL: postgresql://olympus:olympus@localhost:5432/olympus
  TEST_DATABASE_URL: postgresql://olympus:olympus@localhost:5432/olympus
```

**Test Execution**:
```bash
# Fast lane: In-memory proof tests (no database)
pytest tests/ -v --tb=short -m "not postgres"

# Postgres lane: E2E and storage tests (production code paths)
pytest tests/ -v --tb=short -m "postgres"
```

**Why PostgreSQL in CI?**

1. **Production Parity**: Tests run against the same database used in production
2. **Full Coverage**: E2E tests require PostgreSQL to validate storage layer
3. **Integration Testing**: Verifies schema, transactions, and concurrent access patterns
4. **Correctness**: Ensures append-only semantics, chain linkage, and constraint enforcement

**Note**: `test_api_proofs.py` still runs in the "fast lane" (no postgres marker) because it tests proof logic independently of the storage layer.

---

## Code Path Consistency

### Production Code Paths (PostgreSQL Required)

**Modules**:
- `storage/postgres.py` - Storage layer implementation
- `api/app.py` - Production audit API
- `run_api.py` - Production server entrypoint

**Database Operations**:
- ✅ Transactional writes to all four tables
- ✅ Chain linkage enforcement
- ✅ Signature generation and storage
- ✅ Concurrent access safety

**Testing**:
- ✅ `test_storage.py` (validates storage layer)
- ✅ `test_e2e_audit.py` (validates full stack)

### Test-Only Code Paths (In-Memory)

**Modules**:
- `app/state.py` - In-memory state manager (no database)
- `app/main.py` - Test API (no database)

**Database Operations**:
- ❌ No database reads or writes
- ❌ No persistence
- ❌ No transaction management
- ❌ No concurrent access support

**Testing**:
- ✅ `test_api_proofs.py` (validates proof logic only)

### CLI Tools (No Database)

**Modules**:
- `tools/canonicalize_cli.py` - Canonicalization utility
- `tools/verify_cli.py` - Proof verification utility
- `tools/validate_schemas.py` - Schema validation

**Database Operations**:
- ❌ No database required
- ✅ Operate on files or stdin/stdout
- ✅ Purely cryptographic operations

**Philosophy**: CLI tools perform **offline verification** and do not require database access. This ensures third-party auditors can verify proofs without trusting Olympus infrastructure.

---

## Decision Matrix

| Context | Database | Code Path | Why |
|---------|----------|-----------|-----|
| **Production deployment** | PostgreSQL | `storage/postgres.py` + `api/app.py` | ACID, concurrency, scale, maturity |
| **E2E tests** | PostgreSQL | `storage/postgres.py` + `api/app.py` | Production parity, full stack validation |
| **Storage tests** | PostgreSQL | `storage/postgres.py` | Transaction semantics, persistence validation |
| **Proof logic tests** | None (in-memory) | `app/state.py` + `app/main.py` | Fast, isolated proof generation testing |
| **Local development** | PostgreSQL | `storage/postgres.py` + `api/app.py` | Match production environment |
| **Offline verification** | None | `tools/*.py` | Cryptographic verification without database |
| **CLI tools** | None | `tools/*.py` | Operate on files, no persistence needed |

---

## Contributor Guidance

### When to Use PostgreSQL

Use PostgreSQL when:
- Implementing storage layer features (`storage/postgres.py`)
- Testing ledger chain logic
- Testing concurrent access patterns
- Running end-to-end audit flows
- Any code that imports `storage.postgres`
- Developing production API features (`api/app.py`)
- Testing transaction boundaries
- Testing persistence and recovery

### When In-Memory State is Acceptable

In-memory state (`app/state.py`) is acceptable for:
- Unit testing proof generation logic (`protocol/ssmf.py`)
- Testing proof endpoint response structure
- Testing unified proof behavior (exists field)
- **Never for production code**
- **Never for features requiring persistence**
- **Never for features requiring concurrent access**

### When No Database is Needed

No database required for:
- CLI tools (`tools/*.py`)
- Offline verification
- Canonicalization operations
- Schema validation
- Pure cryptographic operations

### Setting Up PostgreSQL Locally

```bash
# Install PostgreSQL 16+
# On macOS:
brew install postgresql@16
brew services start postgresql@16

# On Ubuntu:
sudo apt install postgresql-16
sudo systemctl start postgresql

# Create database
createdb olympus

# Set environment variable
export DATABASE_URL='postgresql://yourusername@localhost:5432/olympus'

# Initialize schema
python -c "from storage.postgres import StorageLayer; StorageLayer('$DATABASE_URL').init_schema()"

# Run production API
python run_api.py
```

---

## Version 1.0 Requirements

For Olympus v1.0 release, the following requirements MUST be satisfied:

### Database Backend ✅
- ✅ PostgreSQL 16+ is the **only documented production backend**
- ✅ All production code uses `storage/postgres.py`
- ✅ Schema defined in `/migrations/001_init_schema.sql`
- ✅ Four append-only tables: `smt_leaves`, `smt_nodes`, `shard_headers`, `ledger_entries`

### Transaction Guarantees ✅
- ✅ All writes are atomic across all four tables
- ✅ `append_record()` performs transactional INSERT to all tables or rollback
- ✅ Sequence numbers generated inside transaction (`SELECT MAX(seq)+1`)
- ✅ Chain linkage preserved (prev_entry_hash, previous_header_hash)
- ✅ Read-only operations use implicit transactions

### Code Path Clarity ✅
- ✅ Two FastAPI applications clearly documented:
  - Production: `api/app.py` (PostgreSQL via `StorageLayer`)
  - Testing: `app/main.py` (in-memory via `OlympusState`)
- ✅ Production API requires `DATABASE_URL` environment variable
- ✅ Test API uses in-memory state (no actual database operations)
- ✅ CLI tools are database-free (offline verification)

### Test Strategy Alignment ✅
- ✅ E2E tests validate production storage layer (`test_e2e_audit.py`, `test_storage.py`)
- ✅ Proof tests validate in-memory logic only (`test_api_proofs.py`)
- ✅ CI runs against PostgreSQL for production code paths
- ✅ Test markers distinguish PostgreSQL tests (`@pytest.mark.postgres`)

### Documentation Completeness ✅
- ✅ Database strategy explicitly documented (this file)
- ✅ Transaction boundaries clearly specified
- ✅ All tables and constraints documented
- ✅ Production vs. test usage unambiguous
- ✅ External reviewer can understand DB model without commit history

### Unsupported/Deprecated ⚠️
- ⚠️ SQLite support is **test-only** and clearly marked as such
- ⚠️ In-memory state (`app/state.py`) is **test-only** and not for production
- ⚠️ `OLY_DB_PATH` environment variable is vestigial (not used for actual DB operations)

---

## Future Considerations

Potential future database enhancements (post-v1.0):

### Horizontal Scaling
- **CockroachDB**: PostgreSQL-compatible, horizontally scalable distributed SQL
- **PostgreSQL + Citus**: Distributed PostgreSQL with sharding
- **Read Replicas**: PostgreSQL streaming replication for auditor nodes

### Time-Series Optimization
- **TimescaleDB**: PostgreSQL extension optimized for time-series data (ledger entries)
- **Partitioning**: PostgreSQL native table partitioning by shard_id or timestamp

### High Availability
- **PostgreSQL HA**: Patroni + etcd for automatic failover
- **Multi-Region**: PostgreSQL logical replication across regions

### Not Planned
- ❌ **MySQL**: Incompatible BYTEA/BLOB semantics, different constraint model
- ❌ **MongoDB**: Document model doesn't fit append-only ledger with strict schema
- ❌ **Promoting SQLite to production**: Concurrency limitations, weaker guarantees
- ❌ **Other backends**: Olympus v1.0 is PostgreSQL-only by design

---

## Frequently Asked Questions

### Q: Can I use SQLite for local development?

**A: No.** Local development MUST use PostgreSQL to match production. SQLite does not provide the same transaction guarantees, constraint enforcement, or concurrent access semantics. Use Docker or a local PostgreSQL installation.

### Q: What about embedded use cases?

**A: Not supported in v1.0.** Olympus v1.0 is designed for server deployments with PostgreSQL. Embedded use cases may be considered post-v1.0 but are explicitly out of scope for the initial release.

### Q: Can I use a different PostgreSQL version?

**A: PostgreSQL 16+ is required.** Earlier versions may work but are not tested. PostgreSQL 16 provides specific features and guarantees that Olympus relies on (BYTEA semantics, CHECK constraints, concurrent indexing).

### Q: Why does `test_api_proofs.py` mention SQLite if it's not used?

**A: Historical artifact.** The `OLY_DB_PATH` environment variable exists for API compatibility but is **not used** for actual database operations. The test API (`app/main.py`) uses in-memory `SparseMerkleTree` instances. This will be cleaned up in a future refactor but does not affect correctness.

### Q: What if I need to test without PostgreSQL?

**A: Use unit tests.** Protocol-level tests (`test_canonicalization.py`, `test_hash_functions.py`, etc.) do not require a database. For proof generation testing, use `test_api_proofs.py` which tests in-memory proof logic. For production storage layer testing, PostgreSQL is **required**.

### Q: Are there any database migrations?

**A: Yes.** Database schema is defined in `/migrations/001_init_schema.sql`. Future migrations will follow the pattern `00X_description.sql`. The `init_schema()` method is idempotent (safe to call multiple times) and will be updated to run all migrations in sequence.

### Q: What about database backups?

**A: Standard PostgreSQL tooling.** Use `pg_dump` for backups, `pg_restore` for recovery. Olympus does not provide custom backup tooling in v1.0. Append-only semantics make backups straightforward (no complex snapshot consistency requirements).

### Q: Can I query the database directly?

**A: Yes, for auditing.** The database schema is public and documented. Auditors can query tables directly using standard PostgreSQL tools. However, **write operations MUST go through `StorageLayer`** to ensure transaction consistency, chain linkage, and constraint enforcement.

---

## References

### Code
- Production storage: `/storage/postgres.py`
- Production API: `/api/app.py`
- Test API: `/app/main.py`
- In-memory state: `/app/state.py`

### Schema
- Schema definition: `/migrations/001_init_schema.sql`
- Table constraints and indexes defined inline

### Tests
- E2E tests: `/tests/test_e2e_audit.py`
- Storage tests: `/tests/test_storage.py`
- Proof tests: `/tests/test_api_proofs.py`

### Documentation
- Overview: `/docs/00_overview.md`
- Ledger protocol: `/docs/04_ledger_protocol.md`
- Phase 0.5 plan: `/docs/PHASE_05.md`
- Schema alignment: `/docs/SCHEMA_ALIGNMENT_RESOLUTION.md`

### Configuration
- CI workflow: `/.github/workflows/ci.yml`
- Project config: `/pyproject.toml`
- Dependencies: `/requirements.txt`, `/requirements-dev.txt`

---

## Revision History

- **2026-01-06**: Enhanced with explicit transaction boundaries, two-API clarity, table-level documentation, and v1.0 requirements
- **Initial version**: Basic PostgreSQL vs SQLite distinction
