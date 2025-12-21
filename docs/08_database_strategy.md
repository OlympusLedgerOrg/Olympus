# Database Strategy

## Overview

Olympus uses **PostgreSQL** as its production database backend and supports **SQLite** for lightweight testing only. This document clarifies the rationale, usage contexts, and testing strategy for both databases.

---

## Production Backend: PostgreSQL

### Rationale

PostgreSQL is the **only supported production database** for Olympus for these reasons:

1. **ACID Guarantees**: Full transaction support ensures atomic append operations
2. **Concurrent Access**: Multiple processes can safely read/write simultaneously
3. **Performance at Scale**: Efficiently handles millions of ledger entries and tree nodes
4. **Schema Enforcement**: Strong typing and constraints prevent data corruption
5. **Operational Maturity**: Battle-tested in production environments worldwide

### Schema

The Postgres schema is defined in `/migrations/001_init_schema.sql` and implements:

- **Append-only tables**: No UPDATE or DELETE operations
- **Explicit sequencing**: `SELECT MAX(seq)+1` pattern prevents race conditions
- **Hash integrity**: All cryptographic hashes stored as 32-byte BYTEA
- **Chain linkage**: Foreign keys and constraints enforce ledger chain invariants

### Usage

```python
from storage.postgres import StorageLayer

# Production connection string
storage = StorageLayer('postgresql://user:pass@localhost:5432/olympus')
storage.init_schema()

# Append records, create proofs, etc.
root, proof, header, signature, ledger_entry = storage.append_record(...)
```

---

## Test Backend: SQLite (Limited Use)

### Rationale

SQLite is used **only for lightweight API tests** where:

1. **No persistence required**: Tests use in-memory or temporary file databases
2. **Single process**: No concurrent access needed
3. **Simplified setup**: No external database server required
4. **Fast iteration**: Faster test execution for proof verification logic

### Limitations

SQLite is **NOT suitable for production** because:

- No true concurrent writes (locks entire database)
- Weaker type enforcement compared to Postgres
- Cannot guarantee the same ACID semantics under load
- Not tested for the full production storage layer

### Usage

SQLite is used **only in `test_api_proofs.py`** for testing proof endpoint logic:

```python
# Test-only: temporary SQLite database
with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as f:
    db_path = f.name

os.environ['OLY_DB_PATH'] = db_path
```

This tests the **proof generation logic** using `app/state.py`, which is a simplified in-memory state manager, **not** the production storage layer.

---

## Test Strategy

### E2E Tests: PostgreSQL Only

**Files**: `test_e2e_audit.py`, `test_storage.py`

These tests validate the **full production stack**:
- Postgres storage layer (`storage/postgres.py`)
- Ledger chain integrity
- Shard header signing
- API proof endpoints backed by Postgres

**Setup**:
```bash
export TEST_DATABASE_URL='postgresql://olympus:olympus@localhost:5432/olympus'
pytest tests/test_e2e_audit.py -v
```

### API Proof Tests: SQLite

**Files**: `test_api_proofs.py`

These tests validate **proof generation logic only**:
- Unified existence/non-existence proofs
- API endpoint behavior (200 vs 404, error handling)
- Does NOT test production storage layer

**Setup**: Automatic via `setup_test_db()` fixture

---

## CI Configuration

The CI pipeline in `.github/workflows/ci.yml` uses **PostgreSQL exclusively**:

```yaml
services:
  postgres:
    image: postgres:16
    env:
      POSTGRES_USER: olympus
      POSTGRES_PASSWORD: olympus
      POSTGRES_DB: olympus
```

**Why Postgres in CI?**

1. **Production Parity**: Tests run against the same database used in production
2. **Full Coverage**: E2E tests require Postgres to validate storage layer
3. **Integration Testing**: Verifies schema, transactions, and concurrent access patterns

**Note**: `test_api_proofs.py` still uses SQLite even in CI because it tests proof logic independently of the storage layer.

---

## Decision Matrix

| Context | Database | Why |
|---------|----------|-----|
| **Production deployment** | PostgreSQL | ACID, concurrency, scale, maturity |
| **E2E tests** | PostgreSQL | Production parity, full stack validation |
| **API proof logic tests** | SQLite | Fast, no external deps, proof-only testing |
| **Local development** | PostgreSQL | Match production environment |
| **Offline verification** | N/A | Proofs are verified cryptographically without DB |

---

## Contributor Guidance

### When to use PostgreSQL

- Implementing storage layer features
- Testing ledger chain logic
- Testing concurrent access patterns
- Running end-to-end audit flows
- Any code that imports `storage.postgres`

### When SQLite is acceptable

- Testing proof generation logic (`protocol/ssmf.py`)
- Testing API endpoint behavior (status codes, response format)
- Unit tests that don't involve persistence
- **Never for production code**

### Setting up PostgreSQL locally

```bash
# Install PostgreSQL 16+
# On macOS:
brew install postgresql@16

# On Ubuntu:
sudo apt install postgresql-16

# Create database
createdb olympus

# Set environment variable
export DATABASE_URL='postgresql://user:pass@localhost:5432/olympus'

# Initialize schema
python -c "from storage.postgres import StorageLayer; StorageLayer('$DATABASE_URL').init_schema()"
```

---

## Version 1.0 Requirements

For Olympus v1.0 release:

- ✅ PostgreSQL is the **only documented production backend**
- ✅ All production code uses `storage/postgres.py`
- ✅ E2E tests validate Postgres storage layer
- ✅ CI runs against PostgreSQL to ensure production parity
- ✅ Documentation clearly distinguishes test vs. production usage
- ⚠️ SQLite support is **test-only** and clearly marked as such

---

## Future Considerations

Potential future database backends (post-v1.0):

- **CockroachDB**: PostgreSQL-compatible, horizontally scalable
- **TimescaleDB**: PostgreSQL extension optimized for time-series (ledger entries)
- **Read replicas**: PostgreSQL streaming replication for auditor nodes

**Not planned**:
- MySQL (incompatible BYTEA/BLOB semantics)
- MongoDB (document model doesn't fit append-only ledger)
- Promoting SQLite to production (concurrency limitations)

---

## References

- Production storage: `/storage/postgres.py`
- Schema definition: `/migrations/001_init_schema.sql`
- E2E tests: `/tests/test_e2e_audit.py`, `/tests/test_storage.py`
- API proof tests: `/tests/test_api_proofs.py`
- Phase 0.5 docs: `/docs/PHASE_05.md`
