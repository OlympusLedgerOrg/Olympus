# Operations Guide

This document provides operational guidance for deploying, monitoring, and verifying Olympus v1.0.

## v1.0 Scope

Olympus v1.0 provides single-node operation with cryptographic guarantees:
- ✅ Ed25519 signatures on shard headers
- ✅ Append-only ledger with hash-chain integrity
- ✅ Sparse Merkle Forest for efficient proofs
- ✅ PostgreSQL persistence
- ✅ Public audit API
- ✅ Offline verification

**Not included in v1.0:**
- ❌ Multi-node Guardian replication (Phase 1+)
- ❌ Byzantine fault tolerance (Phase 1+)
- ❌ Fork detection and resolution (Phase 1+)

---

## Database Setup

### Requirements

- **PostgreSQL 16+** (production only)
- Minimum 2GB RAM for moderate workloads
- SSD storage recommended for performance

### Initial Setup

1. **Create Database**
   ```bash
   createdb olympus
   ```

2. **Set Database URL**
   ```bash
   export DATABASE_URL="postgresql://user:password@localhost:5432/olympus"
   ```

3. **Run Migrations**
   ```bash
   psql $DATABASE_URL -f migrations/001_initial_schema.sql
   ```

### Schema Verification

Verify the schema is correctly installed:

```sql
-- Check that all four tables exist
SELECT table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_name IN ('smt_leaves', 'smt_nodes', 'shard_headers', 'ledger_entries');

-- Verify table constraints
SELECT constraint_name, constraint_type 
FROM information_schema.table_constraints 
WHERE table_schema = 'public';
```

Expected tables:
- `smt_leaves` - Sparse Merkle Tree leaf nodes
- `smt_nodes` - Sparse Merkle Tree internal nodes
- `shard_headers` - Signed shard root commitments with chain linkage
- `ledger_entries` - Global append-only ledger

All tables are **append-only** (no UPDATE or DELETE operations).

### Database Maintenance

**Backups:**
```bash
# Full backup
pg_dump $DATABASE_URL > olympus_backup_$(date +%Y%m%d_%H%M%S).sql

# Compressed backup
pg_dump $DATABASE_URL | gzip > olympus_backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

**Restore:**
```bash
psql $DATABASE_URL < olympus_backup.sql
```

**Monitoring:**
```sql
-- Check shard counts
SELECT shard_id, COUNT(*) as header_count 
FROM shard_headers 
GROUP BY shard_id;

-- Check ledger integrity
SELECT COUNT(*) as total_entries 
FROM ledger_entries;

-- Check storage size
SELECT 
  schemaname,
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

---

## API Deployment

### Production API

The production API is in `api/app.py` and requires PostgreSQL.

**Start the API:**
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/olympus"
python run_api.py
```

**Environment Variables:**
- `DATABASE_URL` - PostgreSQL connection string (REQUIRED)
- `PORT` - API port (default: 8000)
- `HOST` - Bind host (default: 127.0.0.1)

**Production Deployment:**
```bash
# Using uvicorn directly
uvicorn api.app:app --host 0.0.0.0 --port 8000 --workers 4

# With environment variables
DATABASE_URL="postgresql://user:password@localhost:5432/olympus" \
  uvicorn api.app:app --host 0.0.0.0 --port 8000 --workers 4
```

### Test API (Development Only)

The test API is in `app/main.py` and uses in-memory storage.

⚠️ **WARNING**: The test API does NOT persist data and is NOT suitable for production.

**Start test API:**
```bash
uvicorn app.main:app --reload
```

---

## API Endpoints

All endpoints are read-only and return data for offline verification.

### Health Check

```bash
GET /status
```

Returns:
```json
{
  "status": "ok",
  "global_root": "a1b2c3..."
}
```

### List Shards

```bash
GET /shards
```

Returns list of all shard IDs:
```json
{
  "shards": ["shard1", "shard2"]
}
```

### Get Latest Shard Header

```bash
GET /shards/{shard_id}/header/latest
```

Returns the latest signed shard header:
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

### Get Existence/Non-Existence Proof

```bash
GET /shards/{shard_id}/proof/existence?key={hex_key}&version={version}
GET /shards/{shard_id}/proof/nonexistence?key={hex_key}&version={version}
```

Both endpoints return the same unified proof structure:
```json
{
  "exists": true,
  "key": "hex_key...",
  "value_hash": "hex_hash...",
  "siblings": ["sibling1...", "sibling2..."],
  "root_hash": "root..."
}
```

**Important**: Both endpoints always return HTTP 200. The `exists` field indicates whether the key exists. Non-existence is a valid cryptographic response, not an error.

### Get Global Roots

```bash
GET /roots
```

Returns:
```json
{
  "global_root": "forest_root_hash...",
  "shards": {
    "shard1": "root_hash1...",
    "shard2": "root_hash2..."
  }
}
```

---

## Signing Key Management

### Generate Signing Key

```python
import nacl.signing

# Generate new signing key
signing_key = nacl.signing.SigningKey.generate()

# Get 32-byte seed (store this securely!)
seed = bytes(signing_key)

# Get public key
verify_key = signing_key.verify_key
pubkey_hex = verify_key.encode().hex()

print(f"Seed (hex): {seed.hex()}")
print(f"Public key (hex): {pubkey_hex}")
```

### Load Signing Key from Seed

```python
import nacl.signing

# Load from stored seed
seed_hex = "your_32_byte_seed_in_hex"
seed = bytes.fromhex(seed_hex)
signing_key = nacl.signing.SigningKey(seed)
```

**Security:**
- Store seed in secure key management system (HSM, vault, etc.)
- Never commit signing keys to version control
- Use separate keys for different environments (dev, staging, prod)
- Rotate keys periodically (Phase 1+ will support key rotation)

---

## Verification Procedures

### Verify Shard Header Signature

```python
from protocol.shards import verify_header
import nacl.signing
import nacl.encoding

# Get header from API
header = {
    "shard_id": "shard1",
    "root_hash": "...",
    "timestamp": "2024-01-01T00:00:00Z",
    "previous_header_hash": "",
    "header_hash": "..."
}

# Get signature and pubkey
signature = "signature_hex..."
pubkey_hex = "pubkey_hex..."

# Verify
verify_key = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
is_valid = verify_header(header, signature, verify_key)

print(f"Signature valid: {is_valid}")
```

### Verify Existence Proof

```python
from protocol.ssmf import verify_proof, ExistenceProof

# Get proof from API
proof_data = {
    "exists": True,
    "key": "key_hex...",
    "value_hash": "value_hex...",
    "siblings": ["sibling1...", "sibling2..."],
    "root_hash": "root..."
}

# Convert to proof object
proof = ExistenceProof(
    key=bytes.fromhex(proof_data["key"]),
    value_hash=bytes.fromhex(proof_data["value_hash"]),
    siblings=[bytes.fromhex(s) for s in proof_data["siblings"]],
    root_hash=bytes.fromhex(proof_data["root_hash"])
)

# Verify
is_valid = verify_proof(proof)
print(f"Proof valid: {is_valid}")
```

### Verify Ledger Chain Integrity

```python
from protocol.ledger import Ledger, LedgerEntry

# Load entries from database or API
ledger = Ledger()
for entry_data in entries:
    entry = LedgerEntry.from_dict(entry_data)
    ledger.entries.append(entry)

# Verify entire chain
is_valid = ledger.verify_chain()
print(f"Chain valid: {is_valid}")
```

---

## Monitoring

### Key Metrics

1. **Shard Count**
   ```sql
   SELECT COUNT(DISTINCT shard_id) FROM shard_headers;
   ```

2. **Total Records**
   ```sql
   SELECT COUNT(*) FROM smt_leaves;
   ```

3. **Ledger Entries**
   ```sql
   SELECT COUNT(*) FROM ledger_entries;
   ```

4. **Latest Header per Shard**
   ```sql
   SELECT shard_id, MAX(seq) as latest_seq
   FROM shard_headers
   GROUP BY shard_id;
   ```

### Health Checks

Monitor these endpoints:
- `GET /status` - Should return 200 with valid global_root
- `GET /shards` - Should return list of shards
- Database connectivity - Verify PostgreSQL connection

### Alerts

Set up alerts for:
- API endpoint failures
- Database connection failures
- Disk space usage (PostgreSQL data directory)
- Signature verification failures (indicates tampering)

---

## Troubleshooting

### API Won't Start

**Error: "DATABASE_URL not set"**
```bash
export DATABASE_URL="postgresql://user:password@localhost:5432/olympus"
```

**Error: "relation 'shard_headers' does not exist"**
- Run migrations: `psql $DATABASE_URL -f migrations/001_initial_schema.sql`

### Signature Verification Fails

1. Verify public key matches the signing key used
2. Check that header_hash is correct (recompute using canonical JSON)
3. Ensure header fields match exactly (including whitespace in canonical JSON)

### Proof Verification Fails

1. Verify root_hash matches the current shard root
2. Check that all sibling hashes are 32 bytes
3. Ensure key is 32 bytes
4. Verify proof was generated for correct version

### Database Performance

If queries are slow:
1. Add indexes on frequently queried columns
2. Increase PostgreSQL shared_buffers
3. Enable query logging to identify slow queries
4. Consider partitioning large tables (Phase 1+)

---

## CLI Usage

### Check Installation

```bash
# Verify Python dependencies
pip show blake3 PyNaCl pydantic psycopg

# Verify PostgreSQL connection
psql $DATABASE_URL -c "SELECT version();"
```

### Development Workflow

1. **Start Database**
   ```bash
   # Start PostgreSQL (if not running)
   sudo systemctl start postgresql
   ```

2. **Run Migrations**
   ```bash
   psql $DATABASE_URL -f migrations/001_initial_schema.sql
   ```

3. **Start API**
   ```bash
   export DATABASE_URL="postgresql://user:password@localhost:5432/olympus"
   python run_api.py
   ```

4. **Run Tests**
   ```bash
   pytest tests/
   ```

---

## Security Considerations

### v1.0 Security Model

**What v1.0 Provides:**
- Cryptographic integrity of individual records
- Tamper-evident append-only log
- Offline verification without trusting the server
- Ed25519 signature verification

**What v1.0 Does NOT Provide:**
- Protection against Byzantine nodes (Phase 1+)
- Multi-node replication guarantees (Phase 1+)
- Fork detection across multiple nodes (Phase 1+)
- Automatic key rotation (Phase 1+)

### Threat Model

For v1.0, Olympus assumes:
- The node operator is trusted (single-node operation)
- The signing key is kept secure
- The database is not tampered with
- Network communication is over TLS (not handled by Olympus)

Multi-node Byzantine fault tolerance is planned for Phase 1+.

See `docs/01_threat_model.md` for complete threat model documentation.

---

## Backup and Disaster Recovery

### Backup Strategy

1. **Daily Full Backups**
   ```bash
   pg_dump $DATABASE_URL | gzip > olympus_$(date +%Y%m%d).sql.gz
   ```

2. **Continuous Archiving** (WAL archiving)
   - Configure PostgreSQL WAL archiving
   - Store WAL files in secure off-site location

3. **Signing Key Backup**
   - Store signing key seed in HSM or secure vault
   - Keep offline backup in secure location
   - Document key recovery procedures

### Recovery Procedures

**Database Restore:**
```bash
# Stop API
pkill -f "uvicorn api.app"

# Restore database
psql $DATABASE_URL < olympus_backup.sql

# Restart API
python run_api.py
```

**Verify Integrity After Restore:**
```python
from protocol.ledger import Ledger
# Load all entries and verify chain
ledger = Ledger()
# ... load entries ...
assert ledger.verify_chain()
```

---

## Upgrading

### v1.0 to Phase 1+ (Future)

Migration path from v1.0 to Phase 1+ will include:
- Multi-node replication setup
- Guardian node configuration
- Fork detection deployment
- Byzantine consensus integration

**Note**: Phase 1+ upgrade procedures will be documented when available.

### Database Migrations

When schema changes are required:
1. Create new migration file in `migrations/`
2. Test migration on staging environment
3. Backup production database
4. Apply migration
5. Verify integrity

---

## References

- **Protocol Specification**: `docs/04_ledger_protocol.md`
- **Database Strategy**: `docs/08_database_strategy.md`
- **Threat Model**: `docs/01_threat_model.md`
- **API Documentation**: FastAPI docs at `http://localhost:8000/docs`
