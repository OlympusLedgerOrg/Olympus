# Olympus

Olympus is an append-only public ledger for government documents.

Its purpose:

> Make it cryptographically obvious when public records are created, changed, hidden, or over-redacted.

Olympus is **not** a blockchain, not a DAO, and not a token system.
It is a single-node, PostgreSQL-backed cryptographic audit database built on
deterministic canonicalization, sparse Merkle commitments, Ed25519 signatures,
and hash-chained ledger entries.

---

## What Olympus Guarantees

For any document committed to Olympus:

| Guarantee | Mechanism |
|-----------|-----------|
| Existence at a specific time | BLAKE3 hash committed to ledger before disclosure |
| Tamper detection | Ledger hash-chain; any modification breaks the chain |
| Verifiable redaction integrity | Merkle inclusion proofs tie revealed sections to the committed root |
| Append-only historical state | DB-level triggers block UPDATE and DELETE |
| Shard root authenticity | Ed25519 signature verified on every read |
| External time anchor (optional) | RFC 3161 timestamp token from a public TSA |

Olympus guarantees integrity of what it has observed and committed — nothing more.

---

## What It Does Not Guarantee

- **Completeness** — Olympus cannot force an agency to commit every document.
- **Government honesty** — It detects tampering; it cannot prevent omission.
- **Redaction policy** — It proves redaction is consistent, not that it is correct.
- **Distributed consensus** — Single-node only; federation is planned for Phase 1+.

---

## How It Works

**Pipeline:**

```
Ingest → Canonicalize → Hash → Commit → Prove → Verify
```

Each stage is independently verifiable without trusting Olympus itself.

### 1. Ingest

Documents arrive over the REST API (`POST /ingest/records`). Batch ingestion
is supported with content-hash deduplication.

### 2. Canonicalize

The hardened canonicalizer (`protocol/canonicalizer.py`) provides byte-stable,
idempotent, version-pinned output for four formats:

| Format | Pipeline | Key properties |
|--------|----------|----------------|
| **JSON** | JCS (RFC 8785) | NFC normalization, duplicate-key rejection, `Decimal`-safe numerics |
| **HTML** | lxml NFC + attribute sort | Active-content stripping (`<script>`, `<style>`, etc.) |
| **DOCX** | ZIP sort + XML C14N 1.1 | Volatile metadata stripped; `.bin` / thumbnail skipped |
| **PDF** | pikepdf linearization | Volatile metadata scrubbed, static IDs, LF line endings |

Basic structural canonicalization (key sorting, whitespace normalization) is in
`protocol/canonical.py`. Canonical JSON encoding used for ledger hashing is in
`protocol/canonical_json.py`.

### 3. Hash

All hashing uses **BLAKE3** with domain-separated prefixes
(`OLY:LEAF:V1`, `OLY:NODE:V1`, `OLY:HDR:V1`, `OLY:LEDGER:V1`, …) defined in
`protocol/hashes.py`. The prefixes are protocol-critical — changing them breaks
all historical proofs.

### 4. Commit

Each record is inserted into a **256-height sparse Merkle tree** (SMT) keyed by
a deterministic `record_key(type, id, version)`. A new **shard header** is
created for each write, signed with Ed25519, and chained to the previous header
hash. A **ledger entry** ties the record hash to the shard root and is
hash-chained to the previous ledger entry.

Core data structures persisted in PostgreSQL:

| Table | Contents |
|-------|----------|
| `smt_leaves` | Sparse Merkle leaf nodes (key → value hash) |
| `smt_nodes` | Internal SMT nodes (path → hash) |
| `shard_headers` | Ed25519-signed root commitments with chain linkage |
| `ledger_entries` | Hash-chained events linking records to shard roots |

### 5. Prove

The API serves:

- **Existence proofs** — 256-sibling Merkle path proving a key is in the tree
- **Non-existence proofs** — 256-sibling path proving a key is absent
- **Redaction proofs** — Merkle inclusion proofs for selectively revealed sections
- **Shard header** with canonical JSON for offline Ed25519 verification
- **RFC 3161 timestamp token** (optional) for external time anchoring

### 6. Verify

All proofs can be verified offline without access to Olympus:

- `protocol/ssmf.py` — `verify_proof()`, `verify_nonexistence_proof()`
- `protocol/merkle.py` — `verify_proof()`
- `protocol/redaction.py` — `RedactionProtocol.verify_redaction_proof()`
- `protocol/shards.py` — `verify_header()`
- `protocol/ledger.py` — `Ledger.verify_chain()`
- `tools/verify_cli.py` — CLI for Merkle proof, ledger chain, and redaction proof verification

---

## Threat Model

**Olympus defends against:**

- Retroactive document modification (hash-chain linkage)
- Ledger history rewriting (chain integrity check)
- Out-of-order ledger insertion (DB sequence enforcement)
- Forged shard headers (Ed25519 signature on every read)
- Direct SQL tampering (append-only DB triggers)

**Olympus does not defend against:**

- Key compromise (signing key held by the operator)
- Full database deletion without external replication
- Documents that were never committed
- Multi-node collusion (federation is Phase 1+)

See [threat-model.md](threat-model.md) for a plain-English summary suitable
for auditors and policymakers.

---

## FOIA Workflow Support

Olympus is designed to bring cryptographic integrity to Freedom of Information
Act (FOIA) workflows. The core problem: **an agency could alter a document
before responding to a FOIA request**, and the requester would have no way to
know.

### Workflow

```
Agency commits document → Olympus signs Merkle root → FOIA request arrives
→ Agency produces redacted version → Requester verifies the redacted version
  is derived from the same committed original
```

1. **Pre-commitment** — Before any FOIA request, the agency commits the
   original document. A BLAKE3 content hash and a signed Merkle root are
   written to the append-only ledger with an RFC 3161 timestamp.

2. **Redaction proof** — At release time, the agency calls
   `RedactionProtocol.create_redaction_proof(tree, revealed_indices)`. This
   generates a `RedactionProof` that cryptographically binds each revealed
   section to the pre-committed Merkle root.

3. **Independent verification** — Any requester or auditor calls
   `RedactionProtocol.verify_redaction_proof(proof, revealed_content)` to
   confirm:
   - Each revealed section hashes to its committed leaf hash.
   - Each revealed section has a valid Merkle inclusion proof against the
     committed root.
   - The Merkle root in the proof matches the root signed at commitment time.

### What This Proves

| Property | Guarantee |
|----------|-----------|
| Document committed before FOIA request | ✅ Ledger timestamp and hash-chain |
| Revealed content unchanged since commitment | ✅ Leaf hash comparison |
| Redacted sections cannot be silently un-redacted | ✅ Merkle root fixed at commitment |
| Agency cannot claim a different original | ✅ Ed25519-signed shard header |

### Key Code Entry Points

| Component | Location | Purpose |
|-----------|----------|---------|
| Commit document | `protocol/redaction.py` — `RedactionProtocol.commit_document()` | Build Merkle tree over document sections |
| Create proof | `protocol/redaction.py` — `RedactionProtocol.create_redaction_proof()` | Generate selective-disclosure proof |
| Verify proof | `protocol/redaction.py` — `RedactionProtocol.verify_redaction_proof()` | Independently verify redaction proof |
| Reconstruct | `protocol/redaction.py` — `RedactionProtocol.reconstruct_redacted_document()` | Rebuild document with redaction markers |
| Verify ledger | `protocol/ledger.py` — `Ledger.verify_chain()` | Confirm chain integrity |
| Verify shard | `protocol/shards.py` — `verify_header()` | Verify Ed25519 shard header |

### Example: Committing and Verifying a FOIA Redaction

```python
from protocol.redaction import RedactionProtocol

# --- Agency side: before the FOIA request ---
document_sections = ["Section 1 text", "Classified details", "Section 3 text"]
tree, root_hash = RedactionProtocol.commit_document(document_sections)
# Store root_hash in the ledger.

# --- Agency side: at FOIA release time ---
revealed_indices = [0, 2]          # sections 1 and 3 are safe to reveal
proof = RedactionProtocol.create_redaction_proof(tree, revealed_indices)
# Send proof and revealed_content to requester.

# --- Requester / auditor side ---
revealed_content = ["Section 1 text", "Section 3 text"]
is_valid = RedactionProtocol.verify_redaction_proof(proof, revealed_content)

if is_valid:
    print("Redaction proof is valid — released content matches the committed original.")
else:
    print("WARNING: Redaction proof is INVALID.")
```

### FOIA Limitations

- **Completeness** — Olympus cannot force an agency to commit all documents.
- **Redaction policy** — Olympus proves consistency; it does not decide what
  may be withheld.
- **Key honesty** — An agency that controls both the signing key and the
  ledger can forge commitments. Federation (Phase 1+) distributes this trust.

---

## Cryptographic Primitives

| Primitive | Algorithm | Used for |
|-----------|-----------|----------|
| Hashing | BLAKE3 | All leaf, node, header, and ledger hashes |
| Signatures | Ed25519 (PyNaCl) | Shard header authentication |
| Merkle tree | Binary, 256-height sparse | Key-value commitments and SMT proofs |
| Canonical JSON | JCS-compatible, sorted keys | Deterministic ledger hashing |
| Trusted timestamps | RFC 3161 | Optional external time anchoring |
| ZK proofs (optional) | Groth16 / Circom | Document existence circuits |

Domain separation prefixes (`OLY:*:V1`) are defined in `protocol/hashes.py`
and must never change — they are protocol-critical.

---

## Repository Structure

```
protocol/           Core cryptographic primitives
  canonical.py      Basic document canonicalization (key sort, whitespace)
  canonical_json.py Deterministic JSON encoding for ledger hashing
  canonicalizer.py  Multi-format canonicalizer (JSON/HTML/DOCX/PDF)
  hashes.py         BLAKE3 domain-separated hash functions
  ledger.py         Append-only hash-chained ledger
  merkle.py         Binary Merkle tree with inclusion proofs
  redaction.py      Selective-disclosure redaction proofs
  rfc3161.py        RFC 3161 trusted timestamp tokens
  shards.py         Ed25519 shard header signing and verification
  ssmf.py           256-height sparse Merkle tree
  timestamps.py     UTC timestamp generation (ISO 8601 / Z suffix)
  zkp.py            Groth16 proof bridge (snarkjs subprocess wrapper)

storage/
  postgres.py       PostgreSQL storage layer (ACID, append-only)
  schema.sql        Canonical schema

api/
  app.py            FastAPI public audit API (read + verify endpoints)
  ingest.py         Write endpoints (batch record ingestion)

migrations/         Ordered SQL migration files
schemas/            JSON Schema definitions for external artifacts
proofs/             Circom circuits and Groth16 setup tooling
tools/              CLI utilities (verify_cli.py, canonicalize_cli.py, …)
tests/              Full test suite
docs/               Protocol specifications (00_overview.md … 08_*)
examples/           Known-good test artifacts
```

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | API info |
| `GET` | `/health` | Health check |
| `GET` | `/shards` | List shards with latest state |
| `GET` | `/shards/{id}/header/latest` | Latest shard header + signature |
| `GET` | `/shards/{id}/header/latest/verify` | Verify Ed25519 + RFC 3161 |
| `GET` | `/shards/{id}/proof` | Existence or non-existence proof |
| `GET` | `/ledger/{id}/tail` | Last N ledger entries |
| `POST` | `/ingest/records` | Batch record ingestion |
| `GET` | `/ingest/records/{id}/proof` | Retrieve ingestion proof |

Interactive docs at `http://localhost:8000/docs` when running locally.

---

## Status

**Phase 0.5** — Protocol hardening. Single-node. Not yet federated.

**Implemented:**

- Append-only hash-chained ledger
- 256-height sparse Merkle tree with existence and non-existence proofs
- Ed25519-signed shard headers with chain linkage
- RFC 3161 trusted timestamp anchoring
- Version-pinned multi-format canonicalization (JSON/HTML/DOCX/PDF)
- Selective-disclosure redaction proofs
- PostgreSQL storage (ACID, append-only triggers)
- Public audit REST API
- Groth16 ZK proof circuits (Circom / snarkjs)

**Not yet implemented (Phase 1+):**

- Guardian replication (multi-node, distributed trust)
- HSM-backed key custody
- External transparency log anchoring

---

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for full setup instructions including
PostgreSQL, Docker, and ZK circuit setup.

```bash
git clone https://github.com/wombatvagina69-crypto/Olympus.git
cd Olympus
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# Run tests (no PostgreSQL required)
pytest tests/ -m "not postgres" -v

# Start API (DB endpoints return 503 without PostgreSQL)
uvicorn api.app:app --reload
```

For development workflows, linting, type checking, and CI replication, see
[DEVELOPMENT.md](DEVELOPMENT.md).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache 2.0. See [LICENSE](LICENSE).
