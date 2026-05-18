# Olympus — Trail of Bits Audit Package

**Version**: v1.0 (Phase 0 production)
**Date**: 2026-05-14
**Prepared for**: Trail of Bits security audit

---

## 1. System Overview

Olympus is a cryptographic transparency ledger for public records. Its core guarantee: once a document hash is committed to the ledger, the commitment is cryptographically unforgeable and independently verifiable by anyone with the proof bundle, without trusting the server.

**Primary data flow (Phase 0):**

```
Client
  │
  ├─ POST /ledger/ingest/simple  (API key, "ingest" scope)
  │
FastAPI (api/main.py)
  │
  ├─ api/auth.py          ← API key validation, rate limiting, IP trust
  │
  ├─ api/routers/ledger.py
  │
storage/postgres.py::append_record()
  │
  ├─ SMT leaf key = olympus_core.crypto.record_key(type, id, version, shard_id)
  ├─ Global SMT key = BLAKE3.derive_key("olympus 2025-12 global-smt-leaf-key", ...)
  ├─ O(256) sibling fetch from smt_nodes
  ├─ Recompute 256-level path → new root
  ├─ Upsert all 256 smt_nodes + insert smt_leaves leaf
  ├─ Sign new root with Ed25519 → insert shard_headers row
  └─ Return (root, global_key, value_hash, tree_size)
  │
Client receives proof bundle
  └─ GET /shards/{shard_id}/proof → MerkleProof (siblings, value_hash, root, sig)
```

**Public verification flow:**

```
Client drops file
  │
  ├─ BLAKE3 hash (WASM, in-browser — file bytes never sent)
  │
  ├─ GET /shards/files/proof?key=<blake3_hex>
  │
  └─ Verifier re-derives root from siblings + leaf → checks sig → VALID / INVALID
```

---

## 2. Language Ownership & Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│  Python (FastAPI)                                               │
│  api/  protocol/  storage/                                      │
│  ▸ All DB operations (psycopg3, SQLAlchemy async)               │
│  ▸ Policy, auth, rate limiting, orchestration                   │
│  ▸ Calls Rust via PyO3 for crypto                               │
├─────────────────────────────────────────────────────────────────┤
│  Rust (olympus_core PyO3 extension)          src/               │
│  ▸ BLAKE3 domain-separated hashing                              │
│  ▸ Ed25519 signing (ed25519-dalek)                              │
│  ▸ Poseidon BN254 (mandatory, no Python fallback)               │
│  ▸ Groth16 BN254 verification (mandatory, no Python fallback)   │
│  ▸ Sparse Merkle Tree (RustSparseMerkleTree)                    │
│  ▸ Canonical JSON acceleration                                  │
├─────────────────────────────────────────────────────────────────┤
│  Go (sequencer)          services/sequencer-go/   [Phase 1]     │
│  ▸ Write ordering / batching                                    │
│  ▸ Delegates ALL crypto to Rust CD-HS-ST service                │
│  ▸ NEVER computes Merkle hashes                                 │
├─────────────────────────────────────────────────────────────────┤
│  TypeScript (frontend)   app/public-ui/                         │
│  ▸ BLAKE3 WASM hashing (client-side only)                       │
│  ▸ No secrets, no signing                                       │
└─────────────────────────────────────────────────────────────────┘
```

**Enforced by**: `tools/check_import_boundaries.py` (pre-commit hook, blocking)

---

## 3. Cryptographic Architecture

### 3.1 Hash Primitives

| Primitive | Use | Implementation | Fallback |
|-----------|-----|----------------|---------|
| BLAKE3 | Ledger leaf/node hashes, API key hashing, record keys | `olympus_core.crypto` (Rust) | Pure Python path in `protocol/hashes.py` (removed by `OLYMPUS_REQUIRE_RUST=1`) |
| Poseidon BN254 | ZK circuit commitments | `olympus_core.poseidon` (Rust) | **None — hard fail** |
| SHA-256 | Password hashing (Argon2 wrapper), RFC 3161 TSA | Python stdlib | N/A |

### 3.2 Domain Separation

All BLAKE3 leaf and node hashes use mandatory OLY domain prefixes:

```
Leaf hash:  BLAKE3( "OLY:LEAF:V1|" || data )
Node hash:  BLAKE3( "OLY:NODE:V1|" || left_child || right_child )
```

Global SMT leaf keys use BLAKE3 key derivation (not the prefix tag pattern):

```python
BLAKE3.derive_key("olympus 2025-12 global-smt-leaf-key", length_prefixed(shard_id, record_key))
```

**Audit focus**: Verify prefix and separator constants are not duplicated or overridden in calling code. The pipe `|` is a separator, not part of the prefix — they must remain separate constants.

### 3.3 Sparse Merkle Tree

- **Depth**: 256 levels (global, not per-shard)
- **Leaf key space**: 256-bit BLAKE3 derived keys
- **Storage**: `smt_nodes` table (level, index → hash); `smt_leaves` (key, version → value_hash)
- **Root**: `smt_nodes WHERE level=0 AND index=''::bytea` — O(1) read
- **Write path**: O(256) sibling fetch → recompute path → upsert 256 nodes + 1 leaf (all in one transaction)
- **Dual-root**: BLAKE3 ledger tree and Poseidon ZK tree maintained independently (`poseidon_smt_nodes` table)

### 3.4 Ed25519 Signing

- **Algorithm**: Ed25519 (PyNaCl / libsodium; Rust ed25519-dalek for federation)
- **Key source**: `OLYMPUS_INGEST_SIGNING_KEY` environment variable (hex, 32 bytes)
- **Key persistence**: Required — ephemeral keys make historical signed roots unverifiable
- **What is signed**: Each `shard_headers` row contains `{shard_id, seq, root, tree_size, leaf_seq, previous_header_hash}` signed as a canonical JSON blob
- **Chain linkage**: Each header includes `previous_header_hash` — forms a hash chain

**Audit focus**: Key rotation path (`protocol/key_rotation.py`, `protocol/federation/rotation.py`). Verify that rotation does not invalidate old signatures on already-committed headers.

### 3.5 ZK Proof Layer

**Backend**: Groth16 on BN254 curve via snarkjs (Node.js subprocess IPC) + `olympus_core.zkverify` for verification.

| Circuit | File | Constraints | Public Inputs | Proving time |
|---------|------|-------------|---------------|--------------|
| document_existence | `proofs/circuits/document_existence.circom` | ~8k | leafIndex, root | ~1s (snarkjs) |
| redaction_validity | `proofs/circuits/redaction_validity.circom` | ~41k | originalRoot, revealedCount, revealMask, redactedCommitment | ~3s |
| non_existence | `proofs/circuits/non_existence.circom` | ~70k | leafIndex, root | ~5s |

**Trusted setup**: Hermez BN254 PTAU (Powers of Tau) used for Phase 1 ceremony. **Phase 2 (circuit-specific) setup used the dev contribution from `setup_circuits.sh` — this is NOT a production-grade ceremony.** Trail of Bits audit should include ceremony planning.

**Audit focus**: The `redaction_validity` circuit — verify that the `revealMask` and `redactedCommitment` constraints actually prevent selective disclosure attacks. Ensure a prover cannot claim a valid proof for a redacted document while including fabricated leaf values.

---

## 4. API Entry Points — Security-Relevant Endpoints

### 4.1 Write Path (Requires Auth)

| Endpoint | Auth | Risk |
|----------|------|------|
| `POST /ledger/ingest/simple` | `"ingest"` scope | Primary write; triggers SMT update + header signing |
| `POST /documents` | `"write"` scope | Document upload + commit |
| `POST /requests` | `"write"` scope | Public records request creation |
| `PATCH /requests/{display_id}/status` | `"write"` scope | Status change → ledger anchor |
| `POST /appeals` | `"write"` scope | Appeal filing |
| `POST /agencies` | `"write"` scope | Agency creation |
| `POST /witness/checkpoints` | `"witness"` scope | Checkpoint submission |
| `POST /federation/sign-header` | `"ingest"` scope + Guardian enabled | Quorum signing; 409 on fork detection |
| `POST /keys/credential` | `"write"` scope | Ed25519 credential creation |
| `POST /keys/admin/reload-keys` | `"admin"` scope | Hot reload of API key set |
| `DELETE /auth/admin/users/{user_id}` | `"admin"` scope | User deletion |
| `POST /shards/{shard_id}/alert/smt-divergence` | `"admin"` scope | Prometheus counter + structured log |

### 4.2 Public Read Path (No Auth)

All GET endpoints on `/ledger/`, `/shards/`, `/requests`, `/witness/`, `/agencies/`, `/appeals/`, `/public/`, `/federation/status`, `POST /documents/verify`, `POST /keys/verify`.

**Audit focus**: Verify proof endpoints (`/shards/{shard_id}/proof`) cannot be used to enumerate committed records (SMT non-existence proofs leak path membership).

### 4.3 User Auth Endpoints

| Endpoint | Notes |
|----------|-------|
| `POST /auth/register` | Gated by `OLYMPUS_ALLOW_PUBLIC_WRITE_REGISTRATION=1`; default disabled |
| `POST /auth/login` | Returns session token; throttled |
| `POST /auth/reissue-key` | Session auth required |
| `POST /auth/keys` | Creates new API key; session auth |
| `DELETE /auth/keys/{key_id}` | Revokes key; session auth |
| `DELETE /auth/me` | Account deletion |

**Audit focus**: Registration throttle (`tools/check_demo_keys.py`), session token lifetime and invalidation, key revocation reflected immediately in auth checks.

---

## 5. Threat Model

### 5.1 Assets

1. **Ledger integrity** — the append-only property; no committed record can be altered or deleted
2. **Proof soundness** — a valid proof bundle must correspond to a real committed record
3. **Signing key** — if compromised, attacker can forge shard headers (but cannot alter existing `smt_leaves` rows without DB access)
4. **API key material** — if compromised, attacker can write to the ledger under that key's scope
5. **ZK circuit setup** — weak Phase 2 ceremony allows proof forgery for all circuits sharing that ceremony

### 5.2 Trust Assumptions

- PostgreSQL server is trusted (not an adversary) — no Byzantine fault tolerance in Phase 0
- The node operator controls `OLYMPUS_INGEST_SIGNING_KEY` — single point of failure pre-federation
- The snarkjs Node.js subprocess is trusted (same host, no sandboxing)
- BLAKE3 WASM in the browser is unaudited for supply-chain integrity

### 5.3 Attack Surfaces

| Surface | Attack | Mitigation |
|---------|--------|------------|
| API write path | Unauthorized ingest | Scoped API keys, BLAKE3-hashed storage |
| SMT root | Root forgery without DB access | Ed25519-signed headers + chain linkage |
| Proof bundles | Fake proof submission to `/documents/verify` | Rust Groth16 verifier (no Python fallback) |
| ZK circuits | Witness malleability / underconstrained signals | Audit target — especially `redaction_validity` |
| Trusted setup | Trapdoor retained → proof forgery | **Phase 2 ceremony not yet production-grade** |
| Key material | Signing key exfiltration | OLYMPUS_INGEST_SIGNING_KEY in env (not HSM) |
| Registration | Account enumeration via timing | Registration throttle (configurable via env) |
| Rate limiting | Memory backend per-process | Shared state requires Redis backend in multi-process deploy |
| X-Forwarded-For | IP spoofing for rate limit bypass | Default-deny; explicit `TRUSTED_PROXY_IPS` required |
| Canonical JSON | Hash confusion via non-canonical encoding | JCS/RFC 8785 enforced; Python fallback path exists |
| Federation gossip | Fork injection | 409 Conflict on root mismatch + quorum threshold |

### 5.4 Out of Scope (Phase 0)

- Byzantine fault tolerance (requires Phase 1 federation)
- HSM key storage (production ceremony decision)
- Cross-shard consistency proofs (planned for Phase 1)
- Shard enumeration via non-existence proofs (by design — SMT proves non-membership)

---

## 6. Key File Index for Auditors

### Cryptographic Core

| File | Purpose | Audit Priority |
|------|---------|----------------|
| `src/lib.rs` | PyO3 extension root — all Rust exports | HIGH |
| `src/crypto.rs` | BLAKE3, Ed25519, domain prefix constants | HIGH |
| `src/poseidon.rs` | Poseidon BN254 implementation | HIGH |
| `src/smt.rs` | Sparse Merkle Tree Rust implementation | HIGH |
| `src/zkverify.rs` | Groth16 verifier | HIGH |
| `protocol/hashes.py` | Python BLAKE3 wrapper + fallback gate | HIGH |
| `protocol/canonical.py` | JCS canonical JSON | MEDIUM |
| `protocol/merkle.py` | Proof construction and verification | HIGH |
| `protocol/shards.py` | Shard header signing | HIGH |
| `protocol/poseidon.py` | Poseidon Python wrapper | MEDIUM |

### ZK Circuits

| File | Purpose | Audit Priority |
|------|---------|----------------|
| `proofs/circuits/document_existence.circom` | Existence proof circuit | HIGH |
| `proofs/circuits/redaction_validity.circom` | Redaction soundness | **CRITICAL** |
| `proofs/circuits/non_existence.circom` | Non-existence proof circuit | HIGH |
| `proofs/circuits/lib/merkleProof.circom` | Shared Merkle templates | HIGH |
| `proofs/snarkjs_bridge.py` | Node.js IPC bridge | MEDIUM |
| `proofs/setup_circuits.sh` | Ceremony script (Phase 2 contribution) | HIGH |

### Storage & DB

| File | Purpose | Audit Priority |
|------|---------|----------------|
| `storage/postgres.py` | All DB operations | HIGH |
| `alembic/versions/` | Schema migrations (14 files) | MEDIUM |

### Auth & API

| File | Purpose | Audit Priority |
|------|---------|----------------|
| `api/auth.py` | API key validation, rate limiting, IP trust | HIGH |
| `api/main.py` | Lifespan, middleware, CORS | MEDIUM |
| `api/routers/user_auth.py` | Registration, login, session, key management | HIGH |
| `api/routers/ledger.py` | Ingest and verify endpoints | HIGH |
| `api/routers/federation.py` | Quorum signing, fork detection | HIGH |
| `api/routers/keys.py` | Ed25519 credential management | MEDIUM |

### Federation

| File | Purpose | Audit Priority |
|------|---------|----------------|
| `protocol/federation/quorum.py` | Multi-sig vote aggregation | HIGH |
| `protocol/federation/rotation.py` | Key rotation consensus | HIGH |
| `protocol/federation/gossip.py` | VRF committee selection | MEDIUM |
| `protocol/federation/replication.py` | State sync | MEDIUM |

---

## 7. Known Limitations & Pre-Audit Disclosures

1. **Groth16 trusted setup is not production-grade.** The Phase 2 ceremony in `proofs/setup_circuits.sh` uses a single dev contribution. A multi-party ceremony (MPC) with public attestations is required before production ZK usage. This is a planned pre-ceremony item.

2. **Single signing key, no HSM.** `OLYMPUS_INGEST_SIGNING_KEY` is an env variable. Phase 1 federation quorum distributes signing trust, but Phase 0 is single-node.

3. **Rate limiting is per-process in memory by default.** Multi-process deployments (e.g., gunicorn with multiple workers) require `RATE_LIMIT_BACKEND=redis` for correct shared state.

4. **`cdhs-smf-rust` uses different domain prefixes.** This service (`services/cdhs-smf-rust/`) is a historical artifact with non-standard prefixes. It is not used for production crypto and should not be used as a reference implementation.

5. **Python BLAKE3 fallback path exists.** If `OLYMPUS_REQUIRE_RUST` is not set, Python can compute BLAKE3 without Rust. The fallback implementation must be verified to produce identical output to the Rust path.

6. **Go sequencer is Phase 1, not active.** `services/sequencer-go/` is scaffolded but not the primary write path. The `GET /v1/get-consistency-proof` endpoint returns HTTP 410 — sparse Merkle semantics differ from RFC 6962 consistency proofs.

7. **snarkjs subprocess is unsandboxed.** The Node.js process used for ZK proving runs on the same host with the same privileges as the FastAPI process.

---

## 8. Environment for Audit Reproduction

```bash
# Minimum viable stack
docker compose up -d           # PostgreSQL on :5432
maturin develop                # Build olympus_core Rust extension
python -m alembic upgrade head # Apply all 14 migrations
make dev                       # FastAPI on :8000

# Run full test suite
pytest tests/ -v --cov=protocol --cov=storage --cov=api

# Run adversarial tests specifically
pytest tests/adversarial/ -v

# Run security invariant fuzzing
pytest tests/fuzz/test_security_invariants_fuzz.py -v

# Verify golden test vectors
make vectors

# ZK smoke test (requires Node.js + snarkjs)
bash proofs/smoke_test.sh
```

**Required environment variables** (minimum for dev):

```env
DATABASE_URL=postgresql+asyncpg://olympus:olympus@localhost:5432/olympus
PSYCOPG_URL=postgresql://olympus:olympus@localhost:5432/olympus
OLYMPUS_DEV_SIGNING_KEY=1
OLYMPUS_ENV=development
OLYMPUS_LOG_FORMAT=text
```
