# Olympus Architecture

This is the authoritative navigation reference for the Olympus
repository at **v0.10.0**.

For a 5-minute orientation see [`README.md`](../README.md). For the
change log see [`CHANGELOG.md`](../CHANGELOG.md).

## Stack at a glance

```text
Tauri 2 desktop binary
├── Frontend       — React + TypeScript + Vite + Tailwind  (app/public-ui/)
├── Axum server    — embedded HTTP API                     (src-tauri/src/server/, api/)
├── pg_embed       — embedded PostgreSQL                   (pg-embed-local/)
├── sqlx           — migrations + queries                  (migrations/)
└── ZK runtime     — arkworks 0.6 + ark-circom (in-process Groth16)
                     vendored light-poseidon 0.4 (arkworks 0.6 bump)
                                                           (src-tauri/src/zk/, proofs/)
```

Python and Go are retired (replaced in v0.9.0). The Rust + TypeScript
ownership boundary is the only one that matters now.

## Language ownership — hard boundaries

```text
Rust       → Tauri app, Axum HTTP server, cryptographic hot path: BLAKE3,
             Ed25519, Poseidon, SMT, canonicalization, embedded PostgreSQL,
             all DB operations, SBT issue/verify/revoke, anchoring
             (RFC 3161 / Sigstore Rekor / OpenTimestamps), federation
             (Tor hidden service + checkpoint gossip).
TypeScript → React frontend in app/public-ui/.
```

There is **no** Python in the runtime. The `verifiers/` directory ships
**Rust** and **JavaScript** reference verifiers for offline / cross-impl
conformance only.

## Repository layout

```text
.
├── app/public-ui/                  React + TS + Vite frontend
├── src-tauri/                      Tauri 2 desktop binary (entry point of the app)
│   ├── src/main.rs                 Tauri entry, proofs_dir resolution, placeholder gate
│   ├── src/lib.rs                  shared lib for tests
│   ├── src/server/mod.rs           Axum router wiring
│   ├── src/api/                    HTTP route handlers (see below)
│   ├── src/api/middleware/auth.rs  AuthenticatedKey, RateLimit, BJJ-derived API keys, SBT-scope resolver
│   ├── src/state.rs                AppState (DB pool, BJJ keys, proofs_dir, rate limiters)
│   ├── src/bootstrap.rs            first-launch: keys, authority SBT, system user
│   ├── src/merkle.rs               BLAKE3 + Poseidon Merkle tree
│   ├── src/integrity/              file-level integrity helpers
│   ├── src/zk/                     in-process Groth16 prover + verifier
│   │   ├── prove.rs                /zk/prove backend
│   │   ├── verify.rs               /zk/verify backend with embedded vkeys (include_str!)
│   │   ├── zkey.rs                 arkworks .ark.zkey loader
│   │   ├── vkey.rs                 snarkjs vkey JSON parser
│   │   └── witness/                circuit-specific witness builders
│   ├── src/federation/             Tor hidden service + peer gossip (feature = "federation")
│   ├── src/anchoring/              RFC 3161 + Rekor + OpenTimestamps clients
│   └── src/bin/export_ark_zkey.rs  one-shot CLI: snarkjs .zkey → arkworks .ark.zkey
├── crates/olympus-crypto/          shared crypto utilities (no PyO3)
├── crates/light-poseidon/          vendored upstream + arkworks 0.6 bump
├── pg-embed-local/                 pg_embed fork with workspace-local patches
├── migrations/                     sqlx migrations (0001 … 0050 at v0.10.0)
├── proofs/                         Circom circuits + setup pipeline
│   ├── circuits/*.circom           document_existence, non_existence,
│   │                               unified_canonicalization_inclusion_root_sign
│   ├── setup_circuits.sh           dev / single-contributor setup
│   ├── phase2_ceremony.sh          multi-contributor v1.0 ceremony orchestration
│   └── keys/                       runtime artifacts (.wasm, .r1cs, .ark.zkey, vkeys)
└── verifiers/
    ├── rust/                       offline Rust verifier
    ├── javascript/                 offline JS verifier
    └── test_vectors/vectors.json   cross-impl conformance vectors
```

## HTTP API surface

All routes mount on the embedded Axum server. Authentication is via
`X-API-Key` or `Authorization: Bearer`; rate limiting is per-IP via
`governor`.

| Path | Purpose | Required scope |
|---|---|---|
| `/health` | liveness | (none) |
| `/ingest` | append a record (commit) | `ingest` or `commit` |
| `/ingest/records` | list ingest history | `read` / `verify` / `admin` |
| `/ingest/files` | multipart file commit | `ingest` or `commit` |
| `/ledger/*` | Merkle/SMT inclusion + non-inclusion proofs | `read` / `verify` / `admin` |
| `/redaction/*` | redaction proofs + links | scope-gated per endpoint |
| `/zk/verify` | in-process Groth16 verify | `verify` / `read` / `admin` |
| `/zk/prove` | in-process Groth16 prove | `prove` / `admin` |
| `/credentials` (POST) | issue SBT | `admin` |
| `/credentials` (GET) | list SBTs | `read` / `verify` / `admin` |
| `/credentials/{id}` (GET) | one SBT with signatures | `read` / `verify` / `admin` |
| `/credentials/{id}/revoke` | revoke SBT | `admin` |
| `/credentials/{id}/verify` | server-side re-verify | `verify` / `read` / `admin` |
| `/admin/users/*` | mint keys / edit scopes / promote roles | `admin` |
| `/admin/users` (GET) | list users | `admin` |
| `/key/admin/generate` | mint an admin key | `x-admin-key` header (`OLYMPUS_ADMIN_KEY`) |
| `/key/admin/reload-keys` | hot-reload signing keys | `x-admin-key` header |
| `/anchors` | RFC 3161 / Rekor / OTS receipts | `read` / `verify` / `admin` |
| `/anchors/{id}` | one anchor receipt (JSON metadata) | `read` / `verify` / `admin` |
| `/anchors/{id}/receipt` | raw receipt bytes (verifier-friendly Content-Type) | `read` / `verify` / `admin` |
| `/auth/*` | self-service auth (login / whoami / recovery) | varies |
| `/public/stats`, `/v1/public/stats` | counters for the frontend home page | (none) |

## Authentication and scopes

Two-tier auth, all in [`src-tauri/src/api/middleware/auth.rs`](../src-tauri/src/api/middleware/auth.rs):

1. **API key lookup.** `BLAKE3(raw_key)` → `api_keys.key_hash` →
   row with `revoked_at IS NULL` and `expires_at IS NULL OR > NOW()`.
2. **Effective-scope resolution** (v0.9.1, PR #949). The effective
   scope set is the **union** of:
   - the legacy `api_keys.scopes` column (fallback for system-bootstrap
     and any pre-#945 row), plus
   - scopes derived from active SBTs the holder owns, joined via
     `holder_key = "bjj:{x}:{y}"` against the new
     `api_keys.bjj_pubkey_x/y` columns from PR #945.

Mapping `credential_type → scopes` is hardcoded in
`scopes_for_credential_type` and **fail-closed**: unknown types grant
nothing.

| `credential_type` | Scopes granted |
|---|---|
| `authority_sbt` | `admin, prove, ingest, commit, write, read, verify` |
| `press_credential` | `read, verify, ingest, commit` |
| `foia_requester` | `read, verify, ingest` |
| `court_observer` | `read, verify` |
| `verifier_only` | `read, verify` |
| _anything else_ | _(none)_ |

To make the mapping runtime-configurable, promote it to `AppState` and
load from a signed manifest — but the current shape treats it as
federation security policy, not config.

## The unified-key story

Before v0.9.0 there were two parallel secrets per identity: an opaque
API key (hash persisted) and a Baby Jubjub private key (only the pubkey
persisted). In v0.9.0 they were unified:

```text
api_key = "oly_" || hex(BLAKE3("OLY:APIKEY:V1" || bjj_priv))
```

Holders manage one secret (the BJJ private key). The API key is a
one-way derivation, so leaking the API key cannot reveal the BJJ key.
Holders who keep the BJJ key can re-derive the API key losslessly.

Migration `0028_api_keys_bjj_pubkey.sql` adds `bjj_pubkey_x/y` to
`api_keys` so the server can pivot from an authenticated API key to the
holder's BJJ identity — which is the join key into `key_credentials`
for SBT-scope resolution.

## SBTs (Soulbound Tokens)

Olympus issues its own SBTs natively — no EVM mirror, no chain. Every
row in `key_credentials` is BJJ-EdDSA-signed by the federation authority
key at issue time, and again at revocation time. Verifiers re-check
offline using just the federation's BJJ public key — no callback to the
node. See [`docs/sbt-deployment.md`](sbt-deployment.md) for the
verification protocol and [`src-tauri/src/api/credentials/`](../src-tauri/src/api/credentials/)
for the implementation.

## ZK proof pipeline

Three core Circom circuits compile to Groth16 over BN254, with
`federation_quorum` available for quorum attestations:

| Circuit | Purpose |
|---|---|
| `document_existence` | proves a document hash is in the Merkle root |
| `non_existence` | proves a key is absent from the SMT |
| `unified_canonicalization_inclusion_root_sign` | proves canonicalization + Merkle inclusion + ledger-root (SMT) commitment in a single proof |

The `redaction_validity` circuit was removed (ADR-0030): redaction now uses a
signed Merkle fold (Ed25519 signature over a variable-depth Poseidon root of the
per-segment hiding leaves), not a SNARK. The remaining circuits are compiled by
`setup_circuits.sh` and wired for both `/zk/prove` and `/zk/verify`. The unified
circuit's verification key is produced by the trusted setup and is gitignored
until then, so verifying its proofs requires a real ceremony run for that circuit.

At runtime the server loads the arkworks-serialized `.ark.zkey` once
into a `OnceLock`-backed verifier and proves/verifies in-process — no
Node.js, no snarkjs subprocess, no shelling out. The `_final.zkey`
exported by snarkjs is converted to `.ark.zkey` via
[`src-tauri/src/bin/export_ark_zkey.rs`](../src-tauri/src/bin/export_ark_zkey.rs)
as part of the setup pipeline.

## Anchoring

External anchoring to three independent third-party services binds a
signed checkpoint to time, evidence-grade:

- **RFC 3161** TSA (`src-tauri/src/anchoring/rfc3161.rs`) — receipts
  stored verbatim for `openssl ts -verify`.
- **Sigstore Rekor** (`src-tauri/src/anchoring/rekor.rs`) — signed
  `hashedrekord/v0.0.1` entries; verifiable with `rekor-cli`.
- **OpenTimestamps** (`src-tauri/src/anchoring/ots.rs`) — calendar
  receipts upgradeable to Bitcoin block headers; verifiable with
  `ots verify`.

The anchored payload is the **domain-separated, shard-scoped v2** BLAKE3
digest (`OLY:CHECKPOINT_ANCHOR:V2 || version || lp(scope) || lp(shard_id) ||
lp(ledger_root) || tree_size || timestamp || lp(authority) ||
lp(sig_r8x_dec) || lp(sig_r8y_dec) || lp(sig_s_dec)`),
not the raw `ledger_root`. The BJJ signature covers the corresponding
`OLY:CHECKPOINT:STATEMENT:V2` tuple, so scope, shard, height, and timestamp
cannot be relabeled after signing.
See [`docs/court-evidence.md`](court-evidence.md) for the expert-witness
verification protocol.

## Federation (optional feature)

Built with `cargo tauri build --features federation`. Adds:

- Tor hidden service (`arti-client 0.31`) for inbound peer traffic
- Outbound `.onion` HTTP via the same Arti runtime
- Peer node management (add/remove/trust transitions)
- BJJ-signed checkpoint gossip
- Equivocation detection with an in-memory seen-set + auto-blocking

See [`src-tauri/src/federation/`](../src-tauri/src/federation/) for the
implementation.

## Database

Embedded PostgreSQL via `pg_embed`. Schema is in `migrations/`, applied
on startup by `sqlx::migrate!` in both the `init_embedded` and
`connect_external` paths. Migrations through 0050 ship in v0.10.0.

Key tables:

| Table | Source migration |
|---|---|
| `api_keys` | 0010 (+ 0020 revoke/expire, 0028 bjj_pubkey_x/y) |
| `users`, `account_signing_keys` | 0010, 0015 |
| `key_credentials` | 0001 (+ 0002 revocation_commit_id, 0015 burn_authorization, 0027 SBT signatures) |
| `credential_consents`, `credential_ledger_events` | 0015 |
| `merkle_nodes`, `ledger_records` | 0001, 0019 |
| `peer_nodes`, `peer_checkpoints` | 0024, 0025 |
| `anchor_receipts` | 0026 |

Set `DATABASE_URL` to bypass `pg_embed` and use an external Postgres.
Migrations still run.

## Critical invariants

These are non-negotiable correctness properties. Breaking any of them
invalidates historical proofs.

- **Leaf hashes** use the ADR-0005 structured binary prefix:
  `u8(0x01) || "OLY" || u8(0x01)=LEAF || u8(0x01)=V1 || lp(shard_id)`,
  followed by a `0x05` count-framed body
  `lp(key) || value_hash || lp(parser_id) || lp(canonical_parser_version) || lp(model_hash)`.
  The old `OLY:LEAF:V1` marker remains pinned only as a legacy reference
  constant; it is not the live leaf preimage.
- **Node / empty-leaf / signing domains** stay versioned and disjoint:
  `OLY:NODE:V1`, `OLY:EMPTY-LEAF:V1`, `OLY:SBT:OPEN:V1`,
  `OLY:SBT:COMMIT:V1`, `OLY:SBT:REVOKE:V1`, `OLY:SBT:QUORUM:V2`,
  `OLY:CHECKPOINT:QUORUM:V2`, `OLY:CHECKPOINT:STATEMENT:V2`,
  `OLY:CHECKPOINT_ANCHOR:V2`,
  `OLY:APIKEY:V1`, and `OLY:SNAPSHOT:PERSIST:V1`.
- **Persistent Ed25519 ingest-signing key** — ephemeral keys make
  historical signed roots unverifiable.
- **Persistent Baby Jubjub authority key** — same property, and
  required for SBT signing + unified-API-key derivation.
- **Canonical JSON**: always JCS / RFC 8785, raw UTF-8.
- **SBT scope mapping is hardcoded** — `scopes_for_credential_type` in
  `auth.rs`. Treat as security policy; do not move to runtime config
  without a signed-manifest design.

## Where to look next

- [`CHANGELOG.md`](../CHANGELOG.md) — what shipped when
- [`docs/development.md`](development.md) — common workflows
- [`docs/quickstart.md`](quickstart.md) — install / build from source
- [`docs/court-evidence.md`](court-evidence.md) — anchoring verification protocol
- [`docs/sbt-deployment.md`](sbt-deployment.md) — SBT issuance + offline verification
- [`docs/threat-model.md`](threat-model.md) — adversaries and assurances
