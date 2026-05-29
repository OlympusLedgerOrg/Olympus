# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Current version: **v0.9.5** (May 2026).

## Commands

```bash
# Desktop app (primary)
cargo tauri dev                # Dev build with hot-reload frontend
cargo tauri build              # Production Tauri binary + bundled installers

# Rust
cargo check --workspace        # Fast type/lint check
cargo test --workspace         # All Rust unit tests
cargo clippy --workspace       # Lints

# Frontend
pnpm install                   # Install JS deps
pnpm --filter app/public-ui build   # Production frontend build
pnpm --filter app/public-ui dev     # Vite dev server (standalone)

# Database migrations (sqlx, applied by Tauri on startup)
# Migration files live in migrations/ — sqlx applies them automatically.

# ZK setup (run once before cargo tauri build)
cd proofs && bash setup_circuits.sh        # compile circuits + Groth16 setup + ceremony manifests
# The script auto-runs export_ark_zkey AND generate_manifest per circuit, so a
# single invocation produces every artifact the runtime checks at startup:
#   proofs/keys/<circuit>.{wasm,r1cs,ark.zkey}
#   proofs/keys/verification_keys/<circuit>_vkey.json
#   proofs/keys/manifests/<circuit>_manifest.json   (audit CEREMONY_INTEGRITY.md)

# To regenerate the manifest for one circuit only (e.g. after a vkey hand-fix):
cargo run --release --bin generate_manifest -- \
    --circuit <name> --keys-dir proofs/keys --build-dir proofs/build \
    --ceremony-id <id> --contributor-id <name> \
    --out proofs/keys/manifests/<name>_manifest.json

# Verifiers (offline / cross-impl conformance)
cd verifiers/rust && cargo test
cd verifiers/javascript && npm test
```

## Architecture

### Language Ownership — Hard Boundaries

```
Rust       → Tauri app, Axum HTTP server, cryptographic hot path: BLAKE3, Ed25519, Poseidon, SMT,
             canonicalization, embedded PostgreSQL (pg_embed), all DB operations,
             SBT issue/verify/revoke, anchoring (RFC 3161 / Rekor / OTS)
TypeScript → React frontend (app/public-ui/)
```

Python and Go are retired. The Python FastAPI server, the Go sequencer, and
the Go/Python verifiers were replaced by the Tauri + Axum desktop in v0.9.0.

### Deployment

- **Desktop app (primary)**: Tauri 2 binary with embedded Axum HTTP server + pg_embed PostgreSQL.
  - Windows: install the MSI or NSIS bundle produced by `cargo tauri build`.
  - Linux: install the deb / rpm / AppImage bundle.
  - macOS: bundle is produced but not yet code-signed for distribution.
- No external Python, Go, Node, or Docker required at runtime.

### Tauri App (`src-tauri/`)

Axum HTTP server embedded in the Tauri process. Handles all API requests. Runs
pg_embed for an embedded PostgreSQL instance. sqlx migrations in `migrations/`
are applied on startup (both `init_embedded` and `connect_external` paths).

Key files:
- `src-tauri/src/main.rs` — Tauri entry, `resolve_proofs_dir`, placeholder gate, IPC commands
- `src-tauri/src/server/mod.rs` — Axum router setup
- `src-tauri/src/api/` — Axum route handlers (`ingest`, `ledger`, `redaction`, `admin`, `admin_users`, `keys`, `zk`, `user_auth`, `credentials`, `anchors`)
- `src-tauri/src/routes/public_stats.rs` — public ledger statistics endpoint
- `src-tauri/src/api/zk.rs` — `/zk/verify`, `/zk/prove` (scope-gated)
- `src-tauri/src/api/credentials.rs` — Olympus-native SBTs (issue / list / revoke / verify); optional M-of-N federation quorum (`quorum: true`)
- `src-tauri/src/quorum/` — M-of-N quorum signer set + domain-separated co-sign digest + offline verifier (always compiled, not feature-gated); see `docs/federation-quorum-credentials.md`
- `src-tauri/src/api/middleware/auth.rs` — `AuthenticatedKey`, `RateLimit`, `derive_api_key_from_bjj`, SBT-driven scope resolver
- `src-tauri/src/state.rs` — `AppState` (pool, BJJ keys, `proofs_dir`, …)
- `src-tauri/src/federation/` — Tor hidden service + checkpoint gossip + quorum co-sign (`cosign.rs`) (feature-gated)
- `src-tauri/src/anchoring/` — external anchors (RFC 3161 / Sigstore Rekor / OpenTimestamps); see `docs/court-evidence.md`
- `src-tauri/src/bin/export_ark_zkey.rs` — snarkjs `.zkey` → arkworks `.ark.zkey`
- `src-tauri/src/bin/generate_manifest.rs` — writes per-circuit signed ceremony manifest (audit CEREMONY_INTEGRITY.md)
- `src-tauri/src/zk/manifest.rs` — `CeremonyManifest` schema + verify helpers (blake3, contribution-chain, BJJ-EdDSA coordinator signature)
- `src-tauri/build.rs` — placeholder shim + compile-time check #1 (manifest.vkey.blake3 vs blake3(vkey.json))
- `src-tauri/Cargo.toml` — dependencies (arkworks 0.6, ark-circom 0.6, vendored light-poseidon)

### ZK Proof Layer (`proofs/`)

Five Circom circuits (four production, one feature-gated): `document_existence`,
`non_existence`, `redaction_validity`,
`unified_canonicalization_inclusion_root_sign` (requires PTAU power 20),
and `federation_quorum` (gated behind `quorum-circuit` feature). All four
production circuits are compiled by `setup_circuits.sh` and wired for both
`/zk/prove` and `/zk/verify`. The unified circuit's vkey is produced by the
trusted setup and gitignored until then; the other three vkeys are committed
in `proofs/keys/verification_keys/`.

`src-tauri/build.rs` drops ~60-byte `PLACEHOLDER` stubs for all five
circuits (artifacts + vkey JSONs + ceremony manifests) into `proofs/keys/`
so Tauri's resource glob and `include_str!` resolve pre-setup;
`proofs/setup_circuits.sh` overwrites them with real artifacts. With
`OLYMPUS_ENV=production`, startup refuses (`exit 2`) if any artifact is
still a placeholder OR if any ceremony manifest fails its coordinator-
signature / `.ark.zkey` blake3 check. Dev mode logs warnings + continues.

Runtime artifacts (`.wasm`, `.r1cs`, `.ark.zkey`) are staged into
`proofs/keys/` by the setup pipeline. Per-circuit signed ceremony manifests
are staged into `proofs/keys/manifests/<circuit>_manifest.json`.

- `proofs/setup_circuits.sh` — dev / single-contributor all-in-one path
  (compile → Groth16 setup → export `.ark.zkey` → generate signed manifest)
- `proofs/phase2_ceremony.sh` — multi-contributor Phase 2 (`prepare` / `contribute` / `verify` / `finalize`) for v1.0 release ceremonies
- `proofs/CEREMONY_INTEGRITY.md` — operational protocol for ceremony
  bundles + the four runtime checks the desktop binary enforces
- Both setup scripts share the Hermez Phase 1 ptau
  (`proofs/keys/powersOfTau28_hez_final_20.ptau`) and produce the same
  `.ark.zkey` + manifest pair the runtime consumes.

#### Ceremony Integrity (runtime checks — audit CEREMONY_INTEGRITY.md)

Three checks run automatically:

1. **build.rs**: asserts `blake3(vkey.json) == manifest.artifacts.vkey.blake3`. `cargo build` fails on mismatch.
2. **`load_proving_key_with_manifest`**: re-hashes `.ark.zkey` from disk and asserts match against manifest before `deserialize_uncompressed_unchecked`. Returns `ZkeyError::ManifestMismatch` on tamper.
3. **`main.rs::verify_ceremony_manifests`**: at startup, recomputes the contribution chain hash from `manifest.contributions[]` and verifies the coordinator BJJ-EdDSA signature against `state.bjj_trusted_issuers` (audit M-3). Production: any failure is `exit(2)`. Dev: `tracing::error!` + continue.

For production: set `OLYMPUS_CEREMONY_COORDINATOR_KEY` when running setup scripts; add the coordinator pubkey to consumer machines' `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`.

### Frontend (`app/public-ui/`)

React + TypeScript + Vite + Tailwind + React Query. API client in
`app/public-ui/src/lib/api.ts`. Notable v0.9.x components:

- `InitialSecretsModal.tsx` — one-shot bootstrap dialog surfacing the API key + BJJ key on first launch
- `StartupErrorScreen.tsx` — production startup-error landing page
- `WhoAmIChip.tsx` — current-user / scope chip in the header
- `CredentialsPage.tsx` — SBT issue / list / revoke / verify UI
- `AdminUsersPage.tsx` — admin Users page (mint keys, edit scopes, promote roles)

### Cross-Language Verifiers (`verifiers/`)

Reference implementations in Rust and JavaScript — used for differential
fuzzing and offline proof verification. Test vectors in
`verifiers/test_vectors/vectors.json`.

## Critical Invariants

- **Domain prefixes**: Node hashes use `OLY:NODE:V1|`; the empty-leaf sentinel uses `OLY:EMPTY-LEAF:V1`. Leaf hashes use the **ADR-0005 structured binary prefix** (`u8(0x01) || "OLY" || u8(0x01)=LEAF || u8(0x01)=V1 || lp(shard_id)`), not the legacy `OLY:LEAF:V1|` ASCII tag. Constants live in `crates/olympus-crypto/src/lib.rs` (`OLY_STRUCT_MARKER`, `OLY_NAMESPACE`, `LEAF_OBJECT_TYPE`, `LEAF_VERSION`, `LEAF_BODY_FIELD_COUNT`, `NODE_PREFIX`, `KEY_PREFIX`, `EMPTY_LEAF_PREFIX`, `PEDERSEN_H_PREFIX`; `LEAF_PREFIX` is retained as a pinned legacy marker). The desktop crate consumes them via the `olympus-crypto` workspace dep.
- **Leaf hash binds shard + parser provenance** — `leaf_hash(shard_id, key, value_hash, parser_id, canonical_parser_version, model_hash)`: structured prefix with length-prefixed `shard_id` (ADR-0005), then a `0x05`-count-framed body of `lp(key) || value_hash || lp(parser_id) || lp(cpv) || lp(model_hash)` (ADR-0003 + ADR-0004). `value_hash` is raw (must be 32 bytes); all four string fields must be non-empty. Changing the field set / layout is a breaking hash change: update `olympus_crypto`, both SMTs, both verifiers, the `smt_leaves` schema, AND regenerate the SSMF golden vectors (`cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt`) in the same commit. SMT vectors are the single source of truth in `verifiers/test_vectors/vectors.json` — both verifiers load it directly.
- **Ed25519 signing keys must be persisted** — ephemeral keys make historical signed roots unverifiable.
- **Baby Jubjub authority key must be persisted** — same reasoning; required for SBT signing and the unified-API-key derivation (`derive_api_key_from_bjj`).
- **Canonical JSON**: Always JCS/RFC 8785 raw UTF-8.
- **SBT scope mapping is hardcoded in `auth.rs`** — fail-closed: unknown `credential_type` grants no scopes. Treat the mapping as security policy, not config.
- **Quorum signatures are domain-separated** — quorum co-signatures sign `BLAKE3("OLY:SBT:QUORUM:V1" | commit_id_hex)`, disjoint from single-issuer (bare `commit_id`) and revocation (`OLY:SBT:REVOKE:V1`) signatures, so a signature minted in one role can't be replayed in another. The M-of-N signer set and threshold are pinned on the credential row for reproducible offline verification. The `federation_quorum` ZK circuit (feature `quorum-circuit`) is next-phase / ceremony-pending — the explicit signature set is authoritative.
- **Ceremony manifests are atomic** — any change to a vkey JSON requires regenerating its manifest in the same commit. `cargo build` panics if `blake3(vkey.json) != manifest.artifacts.vkey.blake3`; the runtime additionally refuses to load a `.ark.zkey` whose blake3 disagrees. See `proofs/CEREMONY_INTEGRITY.md`. Never hand-edit `proofs/keys/manifests/*.json` — re-run `setup_circuits.sh`.
- **`prove_circom` is the only sanctioned proving entry** — `src-tauri/src/zk/zkey.rs::CircomProvingKey` (M-5) seals the proving-key type so callers cannot bypass `CircomReduction` and fall back to `LibsnarkReduction` (root cause of #1011).
- **Persistent SMT writers serialise** — `NodeBackend::acquire_write_lock` (H-4, Postgres `pg_advisory_lock` or in-mem `tokio::Mutex`) MUST be held across the read-modify-write in `update_batch`; the hot cache is also refreshed inside the locked section to avoid stale-cache stomp.
- **`/zk/verify` enforces the `treeSize=0` invariant** (H-2) — proofs against the document-existence or unified circuits with `treeSize=0` are rejected unless `root` equals `zk::poseidon::empty_doc_existence_root()`.

## Environment

Key `.env` variables:
- `OLYMPUS_API_PORT` — HTTP port for the embedded Axum server (default ephemeral; tests pin to 3737)
- `OLYMPUS_INGEST_SIGNING_KEY` — persistent Ed25519 key (production); use `OLYMPUS_DEV_SIGNING_KEY=true` for dev auto-generation
- `OLYMPUS_BJJ_AUTHORITY_KEY` — persistent Baby Jubjub authority key (32-byte hex); auto-generated by bootstrap if absent
- `OLYMPUS_PROOFS_DIR` — override the resolved ZK artifacts directory (precedence: env > Tauri resource_dir > exe-relative > `proofs/keys`)
- `OLYMPUS_INGEST_PARSER_ID` / `INGEST_PARSER_CANONICAL_VERSION` / `OLYMPUS_INGEST_MODEL_HASH` — parser provenance stamped onto every leaf the ingest path commits into the parser-bound SMT (ADR-0003 / ADR-0004). Defaults: `fallback@1.0.0` / `v1` / `none`. Blank values fall back to defaults (the triple is always non-empty). Resolved once at startup into `AppState.ingest_provenance`.
- `OLYMPUS_ENV=production` — refuse to start with `exit 2` if any ZK artifact is a `PLACEHOLDER` stub OR if any ceremony-manifest check fails
- `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` — extra trusted-issuer entries (audit M-3): JSON array of `{"x":"...","y":"...","valid_from":<unix?>,"valid_until":<unix?>}`. Bootstrap pubkey is always entry 0; this adds rotation-window or coordinator-key entries.
- `OLYMPUS_CEREMONY_COORDINATOR_KEY` — preferred 32-byte hex key for `generate_manifest`; falls back to `OLYMPUS_BJJ_AUTHORITY_KEY` then to a fixed dev key
- `OLYMPUS_CEREMONY_ID` / `OLYMPUS_CEREMONY_CONTRIBUTOR` — optional metadata fields embedded into generated manifests
- `OLYMPUS_TRUST_FORWARDED_FOR=true` — L-3 escape hatch; only safe behind a same-host reverse proxy that strips and rewrites `X-Forwarded-For`
- `OLYMPUS_FEDERATION_QUORUM_THRESHOLD` — default M for M-of-N quorum credentials (clamped `≥ 1`); per-request `quorum_threshold` overrides it
- `OLYMPUS_ADMIN_KEY` — separate header `x-admin-key` required by `/key/admin/generate` and `/key/admin/reload-keys`
- `OLYMPUS_ANCHOR_RFC3161_URL` — RFC 3161 TSA endpoint (e.g. `https://freetsa.org/tsr`); enables RFC 3161 anchoring
- `OLYMPUS_ANCHOR_REKOR_URL` — Sigstore Rekor URL (e.g. `https://rekor.sigstore.dev`); enables Rekor anchoring
- `OLYMPUS_ANCHOR_OTS_CALENDARS` — comma-separated OpenTimestamps calendar URLs; enables OTS anchoring
- `OLYMPUS_ANCHOR_SIGN_KEY` — Ed25519 hex key for Rekor signatures (falls back to `OLYMPUS_INGEST_SIGNING_KEY`)
- `DATABASE_URL` — external Postgres URL; if set, skips pg_embed but still applies migrations
- `CORS_ORIGINS` — explicit comma-separated origins (no wildcards)
