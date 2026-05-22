# Changelog

All notable changes to the Olympus protocol are documented in this file.

## Unreleased

_No changes yet._

## v0.9.1 — 2026-05-22

### Added

- **SBT-driven scope resolver** (#949) — `AuthenticatedKey` extractor in
  `src-tauri/src/api/middleware/auth.rs` now unions the legacy
  `api_keys.scopes` column with scopes derived from active SBTs the holder
  owns (joined via `holder_key = "bjj:{x}:{y}"`). Mapping is hardcoded and
  fail-closed; unknown `credential_type` values grant nothing.
- **Native Olympus-signed Soulbound Tokens** (#942) — `src-tauri/src/api/credentials.rs`
  exposes `POST /credentials`, `GET /credentials/{id}`, `GET /credentials`,
  `POST /credentials/{id}/revoke`, `POST /credentials/{id}/verify`. Every
  row is BJJ-EdDSA-signed by the federation authority key at issue time
  (and again at revocation time) so verifiers don't need a network round-trip
  back to the node. See `docs/sbt-deployment.md`.
- **Unified API key ↔ Baby Jubjub identity** (#945) — `derive_api_key_from_bjj`
  computes `api_key = "oly_" || hex(BLAKE3("OLY:APIKEY:V1" || bjj_priv))`,
  so a holder has one master secret and the API key is a one-way derivation
  of it. Migration `0028_api_keys_bjj_pubkey.sql` adds `api_keys.bjj_pubkey_x/y`.
- **In-app admin Users page** (#939) — `src-tauri/src/api/admin_users.rs`
  exposes `/admin/users/*` for minting keys, editing scopes, and promoting
  roles from the desktop UI.
- **One-shot bootstrap-keys modal** (#940) — `InitialSecretsModal.tsx`
  surfaces the freshly-generated API key + BJJ private key on first launch
  via the `take_initial_secrets` IPC command.
- **UX perf + papercut batch** (#941, #943) — SkylineBackdrop rAF +
  drop-shadow optimisations, GlitchMentor reduced-motion respect, typed
  `ApiError`, ScopeBanner, drag-drop hint, BootProgress overlay, native file
  picker, modal copy-gate, production startup screen, WhoAmI chip.
- **External anchoring of checkpoints to three independent third-party
  services** so existence of a signed root at time T is verifiable
  without trusting any Olympus operator:
  - `src-tauri/src/anchoring/rfc3161.rs` — RFC 3161 TSA client (hand-rolled
    minimal DER encoder for `TimeStampReq`; receipt blob stored verbatim
    for offline verification via `openssl ts`).
  - `src-tauri/src/anchoring/rekor.rs` — Sigstore Rekor `hashedrekord/v0.0.1`
    client; signs the anchored hash with the operator's Ed25519 key
    (`OLYMPUS_ANCHOR_SIGN_KEY` or `OLYMPUS_INGEST_SIGNING_KEY`) and POSTs
    to `/api/v1/log/entries`.
  - `src-tauri/src/anchoring/ots.rs` — OpenTimestamps calendar client;
    `try_upgrade` re-fetches the receipt once the Bitcoin commit settles
    so the final proof is verifiable against the public Bitcoin chain.
- **`anchor_receipts` table** (migration `0026_add_anchor_receipts.sql`):
  append-only store keyed by `(anchored_hash, anchor_kind)`, optional
  FK to a federation `checkpoint_id`, JSON metadata column for
  anchor-specific structured fields.
- **HTTP routes** for inspecting receipts (scope `read`/`verify`/`admin`):
  - `GET  /anchors` — paginated list (newest first; optional
    `?checkpoint_id=<uuid>` filter).
  - `GET  /anchors/{id}` — JSON metadata + base64 receipt.
  - `GET  /anchors/{id}/receipt` — raw receipt bytes with anchor-specific
    `Content-Type` (e.g. `application/timestamp-reply` for RFC 3161) so
    `openssl ts -verify` / `rekor-cli` / `ots verify` consume directly.
- **`checkpoint_anchor_hash`** — domain-separated BLAKE3 digest binding a
  receipt to the full signed-state tuple
  (`OLY:CHECKPOINT_ANCHOR:V1 | ledger_root | tree_size | timestamp | authority | sig`),
  not the raw `ledger_root` (which by itself isn't unique across no-op
  checkpoints).
- **`docs/court-evidence.md`** — expert-witness packet: the cryptographic
  primitives, their admissibility under Daubert, and the minimal command
  sequences for an opposing-party expert to verify a bundle on their own
  hardware using only `b3sum`, `openssl ts`, `rekor-cli`, and `ots verify`.

### Fixed

- **TIMESTAMPTZ decode mismatch in admin Users** (#944) — `UserKeyRow` in
  `src-tauri/src/api/admin_users.rs` was decoding `users.created_at` as
  `chrono::NaiveDateTime` against a `TIMESTAMPTZ` column, causing
  `GET /admin/users` to 500 with a valid admin key. Fixed by switching to
  `chrono::DateTime<chrono::Utc>`.

### CI

- **CodeQL re-enabled** (#947) — `.github/workflows/codeql.yml` restores
  CodeQL security analysis targeting JavaScript/TypeScript with the
  `security-extended,security-and-quality` query suites. Weekly cron plus
  push/PR to `main`. (Rust CodeQL deferred — manual build mode against
  arkworks + Tauri is too slow for per-PR runs; `cargo-audit` and the
  `supply-chain` job already cover Rust CVEs.)
- **CodeRabbit auth + atomicity fixes** — security/auth/atomicity/validation
  corrections from CodeRabbit review on `feat/zk-http-routes-v2`.

### Documentation

- **`docs/session-report-2026-05-22.md`** (#946) — PR map, design
  directions surfaced during the session (SBT-driven scope resolution,
  burn-on-grant lifecycle, "all can sign in & verify"), and the
  next-session work order.
- **`CLAUDE.md`, `docs/architecture.md`, `docs/development.md`,
  `docs/quickstart.md`** — rewritten to reflect the Tauri-only / Rust-only
  reality. Python and Go retirements documented.

### Configuration

- `OLYMPUS_ANCHOR_RFC3161_URL` — RFC 3161 TSA endpoint (e.g.
  `https://freetsa.org/tsr`).
- `OLYMPUS_ANCHOR_REKOR_URL` — Rekor instance (e.g.
  `https://rekor.sigstore.dev`).
- `OLYMPUS_ANCHOR_OTS_CALENDARS` — comma-separated OTS calendar URLs.
- `OLYMPUS_ANCHOR_SIGN_KEY` — Ed25519 key for Rekor submission (32-byte
  hex; falls back to `OLYMPUS_INGEST_SIGNING_KEY`).
- All four are optional; with none set, anchoring is fully disabled.

### Fixed

- **Unified ZK circuit T3001** —
  `unified_canonicalization_inclusion_root_sign.circom` was reading
  `MerkleTreeInclusionProof.root` as an output when the template declares
  it as an *input* (`lib/merkleProof.circom:64`). Changed two call sites
  from `===` (read + constraint) to `<==` (assign + constraint), which
  preserves the security property and lets the circuit compile.

---

## v0.9.0 — 2026-05-22

Feature-complete release ahead of v1.0. Holds back from 1.0 only on
the Phase 2 trusted setup contributor count (single-contributor dev
keys ship; multi-contributor ceremony tooling is in-tree and required
before v1.0).

### Added

- **In-process ZK prover endpoints.** `POST /zk/prove` (scope `prove`
  or `admin`) and `POST /zk/verify` (scope `verify`/`read`/`admin`),
  both rate-limited and key-authenticated. Verifier ships with
  vkeys for `document_existence`, `non_existence`, `redaction_validity`,
  and `unified_canonicalization_inclusion_root_sign` embedded via
  `include_str!`; prover loads `.ark.zkey` from the resolved
  `proofs_dir` at runtime.
- **AppState.proofs_dir resolution.** Resolved once at startup from
  `OLYMPUS_PROOFS_DIR` env var, Tauri `resource_dir`, exe-relative
  `proofs/keys`, or repo-relative dev fallback (first that contains
  a `verification_keys/` subdir wins).
- **OLYMPUS_ENV=production hard gate.** Binary refuses to start with
  `exit 2` if any ZK artifact in the resolved `proofs_dir` is a
  `PLACEHOLDER`-prefixed stub (i.e. setup hasn't run).
- **`prove` scope** added to `VALID_SCOPES` for `POST /key/admin/generate`
  so operators can mint dedicated prover keys without `admin` rights.
- **`proofs/phase2_ceremony.sh`** — multi-contributor Phase 2 Groth16
  ceremony orchestration with four subcommands: `prepare`, `contribute`,
  `verify`, `finalize` (with optional `--beacon`). Required for v1.0.
- **Federation feature** (`--features federation`) — Tor hidden service
  (arti-client 0.27), peer node management (add/remove/trust), checkpoint
  gossip, equivocation detection, auto-blocking, BJJ-signed checkpoints.
- **`crates/light-poseidon/`** — vendored from
  Lightprotocol/light-poseidon v0.4.0 with arkworks deps bumped to 0.6
  (upstream is still pinned to 0.5). Required because Poseidon hash
  output must remain byte-identical with existing Merkle roots.
- **`src-tauri/build.rs`** — writes `PLACEHOLDER` artifact stubs at
  build time so Tauri's `bundle.resources` glob has matching files
  before the trusted setup is run.
- **`src-tauri/src/bin/export_ark_zkey`** — converts snarkjs `.zkey`
  to arkworks-serialised `.ark.zkey` for fast in-process prover load.
- **`tauri.conf.json` bundle.resources** — ships the ZK artifacts
  (`.wasm`, `.r1cs`, `.ark.zkey`, vkey JSONs) inside the desktop bundle.

### Changed

- **arkworks 0.5 → 0.6** across the entire workspace (ark-bn254,
  ark-ff, ark-ec, ark-groth16, ark-serialize, ark-relations, ark-snark,
  ark-circom). Drops `tracing-subscriber 0.2.25` from the dependency
  tree (closes RUSTSEC-2025-0055) plus three other unmaintained-marker
  advisories. Existing Merkle roots remain byte-identical (verified via
  light-poseidon upstream regression test + 85 lib tests including
  `sign_then_verify_via_iden3_roundtrip`).
- **`db::connect_external` now runs `sqlx::migrate!`** after connect,
  fixing the silent-503 trap where pointing `DATABASE_URL` at a fresh
  schema left every DB-backed route returning 503 forever.
- **`proofs/setup_circuits.sh`** — adds the unified circuit to the
  CIRCUITS array, runs `export_ark_zkey` after Groth16 setup, and
  copies `.wasm`/`.r1cs` into `proofs/keys/` alongside the new
  `.ark.zkey`. Single-source artifact directory for the runtime.
- **`update_trust` (federation)** — validates trust status against
  the allowed `pending`/`trusted`/`blocked` set before executing the
  UPDATE, returning 400 on bad input instead of leaning on the DB
  CHECK constraint.

### Fixed

- **Unified circuit T2011 error** — hoisted per-iteration
  `Num2BitsStrict` declaration out of the section-chain `for` loop into
  a `component lengthBits[maxSections]` array (circom forbids component
  declarations inside loop scopes).
- **`AppState::new_with_error` duplicate BJJ key loading** — removed
  ~30 lines of `OLYMPUS_BJJ_AUTHORITY_KEY` env-var parsing that was
  shadowed by `bootstrap::run()`.

### Security advisory baseline

Drops 4 entries from `cargo-audit-baseline.txt` (all gone from the
lockfile after the arkworks 0.6 upgrade):

| ID                  | Crate                |
|---------------------|----------------------|
| RUSTSEC-2025-0055   | tracing-subscriber   |
| RUSTSEC-2023-0089   | atomic-polyfill      |
| RUSTSEC-2025-0141   | bincode 1.x          |
| RUSTSEC-2025-0057   | fxhash               |

---

## v1.0.0 — 2026-05-16

### Changed

- **Python ingest write path now honours `OLYMPUS_USE_GO_SEQUENCER`.** When
  the flag is enabled, `POST /ingest/commit` routes the artifact append
  through the Go sequencer (`GoSequencerClient.append_record` +
  `get_inclusion_proof`) instead of calling
  `StorageLayer.append_record` against PostgreSQL directly. Backend
  selection lives behind a new `append_via_backend` adapter in
  `api/services/storage_layer.py`, which normalises both backends into a
  single `AppendRecordResult` dataclass and maps sequencer transport
  failures to consistent HTTP statuses (`SequencerUnavailableError` →
  `503`, `SequencerResponseError` → `502`). With the flag off, behaviour
  is unchanged: the storage-layer call still runs (now dispatched to a
  worker thread so the FastAPI event loop is never blocked by the sync
  Postgres write).

### Added

- **`GoSequencerClient.get_signed_root_pair(old_tree_size, new_tree_size)`**
  in `api/services/sequencer_client.py` mirrors the renamed
  `/v1/get-signed-root-pair` endpoint on the Go sequencer. Returns a
  `SequencerSignedRootPair` dataclass with the two signed roots so
  callers can verify the signatures and compare hashes offline. This is
  not an RFC-6962 consistency proof; it is the Python wrapper for the
  same endpoint that previously lived behind the misleading
  `/v1/get-consistency-proof` name (now `410 Gone` on the Go side).
- `api/main.py` lifespan shutdown now also closes the
  `GoSequencerClient` singleton (`close_sequencer_client()`) alongside
  the older httpx client embedded in `api/ingest.py`, so both connection
  pools drain cleanly on process exit.

### Breaking Changes

- **ADR-0003: Parser identity is now bound into the SMT leaf hash domain
  separator.** The `OLY:LEAF:V1` leaf hash now appends two
  length-prefixed fields (`parser_id`, `canonical_parser_version`) after
  `value_hash`:

      BLAKE3(
          "OLY:LEAF:V1" || SEP ||
          key || SEP ||
          value_hash || SEP ||
          len(parser_id)[4B BE]               || parser_id || SEP ||
          len(canonical_parser_version)[4B BE] || canonical_parser_version
      )

  Two records produced by different parser versions now hash to distinct
  leaves. The static `OLY:LEAF:V1` prefix is unchanged; no `leaf_hash_v2`
  function is introduced. Because no ledger exists yet, there is no
  migration: all `leaf_hash`, `SparseMerkleTree.update`,
  `incremental_update`, `prove_existence`, `ExistenceProof`, the
  `cdhs-smf-rust` crate, the `cdhs_smf.proto` `LeafEntry`/`UpdateRequest`
  /`VerifyInclusionRequest`/`ProveInclusionResponse` messages, the
  `smt_leaves` Postgres schema, the proof-bundle JSON, and every
  language verifier (Python/Rust/Go/JS) require the two new fields.
  `parser_id` is `"<name>@<version>"` (fallback `"fallback@1.0.0"`);
  `canonical_parser_version` is set by operators via
  `INGEST_PARSER_CANONICAL_VERSION` (default `"v1"`). Empty strings are
  rejected. Golden vectors and `verifiers/test_vectors/vectors.json`
  ssmf blocks have been regenerated.

- **`POST /datasets/commit` and `POST /datasets/{id}/lineage` now return
  immediately with `timestamp_status="pending"` (H-5).** The RFC 3161
  timestamp call has been moved out of the request handler into a
  dedicated background worker (`api.workers.tsa_worker`). Clients that
  previously read `rfc3161_tst_hex` synchronously from the commit response
  will now always see `null` until the worker has stored a token —
  typically within a few seconds, but bounded by the configurable grace
  window `TSA_GRACE_SECONDS` (default 300). Operators must run the new
  worker process (`python -m api.workers.tsa_worker` or the
  `olympus-tsa-worker` console script) alongside the API for tokens to
  ever be persisted.
- **`GET /datasets/{id}/verify` adds a new `timestamp_state` field with
  values `verified | pending_within_grace | pending_past_grace | failed`
  (H-5).** The legacy boolean `rfc3161_valid` is preserved for backward
  compatibility but collapses pending-within-grace and pending-past-grace
  into the same `false` value. Witnesses and downstream verifiers should
  read `timestamp_state` to distinguish "still being processed" from
  "permanently failed". A row that previously rendered as
  `rfc3161_valid=false` because the inline TSA call had timed out will
  now report `timestamp_state="pending_within_grace"` (and eventually
  flip to `verified` once the worker lands a token, or `failed` once the
  sweeper or worker exhausts retries).

### Security

- **TSA call hardening (H-5 Tier 0).** `protocol.rfc3161.request_timestamp`
  now passes an explicit `timeout=5.0` to `rfc3161ng.RemoteTimestamper`,
  bounding the TCP round-trip. Previously the default 10-second timeout
  applied; combined with the synchronous inline call this allowed a hung
  TSA to pin FastAPI workers indefinitely.

### Breaking Changes

- **Sequencer endpoint renamed: `/v1/get-consistency-proof` →
  `/v1/get-signed-root-pair`** (`services/sequencer-go/internal/api/sequencer.go`)
  The original name was misleading: the handler returned a pair of signed
  roots for offline comparison, not an RFC-6962 / Trillian consistency
  proof. Anything an external verifier might have built on the old name
  would have overstated the cryptographic guarantee (H-2). The new name
  describes what the endpoint actually returns. The old path is preserved
  for one release as a deprecated alias that returns HTTP `410 Gone` with
  a body pointing to the successor (rather than a silent 301 redirect, to
  avoid masking the semantic change). The deprecated alias will be removed
  in the next release. A real RFC-6962-style consistency proof for the
  CD-HS-ST sparse Merkle tree is tracked as a follow-up; the proof shape
  differs from RFC 6962 and requires its own design.

### Documentation

- **SECURITY.md: Sequencer Token Trust Model** — Documented the v1.0 trust
  assumption that possession of the sequencer's `X-Sequencer-Token`
  bearer token grants append authority for any leaf in any shard, the
  threats this model does not defend against, the operator mitigations
  required to deploy the sequencer safely, and explicit non-goals for
  v1.0 (per-shard authorization, multi-tenant scoping, capability
  tokens) with a forward reference to Guardian replication for
  multi-party trust distribution.

### CI / Supply Chain

- **govulncheck added to `supply-chain` job** (`.github/workflows/ci.yml`)
  The Go modules under `verifiers/go/` and `services/sequencer-go/` are
  now audited on every PR alongside the existing `pip-audit`,
  `cargo audit`, and `npm audit` steps. Suppressions are managed via
  `go-vuln-baseline.txt` (mirrors the format of `pip-audit-baseline.txt`
  and `cargo-audit-baseline.txt`) and applied by
  `scripts/run-govulncheck.sh`, which post-filters `govulncheck -json`
  output by OSV id and aliases (CVE / GHSA). Only call-graph–reachable
  findings cause CI failure.

## canonical_v2 (Round 2) — 2026-03-26

### Breaking Changes

- **Merkle tree: 0x00/0x01 domain separation** (`api/services/merkle.py`)
  Internal node hashes are now computed as `H(0x01 || left || right)` and
  leaf hashes as `H(0x00 || data)`, following RFC 6962 conventions.  This
  prevents a crafted leaf value from colliding with an internal node hash
  and eliminates structural ambiguity in the tree.  All Merkle roots change.
  Pre-launch determination: no stored proofs reference unprefixed roots in
  a way that cannot be regenerated, so no `CANONICAL_VERSION` bump is needed.

### Fixes

- **Unicode homoglyph scrub** (`protocol/canonical.py`)
  `_scrub_homoglyphs()` replaces Unicode characters whose NFKD form is a
  single ASCII printable character with that ASCII character.  This catches
  fullwidth Latin (`Ａ` → `A`), mathematical bold/italic (`𝐔` → `U`), and
  enclosed alphanumerics without touching legitimate non-ASCII (Arabic, CJK,
  accented Latin).  Controlled via `scrub_homoglyphs=True/False` parameter
  on `canonicalize_document()` and `document_to_bytes()`.

- **Schema-annotated list sorting** (`protocol/canonical.py`)
  Added `sorted_list_keys: set[str] | None` parameter to
  `canonicalize_document()` and `document_to_bytes()`.  Fields named in the
  set have their array values sorted deterministically using canonical JSON
  as the sort key.  Default is `None` (preserve order) for backward
  compatibility.

- **Idempotency gate** (`api/ingest.py`)
  `IngestionResult` now includes an `idempotent: bool` field, set `True`
  when a duplicate submission returns the existing record instead of creating
  a new ledger entry.  The existing content-hash dedup check was already
  enforced before any ledger write; this field lets callers distinguish fresh
  inserts from deduplicated returns.

- **Mixed crypto isolation** (`api/ingest.py`, `api/auth.py`)
  `hmac.compare_digest` calls replaced with `_constant_time_equals()` wrapper
  that documents its sole use is timing-safe comparison (not MAC computation).
  Clarifies the crypto boundary: BLAKE3 for hashing, Ed25519 (nacl) for
  signing, `hmac.compare_digest` only for constant-time equality.

- **Proof depth validation** (`api/services/merkle.py`)
  `MerkleProof` now carries `tree_size`; `verify_proof()` validates that
  proof depth matches `ceil(log2(tree_size))` and rejects invalid sibling
  direction values.  `tree_size=0` disables the check for legacy proofs.

- **BLAKE3/Poseidon canonical-hash binding** (`proofs/proof_generator.py`)
  Added `recompute_canonical_hash()` and `_validate_canonical_hash_binding()`
  to the unified circuit validator.  Before witness generation, the Python
  layer independently recomputes the Poseidon chain from `sectionCount`,
  `sectionLengths`, and `sectionHashes`, and rejects inputs where
  `canonicalHash` does not match.  This closes the binding gap between the
  BLAKE3 canonicalization layer and the Poseidon ZK circuit.

## canonical_v2 (Round 1) — 2026-03-26

### Breaking Changes

- **Merkle tree: lone-node self-pair instead of promotion** (`api/services/merkle.py`)
  Lone nodes at any level of the Merkle tree are now duplicated and hashed
  (`H(node || node)`) instead of being promoted without rehashing.  This
  prevents an attacker who controls batching boundaries from producing
  alternate valid roots from the same dataset.  Any tree with an odd leaf
  count will produce a different root than under `canonical_v1`.

### Fixes

- **Numeric canonicalization** (`protocol/canonical.py`)
  `_canonicalize_value()` now normalises numeric types: whole floats are
  converted to `int`, non-whole floats to `Decimal`, and `NaN`/`Inf` are
  rejected with `CanonicalizationError`.  This ensures semantically
  equivalent JSON representations (`100`, `100.0`, `1e2`) produce the same
  canonical bytes.

- **Merkle leaf ordering** (`api/services/merkle.py`)
  `build_tree()` now sorts leaf hashes lexicographically by default so that
  federation nodes ingesting the same dataset in different arrival orders
  produce identical Merkle roots.  A `preserve_order=True` parameter is
  available for append-only log proofs where positional ordering is required.

### Migration

`CANONICAL_VERSION` has been bumped from `canonical_v1` to `canonical_v2`.
`SUPPORTED_VERSIONS` includes both `canonical_v1` and `canonical_v2` so that
the verifier can still accept proofs generated under the old version (with a
deprecation warning).  A full migration layer is planned for a follow-up PR.
