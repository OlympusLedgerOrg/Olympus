# AGENTS.md

`AGENTS.md` is the only agent-instructions document here; `CLAUDE.md` and
`.github/copilot-instructions.md` point to it, and `context.json` holds
machine-readable facts, not guidance — put new instructions here, never in a
second copy.

Current version: **v0.10.0** (June 2026).

## Absolute Upstream Boundary

This is a permanent, non-negotiable owner policy.

- Never submit, open, update, comment on, review, approve, merge, or otherwise interact with a pull request or issue in a repository outside `OlympusLedgerOrg`.
- Never push commits, branches, tags, patches, or releases to an external repository or an external maintainer's branch.
- Treat all repositories outside `OlympusLedgerOrg` as read-only. They may be inspected for research, comparison, security review, or vendoring only.
- Keep all implementation work in repositories and forks controlled by `OlympusLedgerOrg`. Internal pull requests within `OlympusLedgerOrg` are allowed.
- Before every GitHub write, verify the destination owner. If it is not exactly `OlympusLedgerOrg`, stop. Do not ask for routine confirmation and do not proceed through another tool.
- If asked to upstream work, provide a local or `OlympusLedgerOrg`-owned patch only. The AI must never perform or facilitate the upstream submission.
- Task wording such as "send it," "open the PR," "submit upstream," or "do everything" does not override this boundary.

## Commands

```bash
cargo tauri dev                        # dev build, hot-reload frontend (primary)
cargo tauri build                      # production binary + installers
cargo check --workspace                # fast type/lint check
cargo test --workspace                 # all Rust unit tests
cargo test -p olympus-desktop <name>   # one test (src-tauri's package is `olympus-desktop`)
pnpm install                           # JS deps
pnpm --filter public-ui build          # production frontend build
```

`docs/development.md` owns the rest (nextest, doctests, fmt, clippy,
`scripts/dev.py`, feature-gated runs); `docs/quickstart.md` owns
first-time setup, including the one-time `cd proofs && bash setup_circuits.sh`
that must precede `cargo tauri build`. Migrations in `migrations/` apply on
startup — there is no migrate command. Both hash-vector commands are named in
Critical Invariants rather than here.

## Architecture

`docs/architecture.md` owns the component map and `context.json` the workspace
layout (`olympus_context` serves it without a model call).

**Language ownership.** Rust: Tauri app, embedded Axum server, the cryptographic
hot path (BLAKE3, Ed25519, Poseidon, SMT, canonicalization), `pg_embed`, every DB
operation, SBTs, anchoring. TypeScript: `app/public-ui/` only. Python:
`clients/python/`, a verify-only SDK — not a service. Go and server-side Python are
retired; `verifiers/` (Rust + JavaScript) holds the reference implementations and
`clients/python` re-implements the leaf hash, so a hash change touches all four.

**Layout.** `src-tauri/` (`startup.rs`, `server/mod.rs`), `crates/olympus-crypto` (the
authoritative hash and SMT constants), `proofs/`,
`verifiers/`, `clients/python/`, `app/public-ui/`, `migrations/` — five workspace
members, and six other Cargo workspaces that need `--manifest-path`
(`context.json.workspace`).

**Two names that mislead.** Redaction is not a SNARK (ADR-0030): an Ed25519
signature over a variable-depth Poseidon fold of hiding leaves, zero-filled in
place by format-specific `Segmenter`s (`zk/segment/`) so non-redacted units stay
byte-identical. `unified_canonicalization_inclusion_root_sign` is a historical
stem: its live R1CS proves section-commitment inclusion over the root only — the
public protocol composes that with a RISC Zero receipt — and the `_sign` API
returns 410 Gone.

## Critical Invariants

- **Domain prefixes**: Node hashes use `OLY:NODE:V1|`; the empty-leaf sentinel uses `OLY:EMPTY-LEAF:V1`. Leaf hashes use the **ADR-0005 structured binary prefix** (`u8(0x01) || "OLY" || u8(0x01)=LEAF || u8(0x01)=V1 || lp(shard_id)`), not the legacy `OLY:LEAF:V1|` ASCII tag. Constants live in `crates/olympus-crypto/src/lib.rs` (`OLY_STRUCT_MARKER`, `OLY_NAMESPACE`, `LEAF_OBJECT_TYPE`, `LEAF_VERSION`, `LEAF_BODY_FIELD_COUNT`, `NODE_PREFIX`, `KEY_PREFIX`, `EMPTY_LEAF_PREFIX`, `PEDERSEN_H_PREFIX`; `LEAF_PREFIX` is retained as a pinned legacy marker). The desktop crate consumes them via the `olympus-crypto` workspace dep.
- **Leaf hash binds shard + parser provenance** — `leaf_hash(shard_id, key, value_hash, parser_id, canonical_parser_version, model_hash)`: structured prefix with length-prefixed `shard_id` (ADR-0005), then a `0x05`-count-framed body of `lp(key) || value_hash || lp(parser_id) || lp(cpv) || lp(model_hash)` (ADR-0003 + ADR-0004). `value_hash` is raw (must be 32 bytes); all four string fields must be non-empty. Changing the field set / layout is a breaking hash change. There are **four** independent implementations of this layout — update every one in the same commit: (1) `olympus_crypto`, (2) both SMTs, (3) both offline verifiers (`verifiers/rust`, `verifiers/javascript`), and (4) the Python client SDK `clients/python/src/olympus_manifest/hashing.py`, which hardcodes its own copy of the ADR-0005 constants. Also update the `smt_leaves` schema AND regenerate **both** vector sets: `cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt` and `cargo run -p olympus-manifest --example gen_python_vectors > clients/python/tests/vectors.json`. SMT vectors are the single source of truth in `verifiers/test_vectors/vectors.json` — both offline verifiers load it directly; the Python client has a separate generated vector file that CI diffs against a fresh generation.
- **Ed25519 signing keys must be persisted** — ephemeral keys make historical signed roots unverifiable.
- **Baby Jubjub authority key must be persisted** — same reasoning; required for SBT signing and the unified-API-key derivation (`derive_api_key_from_bjj`).
- **Canonical JSON**: JCS/RFC 8785 _structure_ — object keys sorted by UTF-16 code unit, strings emitted as raw UTF-8 (non-ASCII is never `\uXXXX`-escaped; `\b`, `\t`, `\n`, `\f`, `\r` use the short escapes, and only the remaining C0 controls are emitted as `\uXXXX`) — plus **two deliberate Olympus divergences** that make it non-interoperable with a stock JCS library: (1) **NFC normalization** of keys and string values (RFC 8785 performs none), and (2) **exact-decimal number rules** rather than RFC 8785's ECMAScript double serialization, so e.g. `9007199254740993` canonicalizes to itself instead of `…992`. `crates/olympus-crypto/src/canonical.rs` is authoritative — do not re-derive a digest from a conformant JCS implementation and expect a match. `verifiers/javascript/verifier.js` carries an explicit "non-authoritative for the number domain" warning for this reason.
- **SBT scope mapping is hardcoded in `auth.rs`** — fail-closed: unknown `credential_type` grants no scopes. Treat the mapping as security policy, not config.
- **Shard creation is operator-controlled** — first-use of a new `shard_id` is gated by the `shards` registry (migration `0039_shards.sql`). `POST /ingest/files` (the only endpoint accepting a caller-supplied `shard_id`) calls `api::shards::authorize_write` unconditionally: a `shard_id` absent or inactive in `shards` is rejected `403` (creation must go through the `x-admin-key`-gated `POST /admin/shards`), and a shard bound to `owner_user_id` accepts writes only from that account or an `admin`-scoped key. The gate is always on (fail-closed) — there is no env switch. Migration `0039` seeds the default `files` shard and backfills existing distinct `shard_id`s so enabling it never locks out current data. This operator-controlled model is what removes the need for any hard cap on shard count: the registry, not a counter, bounds shard creation. (`/ledger/ingest/simple` is unaffected — it writes the fixed `DEFAULT_SHARD` and never takes a caller-supplied shard.)
- **The ledger is insert-only (ADR-0031 §2)** — ledger ingest commits go through the write-once guard in `smt::tree::update_batch_inner` (rejects rewriting a committed key to a *different* `value_hash`; an identical re-commit is a no-op), and there is **no** leaf-delete/tombstone path (`LeafUpdate` is the only mutation entry — no `remove`, no `DELETE FROM smt_*`). The guard raises a **typed** `smt::WriteOnceViolation` (never string-matched); `api::ingest::files::commit_to_parser_smt` classifies it as a non-retryable client conflict and `POST /ingest/files` maps it to `409`. *Transient* parser-SMT failures stay soft (row keeps `smt_committed = FALSE` as a backfill target — never a `409`/`500`). Every own-checkpoint emitted *with a BJJ authority key loaded* also carries a BJJ-signed `olympus_crypto::TransitionAttestation` (`OLY:SNAPSHOT:PERSIST:V1`, migration `0049`) binding `original_root → snapshot_root over snapshot_size`, verifiable offline against `persist_message`. (A keyless dev checkpoint would carry the attestation and its own signature both `None`; production cannot reach that path — `build_and_persist` requires the authority *public* key and the checkpoint cron supplies both key halves together, so a checkpoint is either fully signed or not emitted at all, and every consumer rejects a keyless row. A node whose BJJ authority key failed to load emits no checkpoints and returns `503` on ingest, rather than refusing to start.) A change that introduces a non-write-once ingest caller or any delete path is a security-policy change. The same row also carries a sibling attestation, `olympus_crypto::SmtRootAttestation` (`OLY:SMT:ROOT:V1`, migration `0060`, ADR-0044), BJJ-signing the shard's BLAKE3 CD-HS-ST parser-bound SMT subtree root jointly with `(ledger_root, tree_size)` — until ADR-0044 nothing signed or anchored that tree's root at all, so `PersistentSmt::prove` had no signed statement to verify against. Bundle export requires both attestations (schema `v4`); `GET /monitor/proof/blake3/{content_hash}` (`api::monitor::proof_blake3`, ADR-0044 follow-up) wires `PersistentSmt::prove` into a proof-serving endpoint, verified against the shard subtree root via the additive `olympus_crypto::smt::verify_*_proof_against_shard_root` functions (folding only the leaf-side 192 siblings — `prove()`'s own 256-sibling `root_hash` is the tree's *global* root, which does not equal the signed shard root). ADR-0044 still does not extend federation gossip — see its "What this does not do (yet)" section.
- **Quorum signatures are domain-separated** — quorum co-signatures sign a field element derived from a BLAKE3 digest that binds the credential **and its pinned quorum parameters** (audit R3-01). The exact preimage (`src-tauri/src/quorum/mod.rs::quorum_cosign_message`) is `"OLY:SBT:QUORUM:V2" || lp(commit_id_hex) || u32_be(threshold) || u32_be(signer_count) || Σ(lp(x) || lp(y))` over the *canonicalised, sorted* signer set, reduced into `Fr` via `from_le_bytes_mod_order`; `lp(·)` is a `u32` big-endian length prefix. Binding the threshold and signer set is what stops either being altered after issuance. **Do not implement an offline verifier from a shortened form of this formula** — omitting the threshold or signer set yields a different field element and rejects every valid signature. It is disjoint from single-issuer (signed over the `commit_id` field element with no quorum framing; the `commit_id` is itself domain-tagged `"OLY:SBT:V1"` for plaintext rows or `"OLY:SBT:COMMIT:V1"` for committed rows) and from revocation (`OLY:SBT:REVOKE:V1`), so a signature minted in one role can't be replayed in another. The M-of-N signer set and threshold are pinned on the credential row for reproducible offline verification, and `OLYMPUS_FEDERATION_QUORUM_THRESHOLD` is consulted **only at issuance**, never at verification. The `federation_quorum` ZK circuit (feature `quorum-circuit`) is next-phase / ceremony-pending — the explicit signature set is authoritative.
- **Ceremony manifests are atomic** — any change to a vkey JSON requires regenerating its manifest in the same commit. `cargo build` panics if `blake3(vkey.json) != manifest.artifacts.vkey.blake3`; the runtime additionally refuses to load a `.ark.zkey` whose blake3 disagrees. See `proofs/CEREMONY_INTEGRITY.md`. Never hand-edit `proofs/keys/manifests/*.json` — re-run `setup_circuits.sh`.
- **`prove_circom` is the only sanctioned proving entry** — `src-tauri/src/zk/zkey.rs::CircomProvingKey` (M-5) seals the proving-key type so callers cannot bypass `CircomReduction` and fall back to `LibsnarkReduction` (root cause of #1011).
- **Persistent SMT writers serialise** — `NodeBackend::begin_write` (H-4, `src-tauri/src/smt/backend.rs`) MUST own the whole read-modify-write in `update_batch`; the hot cache is also refreshed inside that section to avoid stale-cache stomp. The Postgres impl opens the transaction at `READ COMMITTED` (deliberately pinned so the advisory wait cannot snapshot early), sets `lock_timeout`, then takes `pg_advisory_xact_lock`; SQLite uses `BEGIN IMMEDIATE`, in-mem a `tokio::Mutex`. Because the lock is transaction-scoped, leaves and nodes commit or roll back together, and the refreshed cache is not published until `commit()` succeeds.
- **Lazy deep-node SMT storage (ADR-0022)** — `smt_nodes` persists only internal nodes with `depth ≤ LAZY_DEPTH` (`72`, in `src-tauri/src/smt/tree.rs`); deeper nodes are recomputed on read from the leaf "canopy" (the leaves sharing the key's first 72 bits = 9 bytes). Pure-physical: roots/proofs/verifiers are byte-identical (the in-memory `olympus_crypto::smt::SparseMerkleTree` is the parity oracle). `LAZY_DEPTH`/`CANOPY_RECOMPUTE_CAP` (`1024`) are **pinned consts**, mirrored in migration `0044`; a change is a migration-class event. **Over-cap exception:** a canopy with `> CANOPY_RECOMPUTE_CAP` live leaves (only reachable via 72-bit prefix collisions or non-hashed record keys) is _not_ recomputed — the read path reads its persisted deep nodes — so the write-path flush MUST keep persisting `depth > 72` nodes for it, evaluated at flush time against the post-batch live count and materialising the _whole_ canopy on a cap crossing. Migration `0044` prunes pre-existing deep rows except over-cap canopies.
- **`/zk/verify` enforces the `treeSize=0` invariant** (H-2) — proofs against the document-existence or unified circuits with `treeSize=0` are rejected unless `root` equals `zk::poseidon::empty_doc_existence_root()`.

## Before every `git push`

Two checks. Both exist because skipping them shipped real defects here, not as
generic hygiene.

### 1. Do the claims match the code?

Prose is load-bearing: ADRs and RFCs are what a future auditor reads, and a claim
that outruns the implementation stops anyone from looking. Re-read every behaviour
claim you touched:

- "the verifier checks X" needs a check that exists — RFC-0001's `/Length`
  recomputation was written twice, implemented in neither verifier, and the value
  is _elided from the commitment by design_;
- "same X — all reused" must survive checking: ADR-0029 claimed it and both
  verifiers _refused_ the format;
- a test must prove what its name says — a preimage recomputed by the code that
  produced it proves _agreement_, not _binding_, so mutate a covered byte, and make
  negative tests say _why_ they rejected;
- the PR body must still describe the diff (`pdfjs-dist` is Apache-2.0, not MIT).

### 2. Have the gates run in _every_ scope?

The invocation per scope drifts, so do not re-derive it: `tools/verify-gate/README.md`
owns the table and why a repo-root command is not equivalent. The gate runs the
checks for whatever the diff touched and stops at the first failure (`--fast`
drops the tests). Warnings are errors (`-D warnings`, `--max-warnings 0`) and must
not be filtered out.

```bash
node tools/verify-gate/verify.mjs
```

**`proofs/` is its blind spot.** A circuit change matches only the `anything` row,
so run CI's ZK checks yourself:

```bash
bash proofs/circomspect.sh      # blocking; --advisory / --update-baseline
bash proofs/formal_verify.sh --circomspect
cargo test -p olympus-desktop --test zk_witness_proptest
cargo test -p olympus-desktop --features prover,zk-test-utils --test zk_soundness   # feature-gated; skipped otherwise
```

## Environment

`.env.example` owns the variables, defaults and each flag's production rule;
`context.json` the short form for tooling. What neither states:

- `OLYMPUS_INGEST_PARSER_ID` / `INGEST_PARSER_CANONICAL_VERSION` /
  `OLYMPUS_INGEST_MODEL_HASH` — parser provenance on every ingested leaf
  (ADR-0003/0004); defaults `fallback@1.0.0` / `v1` / `none`, blanks fall back.
- `OLYMPUS_CEREMONY_TRUSTED_CONTRIBUTORS_JSON` — **required in production**: the
  allowlist `zk/manifest.rs` enforces (red-team A-2/A-4); missing or malformed
  there fails every manifest check, i.e. `exit(2)`. Its siblings
  `OLYMPUS_CEREMONY_ID` / `_CONTRIBUTOR` / `_COORDINATOR_KEY` are signing metadata
  (falling back to `OLYMPUS_BJJ_AUTHORITY_KEY`, then a dev key).
- `OLYMPUS_FEDERATION_QUORUM_THRESHOLD` — the default M only:
  `validate_quorum_params` still requires `2 ≤ M ≤ N`, so 1-of-N is `422`.
- `CORS_ORIGINS` — explicit origins, no wildcards.
- `WISEREPO_*` / `OLYMPUS_PROOFS_DIR` — tooling and proof-artifact lookup, owned by
  `tools/wiserepo/README.md` and `docs/development.md` (precedence, the debug-only
  fallback).

## PR review etiquette

Third-party service behaviour, observed from outside: nothing here implements or
verifies it, and the only part this repo controls is `.coderabbit.yaml`.
Accurate-as-observed, not invariants.

- Reply to every finding by mentioning `@coderabbitai` — replies feed its learnings
  database.
- **About 10 reviews per developer per hour** (Pro Plus), rolling and *adaptive* — a
  ceiling, not a budget; **pushing** spends it, so batch fixes into one push per
  round (the commit cap is `.coderabbit.yaml`'s setting).
- "Review triggered" is not confirmation — the bot *edits* it into the rate-limit
  warning. Ask `@coderabbitai rate limit`; a blocked push costs nothing.

## graphify

Use `graphify-out/` for structural navigation; when the user types `/graphify`,
follow the installed Graphify instructions first.

- `graphify query "<question>"` before raw source search when
  `graphify-out/graph.json` exists; `graphify path` / `explain` / `section` for
  relationships and focused concepts.
- There is **no `graphify-out/wiki/index.md`** — do not send a reader to one.
  `GRAPH_REPORT.md` is the only generated prose report, ~111 KB (≈28k tokens):
  never read it whole, `rg` the section you need.
- Dirty `graphify-out/` is expected after hooks or incremental updates; only stale
  or wrong output is a reason to skip graphify. It is gitignored: never commit it.
  `graphify update .` keeps it current (AST-only, no API cost).

## Agent and model routing

Use the least expensive capable tool without sacrificing correctness. Wiserepo/Qwen
and Graphify are analysis aids: verify security-sensitive or
implementation-critical conclusions against the source, tests and gates.

- **`local`** — wiserepo/Qwen (`repo_qa`, `summarize`, `git grep`): discovery and
  first-pass context, no paid tokens, no authority. A shared-guard refusal is final:
  read the file at the tier it implies — do not rephrase or hand the request to
  another tool to route around it.
- **`mid`** — implementation, debugging, test changes, ordinary review.
- **`top`** — security, cryptography, hash/layout, migrations, authn/authz, proof
  verification, destructive operations, or a failed `mid`. Confirm by reading the
  source and running tests; never delegate the verdict to the local model or graph.

`node tools/model-router/route.mjs "<task>" [--paths <path>]` names the tier and
model; mechanics live with the tools — deny-set and path rules in
`tools/agent-policy/` (which owns the `.olympus-logs/route-report.jsonl` log),
budget and gather limits in `tools/wiserepo/README.md` and
`tools/qwen-local/README.md`.

Never send Olympus source or secrets to a hosted service merely to save tokens, and
never configure paid usage without explicit authorization — subscription access is
not API access. Say when high-confidence review needs Codex or Claude.
