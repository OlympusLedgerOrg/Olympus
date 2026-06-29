---
name: olympus-dev-standards
description: >
  Senior-level engineering judgment for the Olympus cryptographic ledger
  (v0.10.x Rust/Tauri desktop). Use whenever writing new code, reviewing code,
  planning architecture, or making any implementation decision in the Olympus
  repo. Triggers on: code review, "write a function/module/service",
  architecture questions, PR prep, "is this pattern OK", "how should I
  structure X", adding tests, or touching crypto, the embedded DB, federation,
  quorum, ZK circuits, or the Tauri 2 app. Also triggers for ZK primitives
  (Groth16, Baby Jubjub, Pedersen) and dependency/licensing changes. Do NOT
  skip just because a task "seems simple" — even single functions must comply
  with Olympus architectural constraints.
---

# Olympus Dev Standards (v0.10.x)

Senior engineering judgment for the Olympus cryptographic ledger.
GitHub: `OlympusLedgerOrg/Olympus`. Source of truth for specifics: `AGENTS.md`.

> **Architecture epoch.** Olympus is a **Rust + Tauri 2 desktop app** as of
> v0.9.0. **Python and Go are RETIRED** — the Python FastAPI server, the Go
> sequencer/log-service, and the Go/Python verifiers were all replaced by the
> Tauri + embedded-Axum desktop. If a rule mentions PyO3, `tokio-postgres`
> bans on Rust, Go Merkle delegation, Halo2, or `OLY:LEAF:V1|` as the live
> leaf prefix, it is **pre-v0.9.0 and no longer applies.**

## Language ownership — hard boundaries

```text
Rust       → EVERYTHING security- and data-critical: Tauri app, embedded Axum
             HTTP server, ALL DB operations (embedded PostgreSQL via pg_embed),
             crypto hot path (BLAKE3, Ed25519, Poseidon, SMT, Baby Jubjub
             EdDSA-Poseidon + Pedersen, canonicalization), SBT issue/verify/
             revoke, ZK prove/verify, federation, quorum, anchoring.
TypeScript → React frontend only (app/public-ui/). Presentation + API calls.
```

Forbidden:
- **Frontend MUST NOT perform security-sensitive crypto.** It calls the Rust
  backend over the local HTTP API / Tauri commands. No signing, no hashing of
  ledger material, no key handling in TS.
- **No new Python or Go.** They are retired; do not reintroduce a service in
  them. Cross-language *verifiers* (Rust + JavaScript, in `verifiers/`) are the
  only sanctioned non-Rust code that touches crypto, and only to
  independently re-verify.

When unsure where something belongs: "Is it cryptographic, touches the DB, or
is otherwise security-critical?" → **Rust** (`src-tauri/` or a `crates/` lib).

## Repo layout

```text
Olympus/
├── src-tauri/            ← Tauri 2 + Axum backend (the app). main.rs, server/, api/,
│   │                       state.rs, db.rs (pg_embed), bootstrap.rs, federation/, quorum/,
│   │                       anchoring/, zk/ (witness/, pedersen.rs, poseidon, manifest.rs)
│   └── build.rs          ← placeholder shim + ceremony compile-time check #1
├── crates/
│   ├── olympus-crypto/   ← shared primitives: leaf/node hashing, SMT, canonical JSON,
│   │                       ledger_snapshot verifier (domain constants live here)
│   ├── babyjubjub-permissive/  ← permissive (Apache-2.0) BJJ-EdDSA + Pedersen
│   ├── light-poseidon/   ← vendored permissive Poseidon
│   └── glib-0.18.5-patched/    ← vendored LGPL glib (patch-only)
├── proofs/               ← Circom circuits + setup_circuits.sh + ceremony manifests
├── app/public-ui/        ← React + Vite + Tailwind frontend
├── verifiers/{rust,javascript}/  ← cross-language offline verifiers + test_vectors/
├── migrations/           ← sqlx migrations (applied by Tauri on startup)
└── .agents/skills/      ← Codex-facing repo skills, including this skill
```

## Global architectural laws (blocking)

### Domain separation (ADR-0005) — non-negotiable
- **Node** hashes: `OLY:NODE:V1|`. **Empty-leaf** sentinel: `OLY:EMPTY-LEAF:V1`.
- **Leaf** hashes use the **ADR-0005 structured binary prefix**
  (`u8(0x01) || "OLY" || u8=LEAF || u8=V1 || lp(shard_id)`), **not** the legacy
  `OLY:LEAF:V1|` ASCII tag (`LEAF_PREFIX` is retained only as a pinned legacy
  marker).
- All constants live in `crates/olympus-crypto/src/lib.rs` — never redefine
  elsewhere. The desktop crate consumes them via the workspace dep.
- **Leaf hash binds shard + parser provenance** (ADR-0003/0004):
  `leaf_hash(shard_id, key, value_hash, parser_id, canonical_parser_version,
  model_hash)` — a `0x05`-count-framed body with **length-prefixed** fields.
  `value_hash` must be 32 raw bytes; all four string fields must be non-empty.
- **Multi-field binary inputs MUST be length-prefixed** (injection prevention)
  — never concatenate attacker-influenced fields with a bare separator.
- **Changing the leaf/shard layout is a breaking hash change.** Update
  `olympus-crypto`, both SMTs, BOTH verifiers (rust + js), the `smt_leaves`
  schema, AND regenerate the SSMF golden vectors
  (`cargo run -p olympus-crypto --example gen_ssmf_vectors --features smt`) **in
  the same commit** — and existing databases must be wiped/rebuilt (old leaf
  hashes will not reconstruct). `verifiers/test_vectors/vectors.json` is the
  single cross-language source of truth.

### Crypto backend & licensing (see the `crypto-guardrails` skill)
- Baby Jubjub EdDSA-Poseidon **and** Pedersen run on
  `crates/babyjubjub-permissive` (Apache-2.0). **Never reintroduce
  `babyjubjub-rs` or `ff_ce`** (they pull GPL-3.0 `poseidon-rs`). It is
  byte-compatible with the iden3 reference; point coords are `ark_bn254::Fr`
  (no field bridge).
- **No GPL in the runtime dependency graph** — `deny.toml` bans it with no
  exceptions. Permissive runtime licenses only; LGPL only via dynamic linking
  (Linux GTK/glib). GPL build-time tools (circom/snarkjs/circomlib) are fine
  (not linked into the binary). Adding a transitively-GPL dep fails the
  `supply-chain` CI job.

### Keys & signing
- **Ed25519 signing keys and the Baby Jubjub authority key MUST be persisted**
  — ephemeral keys make historical signed roots / SBTs unverifiable. Any
  keypair generation needs a persistence strategy before merge.
- Signature verification before any dedup/nonce store lookup (verify cheaply,
  reject invalid sigs before touching shared state — DoS hardening).
- **Quorum requires real multi-party threshold** — a single node MUST NOT
  satisfy its own M-of-N quorum cert. Quorum / single-issuer / revocation
  signatures are **domain-separated** (`OLY:SBT:QUORUM:V1` / bare `commit_id` /
  `OLY:SBT:REVOKE:V1`) — never cross-wire the digests.

### Other pinned invariants
- **Canonical JSON**: always JCS / RFC 8785 raw UTF-8.
- **SBT scope mapping in `auth.rs` is fail-closed security policy** — unknown
  `credential_type` grants no scopes. Treat as policy, not config.
- **`prove_circom` is the only sanctioned proving entry** (`zk/zkey.rs`
  `CircomProvingKey` seals the type so callers can't fall back to
  `LibsnarkReduction`).
- **Persistent SMT writers serialise** — hold `acquire_write_lock` across the
  read-modify-write in `update_batch`; refresh the hot cache inside the lock.
- **`/zk/verify` enforces the `treeSize=0` invariant** — reject proofs against
  the doc-existence/unified circuits with `treeSize=0` unless `root ==
  empty_doc_existence_root()`.
- **Ceremony manifests are atomic** — any vkey change requires regenerating its
  signed manifest in the same commit (`build.rs` panics on
  `blake3(vkey.json)` mismatch; runtime refuses a mismatching `.ark.zkey`).
  Never hand-edit `proofs/keys/manifests/*.json` — re-run `setup_circuits.sh`.

## ZK primitives
Groth16 over **BN254** via Circom + `ark-circom`/`ark-groth16` (Apache-2.0/MIT)
at runtime. Circuits in `proofs/circuits/`. Baby Jubjub (twisted Edwards over
BN254's scalar field) for EdDSA-Poseidon + key derivation; Pedersen commitments
for hiding+binding record commitments. The trusted-setup ceremony (Phase 1 ptau
+ per-circuit Phase 2) produces signed manifests the runtime verifies. See the
`zk-verifiers` skill for the vector/ceremony runbook and the "do I need to rerun
the ceremony?" decision rule (answer: only when circuits/keys/vkeys/manifests
change — not for code-only changes).

## How to use this skill

**Code review:** check Global Laws first (blocking), then language patterns.
Flag as `[BLOCKING]` (violates an arch law), `[HIGH]`, `[MEDIUM]`, `[LOW]`.
Always suggest the fix, not just the problem.

**Writing code:** confirm which layer owns the concern (almost always Rust for
anything security/DB). Satisfy all Global Laws. Include tests — minimum happy
path + one error path per public fn.

**Architecture/design:** start with ownership; define the cross-boundary
contract first (Tauri command / HTTP contract for the frontend; protobuf only
where a real wire boundary exists). Apply the threat model: replay resistance,
domain separation, key persistence, multi-party quorum, length-prefix framing,
no-GPL. Record an ADR for new architectural decisions.

## Quick anti-pattern checklist (run mentally before presenting/approving code)
- [ ] No security-sensitive crypto in the TS frontend — goes through Rust.
- [ ] No new Python/Go service; crypto stays in Rust.
- [ ] Domain constants used from `olympus-crypto` (ADR-0005 structured leaf
      prefix, `OLY:NODE:V1|`, `OLY:EMPTY-LEAF:V1`) — not redefined, not the
      legacy `OLY:LEAF:V1|` ASCII tag.
- [ ] Multi-field hash inputs are length-prefixed (injection prevention).
- [ ] `shard_id` + `canonical_parser_version` + `model_hash` enter the leaf
      hash; a layout change moves vectors + both verifiers + schema together.
- [ ] Baby Jubjub / Pedersen go through `babyjubjub-permissive` — never
      `babyjubjub-rs`/`ff_ce`; no GPL added to the graph.
- [ ] Ed25519 + BJJ keys persisted, not ephemeral.
- [ ] Quorum is genuinely multi-party; quorum/issuer/revocation digests are
      domain-separated.
- [ ] Signature verified before dedup/nonce lookup.
- [ ] Canonical JSON is JCS/RFC 8785 (raw UTF-8), not default `serde_json`.
- [ ] SBT scope mapping stays fail-closed.
- [ ] ZK proving only via `prove_circom`; `/zk/verify` keeps the `treeSize=0`
      guard; vkey edits regenerate the signed manifest in the same commit.
- [ ] SMT writes hold the write lock across read-modify-write.
- [ ] Tests included; new modules meet the coverage gate.
