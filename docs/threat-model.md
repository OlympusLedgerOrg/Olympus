# Olympus Threat Model

*A plain-English summary for auditors, policymakers, and grant committees.*

> **v0.10 court-readiness statement — read this before the mitigation
> tables.** Olympus v0.10 still depends on a real multi-contributor
> Phase 2 ceremony for court-grade production use. The red-team fixes
> formerly tracked as OTS-1, OTS-2, GRV-1, and CKPT-1 are implemented
> in the current tree. See
> [`docs/court-evidence.md` §0](court-evidence.md#0-v010-court-readiness-statement--read-this-first)
> for the full statement.

---

## What Problem Are We Solving?

Institutional records — budgets, contracts, audit responses, meeting minutes — are
supposed to be trustworthy and permanent.  In practice, they can be quietly edited,
deleted, or buried without anyone noticing.  Olympus is designed to make such
tampering **detectable**, even by someone who was not watching when the original
document was published.

---

## Who Are the Adversaries?

| Adversary | What they might do |
|-----------|-------------------|
| **Institutional official or contractor** | Edit or delete a previously published document to hide inconvenient information. |
| **Database or server administrator** | Directly modify stored records in a way that bypasses application-level controls. |
| **Malicious document submitter** | Submit a forged or altered document and claim it is the authentic original. |
| **External attacker** | Compromise the server hosting the ledger and rewrite history. |

Olympus does **not** assume any single party is honest.  It is designed so that
independent observers can verify integrity without trusting the operator.

---

## What Does Olympus Protect Against?

### 1. Silent After-the-Fact Modification
Every document committed to Olympus is fingerprinted using a cryptographic hash
(BLAKE3).  The hash is computed from the exact bytes of the document.  Changing
even a single character produces a completely different hash, making any edit
immediately detectable by anyone who saved the original hash.

### 2. Retroactive Deletion or Reordering of Records
All ledger entries are chained together: each new entry includes the hash of the
previous entry.  Breaking or reordering this chain is mathematically equivalent
to changing a fingerprint — it cannot be done without detection.

### 3. Forged Audit Proofs
Each checkpoint over a batch of documents is signed using the operator's
persistent Baby Jubjub authority key under EdDSA-Poseidon.  A signed checkpoint
commits to the set of documents in a given batch.  A verifier can check the
signature independently against the operator's published authority pubkey and
confirm no documents were added or removed after signing.

### 4. Over-Redaction or Secret Redaction
When a document is released with portions redacted, Olympus can prove
that the redacted version is derived from the same original that was committed
before the redaction request arrived.  This prevents retroactive
changing of what was in the document before redacting it.

---

## How Does the Protocol Offer This Protection?

```
Document → Canonicalize → Hash → Merkle Tree → Signed Checkpoint → Root-Committed Ledger
```

1. **Canonicalization** — The document is converted to a single, reproducible
   byte sequence regardless of formatting differences.  Two semantically
   identical documents always produce the same fingerprint.

2. **Hashing** — A BLAKE3 cryptographic hash is computed.  This is a one-way
   mathematical function: the hash reveals nothing about the document content
   but uniquely identifies it.

3. **Merkle Commitment** — A batch of document hashes is organized into a
   Merkle tree.  The single root hash of the tree commits to every document in
   the batch.  An efficient "inclusion proof" can later show that a specific
   document was part of that batch without revealing the others.

4. **Signed Checkpoint** — The batch root is signed with the operator's Baby
   Jubjub authority key under EdDSA-Poseidon.  Anyone with the corresponding
   authority pubkey can verify the signature is authentic.  (The same checkpoint
   payload is *separately* signed with Ed25519 when it is submitted to a
   Sigstore Rekor transparency log — see §3 of the mitigations table.)

5. **Root-Committed Ledger** — Every signed checkpoint commits to the current
   sparse-Merkle-tree root (`ledger_root`, `tree_size`).  Removing or reordering
   any record would produce a different SMT root than the one already signed
   into a previously-anchored checkpoint, and the divergence is detectable
   against any preserved anchor (RFC 3161 timestamp, Rekor receipt, or
   OpenTimestamps proof).

---

## What Olympus Does NOT Protect Against

- **Key compromise** — If the signing key is stolen, an attacker could sign
  forged headers.  Key management and rotation are outside this protocol.
- **In-band key revocation** — v0.10 has no in-band mechanism for revoking a
  previously-published Ed25519 or BJJ pubkey. If an old key is compromised
  after rotation, the published bundle still verifies against the embedded
  pubkey, and revocation is an out-of-band publishing concern. See
  [`docs/court-evidence.md` §6.1](court-evidence.md#61-bundle-byte-identity-and-bjj-key-rotation).
  An in-band PKI revocation mechanism is a **v1.0 roadmap item**.
- **v0.10 trusted-setup ceremony** — v0.10 ships with a single-contributor dev
  Phase 2 ceremony. Production startup refuses to run against it (audit
  A-2/A-3/A-4, PR #1164). v1.0 ships the real multi-contributor ceremony.
  See [`docs/court-evidence.md` §0 + §5.1](court-evidence.md#0-v010-court-readiness-statement--read-this-first).
- **Completeness** — Olympus cannot force a government agency to submit all
  records.  It only guarantees the integrity of what it has received.
- **Single-operator deletion** — If the only copy of the ledger is deleted and
  no replicas exist, the audit trail is lost.  Federation (Tor hidden service +
  checkpoint gossip) addresses this.
- **Content confidentiality** — Olympus does not encrypt documents.  Access
  controls are a separate concern.

---

## Mitigations and Evidence

The table below maps each threat to the concrete mitigation implemented in this
repository, with links to the relevant source evidence.

> **Implementation note:** Python and Go were retired in v0.9.0. The entire
> runtime is now Rust (Tauri 2 + Axum + embedded PostgreSQL). Evidence links
> below point to the current Rust implementation.

### T1 — Silent After-the-Fact Modification

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Preimage resistance | BLAKE3 hash; changing any byte produces a different hash | [`crates/olympus-crypto/src/lib.rs`](../crates/olympus-crypto/src/lib.rs) — `blake3_hash()` |
| Domain separation | ADR-0005 structured SMT leaves, legacy binary-Merkle node domains, and signing/anchor domains prevent cross-context collisions | [`crates/olympus-crypto/src/lib.rs`](../crates/olympus-crypto/src/lib.rs) — `leaf_hash`, `NODE_PREFIX`, `EMPTY_LEAF_PREFIX`; [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) — checkpoint anchor domain; [`src-tauri/src/api/middleware/auth.rs`](../src-tauri/src/api/middleware/auth.rs) — API-key derivation domain |
| Merkle commitment | Single root commits all document parts; inclusion proof verifiable offline | [`crates/olympus-crypto/src/smt.rs`](../crates/olympus-crypto/src/smt.rs) — SMT insert / inclusion proof; [`src-tauri/src/api/ledger/read.rs`](../src-tauri/src/api/ledger/read.rs) — proof endpoints |
| Canonicalization | Deterministic byte sequence from any semantically equivalent input | [`crates/olympus-crypto/src/canonical.rs`](../crates/olympus-crypto/src/canonical.rs) — `canonicalize_bytes()`, `canonicalize_str()` |
| Cross-language test vectors | Canonicalization hash parity verified in Rust and JS | [`verifiers/test_vectors/canonicalizer_vectors.tsv`](../verifiers/test_vectors/canonicalizer_vectors.tsv); [`verifiers/rust/`](../verifiers/rust/); [`verifiers/javascript/`](../verifiers/javascript/) |

### T2 — Retroactive Deletion or Reordering

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Per-record content binding | `ledger_entry_hash = BLAKE3("OLY:LEDGER_ENTRY:V2" \|\| lp(shard_id) \|\| lp(record_id) \|\| lp(record_type) \|\| be64(version) \|\| lp(content_hash) \|\| lp(proof_id))` where `lp(x)` is a 4-byte big-endian length prefix — a stable digest that pins each record to its full location (shard/record/version) and identity (content + proof id), not to a predecessor. The V1 form bound only `content_hash` + `proof_id` joined with raw `\|` separators (injection-ambiguous and blind to shard/record); see audit finding 7. | [`src-tauri/src/api/ingest/files/route.rs`](../src-tauri/src/api/ingest/files/route.rs) — `ledger_entry_hash` construction |
| SMT-root commitment | Every ingest updates the sparse Merkle tree in-place; the resulting `ledger_root` is what gets signed into a checkpoint, so any removal/reorder produces a root that won't match a previously-anchored checkpoint. Persistent SMT writers serialize via `acquire_write_lock` (audit H-4 — `pg_advisory_lock` on Postgres, `tokio::Mutex` on Mem backends) so concurrent batches cannot race on the read-modify-write. ADR-0022 lazy deep-node storage (PRs #1172/#1175/#1176, migration 0044) persists only nodes at depth ≤ 72 and recomputes deeper nodes on read from the leaf canopy; roots and proofs are byte-identical to the in-memory parity oracle (`olympus_crypto::smt::SparseMerkleTree`). | [`crates/olympus-crypto/src/smt.rs`](../crates/olympus-crypto/src/smt.rs) — `update(key, value_hash, parser_id, canonical_parser_version)` recomputes internal nodes; [`src-tauri/src/smt/tree.rs`](../src-tauri/src/smt/tree.rs) — `LAZY_DEPTH`, `CANOPY_RECOMPUTE_CAP`, write-lock + cache-refresh sequence; [`src-tauri/src/federation/checkpoint.rs`](../src-tauri/src/federation/checkpoint.rs) — checkpoint binds `ledger_root` + `tree_size` |
| Narrow-scope mutations only | DB schema does not allow arbitrary updates: <ul><li>`ingest_records` permits only one-shot attach of `zk_bundle` and bounded snapshot-column writes.</li><li>`peer_checkpoints` is mutated only to flag equivocation; peer removal is a soft delete and the checkpoint FK is `ON DELETE RESTRICT`, preserving evidence.</li><li>An OTS row has one monotonic `pending` → `upgraded` transition. The merged receipt must contain a structurally reachable Bitcoin attestation, but metadata remains `bitcoin_attestation_verified=false` and `verified_at=NULL` pending independent chain verification.</li><li>v2 `own_checkpoints` are INSERT-only and unique on `(format_version, checkpoint_scope, shard_id, ledger_root, tree_size)`.</li></ul>There is no application path that overwrites the cryptographic identity of a checkpoint after insert. | [`migrations/0051_harden_checkpoint_identity.sql`](../migrations/0051_harden_checkpoint_identity.sql); [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs); [`src-tauri/src/anchoring/store.rs`](../src-tauri/src/anchoring/store.rs); [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs); [`docs/court-evidence.md` §6](court-evidence.md#6-chain-of-custody--typical-operator-practice) |
| SMT root consistency across federation peers | Wire v2 labels every checkpoint as scope=`shard` with an authenticated `shard_id`; it never advertises one shard snapshot as a global ledger root. The BJJ signature binds version, scope, shard, root, height, timestamp, and authority identity. The receiver also binds Groth16 public signals to `ledger_root` and `tree_size`, enforces the empty-tree invariant, deduplicates an already-verified signed statement before pairing work, and keys equivocation/evidence on canonical BJJ identity rather than replaceable peer UUID. | [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) — `checkpoint_signing_message_v2`; [`src-tauri/src/federation/verify.rs`](../src-tauri/src/federation/verify.rs); [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs) |

### T3 — Forged Audit Proofs

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| BJJ-EdDSA checkpoint signing | Each checkpoint is signed with the persistent Baby Jubjub authority key over the complete v2 statement: version, shard scope/id, canonical decimal root, height, timestamp, and authority hash. The external BLAKE3 anchor additionally binds canonical signature components using length prefixes. | [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs); [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) — `checkpoint_signing_message_v2`, `checkpoint_anchor_hash_v2` |
| Ed25519 sign-on-persist of `anchor_hash` | The 32-byte `anchor_hash` (BLAKE3 domain digest above) is additionally signed with the operator's Ed25519 ingest key at the moment the `own_checkpoints` row is written (PR [#1168](https://github.com/OlympusLedgerOrg/Olympus/pull/1168) + migration 0042). Pinned at emission so a re-exported bundle is byte-identical to the original. Signing key resolved with the same precedence the Rekor path uses: dedicated `OLYMPUS_ANCHOR_SIGN_KEY` → fallback `OLYMPUS_INGEST_SIGNING_KEY`. | [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs) — `sign_anchor_hash_ed25519()`, `resolve_ed25519_signing_key()` |
| Federation peer signature verification with signal binding | Peers require wire v2 and canonical decimals, verify the complete scoped BJJ statement against the pinned key, require its authority hash to match that key, and bind Groth16 public signals to root/size. Exact authenticated statements already stored with `verified=true` bypass repeat Groth16 work. Equivocation locks, indexes, and blocking use canonical `(BJJ x, BJJ y, scope, shard)` identity, so a replacement UUID cannot hide a fork. | [`src-tauri/src/federation/verify.rs`](../src-tauri/src/federation/verify.rs); [`migrations/0051_harden_checkpoint_identity.sql`](../migrations/0051_harden_checkpoint_identity.sql) |
| Ed25519 signing on the Rekor anchor path | The Rekor transparency-log entry payload is signed with the operator's Ed25519 key so the log entry itself is attributable. Sigstore Rekor SET ECDSA-P-256 verification at submission when `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set (audit M-A2). | [`src-tauri/src/anchoring/rekor.rs`](../src-tauri/src/anchoring/rekor.rs) |
| RFC 3161 timestamp token | Domain-separated BLAKE3 checkpoint digest submitted to accredited TSA. Nonce-echo verification at submission (audit M-A1, PR #1146); `TSTInfo.messageImprint` binding check confirms the TSA signed what we asked it to. SHA-256 OID `AlgorithmIdentifier` parameters require canonical DER NULL (`05 00`) — non-canonical NULL is refused (PR #1160 / `tstinfo.rs:142`). Receipt stored verbatim for `openssl ts -verify`. | [`src-tauri/src/anchoring/rfc3161.rs`](../src-tauri/src/anchoring/rfc3161.rs); [`src-tauri/src/anchoring/tstinfo.rs`](../src-tauri/src/anchoring/tstinfo.rs) |
| OpenTimestamps upgrade | A bounded Timestamp AST parser derives the pending commitment from the original anchored hash, parses the calendar response as a commitment-rooted subtree, requires a Bitcoin attestation, merges it into the original tree, and reparses the persisted bytes. Pending rows are claimed with cross-process leases and rotate through bounded exponential backoff, so the same oldest batch cannot starve later receipts. The node records the claimed height/root but deliberately leaves `bitcoin_attestation_verified=false` and `verified_at=NULL`; a tag supplied by a calendar is not Bitcoin consensus verification. | [`src-tauri/src/anchoring/ots_tree.rs`](../src-tauri/src/anchoring/ots_tree.rs); [`src-tauri/src/anchoring/ots.rs`](../src-tauri/src/anchoring/ots.rs); [`src-tauri/src/anchoring/store.rs`](../src-tauri/src/anchoring/store.rs); [`migrations/0052_harden_anchor_retry_state.sql`](../migrations/0052_harden_anchor_retry_state.sql) |
| Anchor cron actually runs (PR #1165) | Before PR #1165 the anchor cron read a never-written BLAKE3 column from `ingest_records` and was silently inert — the `anchor_receipts` table stayed empty under any operator configuration. PR #1165 introduced `own_checkpoints` as the canonical producer; the cron now ticks once per `OLYMPUS_ANCHOR_INTERVAL_SECS`, builds an existence proof + BJJ signature + Ed25519 signature, inserts a row, then calls the RFC 3161 / Rekor / OTS backends for each configured URL. Migration 0052 makes those calls durably idempotent by `(kind, hash, target)`, with a lease before network I/O and bounded retry after failure. **Anchoring is opt-in per backend:** zero URLs configured = producer-only mode (rows in `own_checkpoints`, none in `anchor_receipts`). | [`src-tauri/src/anchoring/cron.rs`](../src-tauri/src/anchoring/cron.rs); [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs); [`src-tauri/src/anchoring/store.rs`](../src-tauri/src/anchoring/store.rs); [`migrations/0052_harden_anchor_retry_state.sql`](../migrations/0052_harden_anchor_retry_state.sql); [`docs/court-evidence.md` §1.1](court-evidence.md#11-what-the-v09-binary-actually-enforces-online) |
| Independent court-side verification | Standalone Rust Groth16 verifier (`olympus-verifier verify --circuit X --vkey ... --proof ... --public-signals ...`, PR [#1167](https://github.com/OlympusLedgerOrg/Olympus/pull/1167)) — strict snarkjs JSON parsing, on-curve + subgroup checks, modulus-canonical field-element parse, BLAKE3 vkey fingerprint in output, and `MAX_N_PUBLIC` gates for vkeys/public signals (red-team GRV-1 closure). JS `verify-checkpoint --bundle` (PR [#1168](https://github.com/OlympusLedgerOrg/Olympus/pull/1168)) runs three signature-layer checks; the Groth16 step is delegated to the Rust verifier. See [`docs/court-evidence.md` §3](court-evidence.md#3-independent-verification--minimal-commands) for the operator runbook — note especially that exit 0 from the JS verifier means "checks 1–3 passed", not "Groth16 also verified". | [`verifiers/rust/src/groth16.rs`](../verifiers/rust/src/groth16.rs); [`verifiers/rust/src/bin/verify.rs`](../verifiers/rust/src/bin/verify.rs); [`verifiers/javascript/verify.js`](../verifiers/javascript/verify.js); [`docs/checkpoint-bundle-schema.md`](checkpoint-bundle-schema.md) |
| Production ceremony enforcement | Production no longer counts unauthenticated manifest rows. It requires at least three distinct contributor BJJ keys whose signatures bind the exact contribution index and hash chain and whose keys are valid in the independently supplied `OLYMPUS_CEREMONY_TRUSTED_CONTRIBUTORS_JSON` policy. Repeated rows from one key count once; missing, forged, out-of-window, duplicate-policy, or non-subgroup identities fail closed. Coordinator/self-attestation and dev-ceremony gates remain. | [`src-tauri/src/zk/manifest.rs`](../src-tauri/src/zk/manifest.rs) — `verify_authenticated_contributors`; [`src-tauri/src/bin/verify_ceremony_bundle.rs`](../src-tauri/src/bin/verify_ceremony_bundle.rs); [`proofs/CEREMONY_INTEGRITY.md`](../proofs/CEREMONY_INTEGRITY.md) |
| Bootstrap secrets handling | Initial API key + BJJ authority private key are surfaced once via the in-app `InitialSecretsModal` (the sole sanctioned channel) and zeroized after handoff. No `eprintln!` / `tracing::*` of raw secrets anywhere in `src-tauri/src/` (audit C-1 / PR [#1161](https://github.com/OlympusLedgerOrg/Olympus/pull/1161)). Frontend stores secrets in JS module-level variables only — not localStorage / sessionStorage. | [`src-tauri/src/bootstrap.rs`](../src-tauri/src/bootstrap.rs); [`src-tauri/src/commands.rs`](../src-tauri/src/commands.rs) — `take_initial_secrets`; [`app/public-ui/src/components/InitialSecretsModal.tsx`](../app/public-ui/src/components/InitialSecretsModal.tsx) |
| Dual-root / snapshot binding | Current file commits write a signed Poseidon `snapshot_root`; legacy `merkle_root` / `poseidon_root` fields are compatibility aliases when surfaced. The unified Groth16 circuit takes `canonicalHash`, `merkleRoot`, `ledgerRoot`, `treeSize`, and `ledgerKeyHash` as public inputs, so a valid proof binds the record-level Merkle commitment to the parser-bound SMT root. The SMT leaf hash itself binds `shard_id`, `key`, `value_hash`, `parser_id`, `canonical_parser_version`, and `model_hash`; it does **not** include the compatibility `poseidon_root` column. | [`src-tauri/src/api/ingest/files/snapshot.rs`](../src-tauri/src/api/ingest/files/snapshot.rs) — signed snapshot write; [`src-tauri/src/api/ingest/zk_bundle.rs`](../src-tauri/src/api/ingest/zk_bundle.rs) — lazy bundle from `snapshot_root`; [`src-tauri/src/zk/witness/unified.rs`](../src-tauri/src/zk/witness/unified.rs) — public-signal arity |

### T4 — Over-Redaction or Secret Redaction

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Redaction commitment | Document parts are committed as hiding leaves and folded into a signed-Merkle redaction root before any release decision | [`src-tauri/src/zk/segment.rs`](../src-tauri/src/zk/segment.rs); [`crates/olympus-crypto/src/redaction.rs`](../crates/olympus-crypto/src/redaction.rs) |
| Redaction proof binding | ADR-0030 V3 verifier deterministically replays the redacted artifact, derives offsets/labels from the artifact, recomputes revealed leaves, checks destroyed redacted spans, folds to `original_root`, and verifies the issuer Ed25519 signature over the segment table | [`verifiers/rust/src/redaction.rs`](../verifiers/rust/src/redaction.rs); [`verifiers/javascript/test_redaction.js`](../verifiers/javascript/test_redaction.js); [`docs/adr/ADR-0030-redaction-signed-merkle-drop-groth16.md`](adr/ADR-0030-redaction-signed-merkle-drop-groth16.md) |
| Semantic equivalence | Canonicalization ensures whitespace / formatting changes do not mask content changes | [`crates/olympus-crypto/src/canonical.rs`](../crates/olympus-crypto/src/canonical.rs) — JCS/RFC 8785 normalization |

> **Verifier note:** selective-disclosure verification requires both ADR-0030
> artifact replay and the CD-HS-ST inclusion proof. The signed-Merkle replay
> proves the redacted artifact folds to `original_root`; the surrounding SMT
> inclusion proof binds that root to the
> document identity and ledger sequence. See
> [`docs/SECURITY_AUDIT_REPORT_V5.md`](SECURITY_AUDIT_REPORT_V5.md).

#### T4a — Dual-Anchor Binding Requirement

Olympus commits two separate roots for every document that participates in
ZK-based selective disclosure:

1. **BLAKE3 Merkle root** (`root_b3`) — the operational ledger commitment,
   stored as the leaf value in the CD-HS-ST Sparse Merkle Tree.
2. **Poseidon Merkle root** (`root_poseidon`) — the ZK-circuit input, built
   from the same canonicalized document parts but using a hash function
   compatible with Groth16 arithmetic circuits.

Both roots are bound by the **unified Groth16 circuit's public inputs**
(`canonicalHash`, `merkleRoot`, `ledgerRoot`, `treeSize`), so that any
accepted ZK proof asserts the BLAKE3 ledger root and the Poseidon ZK root
refer to the same underlying record.  The SMT leaf hash itself only
contains `(key, value_hash, parser_id, canonical_parser_version)` — it
does **not** include `poseidon_root` — so the dual-root binding is a
circuit-level guarantee, not a leaf-level one.

**Root-swap attack (without dual anchoring):**
Without dual anchoring, a prover could present:
- A valid SMT inclusion proof for a committed `root_b3` that corresponds to
  document _D_, and
- A valid Groth16 proof whose public input (`poseidon_root`) was derived from
  a *different* document _D′_.

Because there would be no link between the Poseidon root and the ledger
commitment, the verifier would have no way to detect that the ZK proof
describes a different document than the one on the ledger.  The unified
circuit closes this gap by taking both roots as public inputs and
constraining them against the same canonicalized record.

**Verification steps a verifier MUST perform:**

1. **SMT inclusion proof** — Verify that the leaf at the expected CD-HS-ST key
   commits to `root_b3` at a specific ledger sequence number.  This proves
   that the operator committed _this specific document_ at that sequence;
   the leaf alone does not pin `root_poseidon` — that pinning comes from
   step 3 below via the unified circuit's public inputs.
2. **BLAKE3 Merkle proof** — Verify the document's BLAKE3 Merkle path against
   `root_b3`.  This links the leaf hash back to the actual document bytes.
3. **Groth16 circuit verification** — Verify the snarkjs proof with
   `root_poseidon` as the public input.  The circuit attests that the revealed
   leaves are a subset of the Poseidon Merkle tree whose root is
   `root_poseidon`.

Only when all three checks pass can a verifier conclude:
- The document is on the ledger (step 1 + 2).
- The revealed content is an authentic, non-forged subset of that document
  (step 3).

**Implementation evidence:**
- [`src-tauri/src/api/ingest/files/snapshot.rs`](../src-tauri/src/api/ingest/files/snapshot.rs) —
  signed `snapshot_root` written after server-side file hashing.
- [`src-tauri/src/api/redaction/`](../src-tauri/src/api/redaction/) —
  V3 signed-Merkle redaction bundles and manifest-backed redaction transforms.

### T5 — Infrastructure / Operational Attacks

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| DB connection resilience | pg_embed embedded PostgreSQL; external `DATABASE_URL` path uses sqlx connection pool with retry | [`src-tauri/src/db.rs`](../src-tauri/src/db.rs) — `init_embedded()`, `connect_external()` |
| Supply-chain integrity | SBOM (CycloneDX) + `cargo audit` on every CI run | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — `supply-chain` job |
| Static security analysis | `cargo clippy -D warnings` + CodeQL across all first-party Rust code | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — `lint` job; [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) |
| CodeQL extended queries | Semantic vulnerability patterns detected in CI | [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) |
| DoS hardening (inbound) | Axum request timeouts, CORS narrowing, streaming body caps, per-IP rate limiting via `governor`, loopback-only `Host` header enforcement | [`src-tauri/src/server/mod.rs`](../src-tauri/src/server/mod.rs); [`src-tauri/src/api/middleware/auth.rs`](../src-tauri/src/api/middleware/auth.rs) |
| DoS hardening (outbound — anchoring backends) | Successful receipt bodies have a 10 MiB streamed cap; non-success diagnostic bodies stop at 8 KiB; the shared `reqwest::Client` also has a wall-clock timeout. No anchoring path uses unbounded `.text()` or `.bytes()` buffering. | [`src-tauri/src/anchoring/http_limits.rs`](../src-tauri/src/anchoring/http_limits.rs); [`src-tauri/src/anchoring/rfc3161.rs`](../src-tauri/src/anchoring/rfc3161.rs); [`src-tauri/src/anchoring/rekor.rs`](../src-tauri/src/anchoring/rekor.rs); [`src-tauri/src/anchoring/ots.rs`](../src-tauri/src/anchoring/ots.rs) |
| Concurrent SMT writer safety (audit H-4) | Persistent SMT writers serialize via `acquire_write_lock` (Postgres `pg_advisory_lock` / `tokio::Mutex`). The lock is held across the read-modify-write in `update_batch`, and the in-memory hot cache is refreshed inside the locked section — preventing stale-cache stomp. | [`src-tauri/src/smt/tree.rs`](../src-tauri/src/smt/tree.rs) — `update_batch`, `acquire_write_lock`, `load_hot` |
| Standalone verifier resource exhaustion | `MAX_N_PUBLIC` (65,536) caps both vkey `nPublic` and public-signal length before the verifier reaches the MSM path (red-team GRV-1 closure). | [`verifiers/rust/src/groth16.rs`](../verifiers/rust/src/groth16.rs) |
| SBT replay race (audit H-3 / PR #1163) | `key_credentials.commit_id` has a UNIQUE constraint (migration 0040); the issue path uses `INSERT … ON CONFLICT (commit_id) DO NOTHING RETURNING id` with an idempotent loser path that returns the canonical row. Concurrent issuance over the same `(holder, type, ...)` tuple resolves to a single canonical credential. | [`migrations/0040_key_credentials_commit_id_unique.sql`](../migrations/0040_key_credentials_commit_id_unique.sql); [`src-tauri/src/api/credentials/mod.rs`](../src-tauri/src/api/credentials/mod.rs) — `issue_credential` |

---

## Summary

Olympus is a **tamper-evident audit trail** for sensitive records.  It cannot
prevent a bad actor from withholding documents, but it makes it cryptographically
impossible to alter or delete a committed document without that fact being
detectable by any independent verifier who has the original commitment hash.
