# Olympus Threat Model

*A plain-English summary for auditors, policymakers, and grant committees.*

> **v0.9 court-readiness statement — read this before the mitigation
> tables.** Olympus v0.9 ships with a **single-contributor dev trusted
> setup ceremony** and **four in-flight red-team fix PRs** that
> together gate court-grade use of the binary. See
> [`docs/court-evidence.md` §0](court-evidence.md#0-v09-court-readiness-statement--read-this-first)
> for the full statement. The mitigations below describe the **post-fix**
> state and call out in-flight gaps inline where relevant.

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
- **In-band key revocation** — v0.9 has no in-band mechanism for revoking a
  previously-published Ed25519 or BJJ pubkey. If an old key is compromised
  after rotation, the published bundle still verifies against the embedded
  pubkey, and revocation is an out-of-band publishing concern. See
  [`docs/court-evidence.md` §6.1](court-evidence.md#61-bundle-byte-identity-and-bjj-key-rotation).
  An in-band PKI revocation mechanism is a **v1.0 roadmap item**.
- **v0.9 trusted-setup ceremony** — v0.9 ships with a single-contributor dev
  Phase 2 ceremony. Production startup refuses to run against it (audit
  A-2/A-3/A-4, PR #1164). v1.0 ships the real multi-contributor ceremony.
  See [`docs/court-evidence.md` §0 + §5.1](court-evidence.md#0-v09-court-readiness-statement--read-this-first).
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
| Domain separation | Leaf / node / ledger prefixes prevent cross-context collisions | [`crates/olympus-crypto/src/lib.rs`](../crates/olympus-crypto/src/lib.rs) — `LEAF_PREFIX`, `NODE_PREFIX`, `EMPTY_LEAF_PREFIX`; [`src-tauri/src/crypto.rs`](../src-tauri/src/crypto.rs) — checkpoint and API-key domain constants |
| Merkle commitment | Single root commits all document parts; inclusion proof verifiable offline | [`crates/olympus-crypto/src/smt.rs`](../crates/olympus-crypto/src/smt.rs) — SMT insert / inclusion proof; [`src-tauri/src/api/ledger.rs`](../src-tauri/src/api/ledger.rs) — proof endpoints |
| Canonicalization | Deterministic byte sequence from any semantically equivalent input | [`crates/olympus-crypto/src/canonical.rs`](../crates/olympus-crypto/src/canonical.rs) — `canonicalize_bytes()`, `canonicalize_str()` |
| Cross-language test vectors | Canonicalization hash parity verified in Rust and JS | [`verifiers/test_vectors/canonicalizer_vectors.tsv`](../verifiers/test_vectors/canonicalizer_vectors.tsv); [`verifiers/rust/`](../verifiers/rust/); [`verifiers/javascript/`](../verifiers/javascript/) |

### T2 — Retroactive Deletion or Reordering

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Per-record content binding | `ledger_entry_hash = BLAKE3("OLY:LEDGER_ENTRY:V2" \|\| lp(shard_id) \|\| lp(record_id) \|\| lp(record_type) \|\| be64(version) \|\| lp(content_hash) \|\| lp(proof_id))` where `lp(x)` is a 4-byte big-endian length prefix — a stable digest that pins each record to its full location (shard/record/version) and identity (content + proof id), not to a predecessor. The V1 form bound only `content_hash` + `proof_id` joined with raw `\|` separators (injection-ambiguous and blind to shard/record); see audit finding 7. | [`src-tauri/src/api/ingest.rs`](../src-tauri/src/api/ingest.rs) — `ledger_entry_hash` construction |
| SMT-root commitment | Every ingest updates the sparse Merkle tree in-place; the resulting `ledger_root` is what gets signed into a checkpoint, so any removal/reorder produces a root that won't match a previously-anchored checkpoint. Persistent SMT writers serialize via `acquire_write_lock` (audit H-4 — `pg_advisory_lock` on Postgres, `tokio::Mutex` on Mem backends) so concurrent batches cannot race on the read-modify-write. ADR-0022 lazy deep-node storage (PRs #1172/#1175/#1176, migration 0044) persists only nodes at depth ≤ 72 and recomputes deeper nodes on read from the leaf canopy; roots and proofs are byte-identical to the in-memory parity oracle (`olympus_crypto::smt::SparseMerkleTree`). | [`crates/olympus-crypto/src/smt.rs`](../crates/olympus-crypto/src/smt.rs) — `update(key, value_hash, parser_id, canonical_parser_version)` recomputes internal nodes; [`src-tauri/src/smt/tree.rs`](../src-tauri/src/smt/tree.rs) — `LAZY_DEPTH`, `CANOPY_RECOMPUTE_CAP`, write-lock + cache-refresh sequence; [`src-tauri/src/federation/checkpoint.rs`](../src-tauri/src/federation/checkpoint.rs) — checkpoint binds `ledger_root` + `tree_size` |
| Narrow-scope mutations only | DB schema does not allow arbitrary updates: <ul><li>`ingest_records` permits only NULL-backfill of `content_json`, one-shot attach of `zk_bundle`, and a snapshot-column back-fill that fills in `(snapshot_root, snapshot_index, snapshot_size, snapshot_path)` for rows that pre-dated the persistence migration. Each UPDATE has a `WHERE … IS NULL` guard so the column transitions monotonically NULL → set.</li><li>`peer_checkpoints` is mutated only by the equivocation detector to flag a competing root.</li><li>`anchor_receipts` has one monotonic OTS `phase: pending` → `phase: upgraded` transition per row, replacing the calendar's pending blob with the Bitcoin-anchored form (audit M-A3 / PR #1166). Identity columns (`id`, `anchor_kind`, `anchored_hash`, `checkpoint_id`, `target`, `submitted_at`) never change.</li><li>`own_checkpoints` is INSERT-only (PR [#1165](https://github.com/OlympusLedgerOrg/Olympus/pull/1165)) plus, once landed, `UNIQUE (ledger_root, tree_size) + ON CONFLICT DO NOTHING` ([fix in flight at #1187](https://github.com/OlympusLedgerOrg/Olympus/pull/1187)) so concurrent or retried cron emissions never produce duplicate or substituted rows.</li></ul>There is no application-code path that overwrites `content_hash`, `ledger_entry_hash`, `merkle_root`, `poseidon_root`, or the cryptographic columns of `own_checkpoints` after the initial insert. | [`migrations/`](../migrations/) — `0001` through `0044`; [`src-tauri/src/api/ingest.rs`](../src-tauri/src/api/ingest.rs) — narrow UPDATEs (`content_json IS NULL` guard, `zk_bundle` attach, snapshot back-fill); [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs) — INSERT-only producer; [`src-tauri/src/anchoring/store.rs`](../src-tauri/src/anchoring/store.rs) — `mark_ots_upgraded` once-only transition; [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs); [`docs/court-evidence.md` §6](court-evidence.md#6-chain-of-custody--typical-operator-practice) |
| SMT root consistency across federation peers | Peers gossip signed checkpoints; the receiver binds the Groth16 proof's public signals to the envelope's `ledger_root` and `tree_size` (audit F-1 / F-RT-1, PR [#1162](https://github.com/OlympusLedgerOrg/Olympus/pull/1162)) so a peer cannot substitute a different envelope around a real proof. The empty-tree invariant (`treeSize=0` must mean `root == empty_doc_existence_root()`) is enforced via a shared helper at every call site. Equivocation (two different roots at the same sequence) triggers auto-blocking. | [`src-tauri/src/federation/verify.rs`](../src-tauri/src/federation/verify.rs) — `verify_checkpoint_proof` binding + `enforce_empty_tree_invariant`; [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs); [`src-tauri/src/federation/gossip.rs`](../src-tauri/src/federation/gossip.rs) |

### T3 — Forged Audit Proofs

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| BJJ-EdDSA checkpoint signing | Each checkpoint is signed with the persistent Baby Jubjub authority key using EdDSA-Poseidon; the signature components (`bjj_signature_r8x`, `bjj_signature_r8y`, `bjj_signature_s`) are included in the BLAKE3 `checkpoint_anchor_hash` digest (binary-encoded i64 fields prevent `\|`-separator injection) so the signature is bound into the timestamped envelope | [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs) — `build_and_persist()` (PR [#1165](https://github.com/OlympusLedgerOrg/Olympus/pull/1165)); [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) — `checkpoint_anchor_hash()` |
| Ed25519 sign-on-persist of `anchor_hash` | The 32-byte `anchor_hash` (BLAKE3 domain digest above) is additionally signed with the operator's Ed25519 ingest key at the moment the `own_checkpoints` row is written (PR [#1168](https://github.com/OlympusLedgerOrg/Olympus/pull/1168) + migration 0042). Pinned at emission so a re-exported bundle is byte-identical to the original. Signing key resolved with the same precedence the Rekor path uses: dedicated `OLYMPUS_ANCHOR_SIGN_KEY` → fallback `OLYMPUS_INGEST_SIGNING_KEY`. | [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs) — `sign_anchor_hash_ed25519()`, `resolve_ed25519_signing_key()` |
| Federation peer signature verification with signal binding | Peers verify each received checkpoint's BJJ-EdDSA signature against the sender's authority pubkey before accepting it. The Groth16 proof's public signals are bound to the envelope's `ledger_root` and `tree_size` (audit F-1 / F-RT-1, PR [#1162](https://github.com/OlympusLedgerOrg/Olympus/pull/1162)) so a peer cannot substitute a different envelope around a real proof. The empty-tree invariant is enforced via a shared helper. Equivocation detection auto-blocks misbehaving nodes. | [`src-tauri/src/federation/verify.rs`](../src-tauri/src/federation/verify.rs) — `verify_checkpoint_proof`, `enforce_empty_tree_invariant`; [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs) |
| Ed25519 signing on the Rekor anchor path | The Rekor transparency-log entry payload is signed with the operator's Ed25519 key so the log entry itself is attributable. Sigstore Rekor SET ECDSA-P-256 verification at submission when `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set (audit M-A2). | [`src-tauri/src/anchoring/rekor.rs`](../src-tauri/src/anchoring/rekor.rs) |
| RFC 3161 timestamp token | Domain-separated BLAKE3 checkpoint digest submitted to accredited TSA. Nonce-echo verification at submission (audit M-A1, PR #1146); `TSTInfo.messageImprint` binding check confirms the TSA signed what we asked it to. SHA-256 OID `AlgorithmIdentifier` parameters require canonical DER NULL (`05 00`) — non-canonical NULL is refused (PR #1160 / `tstinfo.rs:142`). Receipt stored verbatim for `openssl ts -verify`. | [`src-tauri/src/anchoring/rfc3161.rs`](../src-tauri/src/anchoring/rfc3161.rs); [`src-tauri/src/anchoring/tstinfo.rs`](../src-tauri/src/anchoring/tstinfo.rs) |
| OpenTimestamps upgrade | Pending OTS receipts are upgraded to Bitcoin-anchored form by a background cron (audit M-A3, PR #1166 — the URL-construction fix that made the upgrade actually work). **Commitment re-verification on the upgraded blob is in flight** ([#1182](https://github.com/OlympusLedgerOrg/Olympus/pull/1182)); until merged, an honest operator should independently `ots verify` the upgraded receipt rather than relying on `metadata.phase=upgraded`. | [`src-tauri/src/anchoring/ots.rs`](../src-tauri/src/anchoring/ots.rs); [`src-tauri/src/anchoring/ots_format.rs`](../src-tauri/src/anchoring/ots_format.rs); [`src-tauri/src/anchoring/upgrade_cron.rs`](../src-tauri/src/anchoring/upgrade_cron.rs) |
| Anchor cron actually runs (PR #1165) | Before PR #1165 the anchor cron read a never-written BLAKE3 column from `ingest_records` and was silently inert — the `anchor_receipts` table stayed empty under any operator configuration. PR #1165 introduced `own_checkpoints` as the canonical producer; the cron now ticks once per `OLYMPUS_ANCHOR_INTERVAL_SECS`, builds an existence proof + BJJ signature + Ed25519 signature, inserts a row, then calls the (idempotent) RFC 3161 / Rekor / OTS backends for each `OLYMPUS_ANCHOR_*` URL that's configured. **Anchoring is opt-in per backend:** zero URLs configured = producer-only mode (rows in `own_checkpoints`, none in `anchor_receipts`). | [`src-tauri/src/anchoring/cron.rs`](../src-tauri/src/anchoring/cron.rs); [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs); [`docs/court-evidence.md` §1.1](court-evidence.md#11-what-the-v09-binary-actually-enforces-online) |
| Independent court-side verification | Standalone Rust Groth16 verifier (`olympus-verifier verify --circuit X --vkey ... --proof ... --public-signals ...`, PR [#1167](https://github.com/OlympusLedgerOrg/Olympus/pull/1167)) — strict snarkjs JSON parsing, on-curve + subgroup checks, modulus-canonical field-element parse, BLAKE3 vkey fingerprint in output. JS `verify-checkpoint --bundle` (PR [#1168](https://github.com/OlympusLedgerOrg/Olympus/pull/1168)) runs three signature-layer checks; the Groth16 step is delegated to the Rust verifier. **`nPublic` cap to prevent crafted-vkey MSM DoS is in flight** ([#1186](https://github.com/OlympusLedgerOrg/Olympus/pull/1186)). See [`docs/court-evidence.md` §3](court-evidence.md#3-independent-verification--minimal-commands) for the operator runbook — note especially that exit 0 from the JS verifier means "checks 1–3 passed", not "Groth16 also verified". | [`verifiers/rust/src/groth16.rs`](../verifiers/rust/src/groth16.rs); [`verifiers/rust/src/bin/verify.rs`](../verifiers/rust/src/bin/verify.rs); [`verifiers/javascript/verify.js`](../verifiers/javascript/verify.js); [`docs/checkpoint-bundle-schema.md`](checkpoint-bundle-schema.md) |
| Production ceremony enforcement | Production startup (`OLYMPUS_ENV=production`) refuses to run against the v0.9 single-contributor dev manifest. Three gates fire: A-2 (≥3 contributors), A-3 (coordinator ≠ bootstrap pubkey — required), A-4 (no `olympus-dev-` prefix on `ceremony_id`) — PR [#1164](https://github.com/OlympusLedgerOrg/Olympus/pull/1164) + CodeRabbit follow-up making A-3 mandatory. v0.9 dev mode logs each as a warning and continues; **a v0.9 dev binary is not court-ready** (see [`docs/court-evidence.md` §0 + §5.1](court-evidence.md#0-v09-court-readiness-statement--read-this-first)). | [`src-tauri/src/startup.rs`](../src-tauri/src/startup.rs) — `apply_extra_prod_gates`, `verify_ceremony_manifests`; [`proofs/setup_circuits.sh`](../proofs/setup_circuits.sh); [`proofs/phase2_ceremony.sh`](../proofs/phase2_ceremony.sh) |
| Bootstrap secrets handling | Initial API key + BJJ authority private key are surfaced once via the in-app `InitialSecretsModal` (the sole sanctioned channel) and zeroized after handoff. No `eprintln!` / `tracing::*` of raw secrets anywhere in `src-tauri/src/` (audit C-1 / PR [#1161](https://github.com/OlympusLedgerOrg/Olympus/pull/1161)). Frontend stores secrets in JS module-level variables only — not localStorage / sessionStorage. | [`src-tauri/src/bootstrap.rs`](../src-tauri/src/bootstrap.rs); [`src-tauri/src/commands.rs`](../src-tauri/src/commands.rs) — `take_initial_secrets`; [`app/public-ui/src/components/InitialSecretsModal.tsx`](../app/public-ui/src/components/InitialSecretsModal.tsx) |
| Dual-root binding via unified ZK circuit | `poseidon_root` is stored alongside the BLAKE3-based `ledger_root` on each ingest row; the unified Groth16 circuit takes both as public inputs (`canonicalHash`, `merkleRoot`, `ledgerRoot`, `treeSize`) so a valid proof asserts the BLAKE3 ledger root and the Poseidon ZK root agree on the same underlying record. (The SMT leaf hash itself does **not** include `poseidon_root` — the binding lives in the circuit, not in the leaf.) | [`src-tauri/src/api/ingest.rs`](../src-tauri/src/api/ingest.rs) — `poseidon_root` column; [`src-tauri/src/zk/witness/unified.rs`](../src-tauri/src/zk/witness/unified.rs) — public-signal arity |

### T4 — Over-Redaction or Secret Redaction

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Redaction commitment | Document parts hashed individually into Merkle tree before any release decision | [`src-tauri/src/api/redaction.rs`](../src-tauri/src/api/redaction.rs) — `issue_redaction()`, `generate_redaction_proof()` |
| Redaction proof binding | Groth16 `redaction_validity` circuit proves the redacted commitment is derived only from the original committed leaves | [`proofs/circuits/redaction_validity.circom`](../proofs/circuits/redaction_validity.circom); [`src-tauri/src/zk/`](../src-tauri/src/zk/) — in-process prover/verifier |
| Semantic equivalence | Canonicalization ensures whitespace / formatting changes do not mask content changes | [`crates/olympus-crypto/src/canonical.rs`](../crates/olympus-crypto/src/canonical.rs) — JCS/RFC 8785 normalization |

> **Verifier note:** selective-disclosure verification requires both the ZK proof
> and the CD-HS-ST inclusion proof. A Groth16 proof alone proves membership in a
> Poseidon tree; the surrounding SMT inclusion proof binds that root to the
> document identity and ledger sequence. See
> [`docs/SECURITY_AUDIT_REPORT_V4.md`](SECURITY_AUDIT_REPORT_V4.md).

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
- [`src-tauri/src/api/ingest.rs`](../src-tauri/src/api/ingest.rs) —
  `poseidon_root` column written alongside the BLAKE3 SMT leaf.
- [`src-tauri/src/api/redaction.rs`](../src-tauri/src/api/redaction.rs) —
  `generate_redaction_proof()` builds the Poseidon Merkle tree;
  `issue_redaction()` links the proof back to the committed record.

### T5 — Infrastructure / Operational Attacks

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| DB connection resilience | pg_embed embedded PostgreSQL; external `DATABASE_URL` path uses sqlx connection pool with retry | [`src-tauri/src/db.rs`](../src-tauri/src/db.rs) — `init_embedded()`, `connect_external()` |
| Supply-chain integrity | SBOM (CycloneDX) + `cargo audit` on every CI run | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — `supply-chain` job |
| Static security analysis | `cargo clippy -D warnings` + CodeQL across all first-party Rust code | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — `lint` job; [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) |
| CodeQL extended queries | Semantic vulnerability patterns detected in CI | [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml) |
| DoS hardening (inbound) | Axum request timeouts, CORS narrowing, streaming body caps, per-IP rate limiting via `governor`, loopback-only `Host` header enforcement | [`src-tauri/src/server/mod.rs`](../src-tauri/src/server/mod.rs); [`src-tauri/src/api/middleware/auth.rs`](../src-tauri/src/api/middleware/auth.rs) |
| DoS hardening (outbound — anchoring backends) | **Response-size cap (10 MiB) on all calendar / TSA / Rekor reads is in flight** ([fix at #1184](https://github.com/OlympusLedgerOrg/Olympus/pull/1184)). Until merged, an adversarial or buggy anchoring backend that streams gigabytes can OOM the desktop. `reqwest::Client` already enforces a wall-clock timeout. | [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) — `build_http_client`; PR #1184 adds `anchoring::http_limits::read_response_capped` and wires all four outbound call sites through it |
| Concurrent SMT writer safety (audit H-4) | Persistent SMT writers serialize via `acquire_write_lock` (Postgres `pg_advisory_lock` / `tokio::Mutex`). The lock is held across the read-modify-write in `update_batch`, and the in-memory hot cache is refreshed inside the locked section — preventing stale-cache stomp. | [`src-tauri/src/smt/tree.rs`](../src-tauri/src/smt/tree.rs) — `update_batch`, `acquire_write_lock`, `load_hot` |
| Standalone verifier resource exhaustion | **`nPublic` cap (65 536) on the standalone Groth16 verifier is in flight** ([fix at #1186](https://github.com/OlympusLedgerOrg/Olympus/pull/1186)). Until merged, a tampered vkey with huge `nPublic` (real Olympus circuits have <16) can force a multi-million-point MSM in the court's verifier. | [`verifiers/rust/src/groth16.rs`](../verifiers/rust/src/groth16.rs); PR #1186 adds `MAX_N_PUBLIC` gates in `parse_vkey_json` and `parse_public_signals_json` |
| SBT replay race (audit H-3 / PR #1163) | `key_credentials.commit_id` has a UNIQUE constraint (migration 0040); the issue path uses `INSERT … ON CONFLICT (commit_id) DO NOTHING RETURNING id` with an idempotent loser path that returns the canonical row. Concurrent issuance over the same `(holder, type, ...)` tuple resolves to a single canonical credential. | [`migrations/0040_key_credentials_commit_id_unique.sql`](../migrations/0040_key_credentials_commit_id_unique.sql); [`src-tauri/src/api/credentials/mod.rs`](../src-tauri/src/api/credentials/mod.rs) — `issue_credential` |

---

## Summary

Olympus is a **tamper-evident audit trail** for sensitive records.  It cannot
prevent a bad actor from withholding documents, but it makes it cryptographically
impossible to alter or delete a committed document without that fact being
detectable by any independent verifier who has the original commitment hash.
