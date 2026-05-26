# Olympus Threat Model

*A plain-English summary for auditors, policymakers, and grant committees.*

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
| Per-record content binding | `ledger_entry_hash = BLAKE3("OLY:LEDGER_ENTRY:V1\|" \|\| content_hash \|\| "\|" \|\| proof_id)` — a stable digest that pins each record to its canonicalized content and proof identifier (not to a predecessor) | [`src-tauri/src/api/ingest.rs`](../src-tauri/src/api/ingest.rs) — `ledger_entry_hash` construction |
| SMT-root commitment | Every ingest updates the sparse Merkle tree in-place; the resulting `ledger_root` is what gets signed into a checkpoint, so any removal/reorder produces a root that won't match a previously-anchored checkpoint | [`crates/olympus-crypto/src/smt.rs`](../crates/olympus-crypto/src/smt.rs) — `update(key, value_hash, parser_id, canonical_parser_version)` recomputes internal nodes; [`src-tauri/src/federation/checkpoint.rs`](../src-tauri/src/federation/checkpoint.rs) — checkpoint binds `ledger_root` + `tree_size` |
| Narrow-scope mutations only | DB schema does not allow arbitrary updates: `ingest_records` permits only NULL-backfill of `content_json` and one-shot attach of `zk_bundle`; `peer_checkpoints` is mutated only by the equivocation detector to flag a competing root; `anchor_receipts` has one monotonic OTS pending → upgraded transition. There is no path that overwrites `content_hash`, `ledger_entry_hash`, `merkle_root`, or `poseidon_root` after the initial insert | [`migrations/`](../migrations/) — `0001` through `0031`; [`src-tauri/src/api/ingest.rs`](../src-tauri/src/api/ingest.rs) — narrow UPDATEs (`content_json IS NULL` guard, zk_bundle attach); [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs); [`docs/court-evidence.md`](court-evidence.md) — OTS upgrade |
| SMT root consistency across federation peers | Peers gossip signed checkpoints; equivocation (two different roots at the same sequence) triggers auto-blocking | [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs); [`src-tauri/src/federation/gossip.rs`](../src-tauri/src/federation/gossip.rs) |

### T3 — Forged Audit Proofs

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| BJJ-EdDSA checkpoint signing | Each checkpoint is signed with the persistent Baby Jubjub authority key using EdDSA-Poseidon; the signature components (`bjj_signature_r8x`, `bjj_signature_r8y`, `bjj_signature_s`) are included in the anchored digest so the signature is bound into the timestamped envelope | [`src-tauri/src/federation/checkpoint.rs`](../src-tauri/src/federation/checkpoint.rs) — `build_own_checkpoint()`; [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) — `checkpoint_anchor_hash()` |
| Federation peer signature verification | Peers verify each received checkpoint's BJJ-EdDSA signature against the sender's authority pubkey before accepting it; equivocation detection (two valid signatures over different roots at the same sequence) auto-blocks misbehaving nodes | [`src-tauri/src/federation/verify.rs`](../src-tauri/src/federation/verify.rs) — `baby_jubjub::verify_signature`; [`src-tauri/src/federation/equivocation.rs`](../src-tauri/src/federation/equivocation.rs) |
| Ed25519 signing on the Rekor anchor path | The Rekor transparency-log entry payload is signed with the operator's Ed25519 key so the log entry itself is attributable | [`src-tauri/src/anchoring/rekor.rs`](../src-tauri/src/anchoring/rekor.rs) |
| RFC 3161 timestamp token | Domain-separated BLAKE3 checkpoint digest submitted to accredited TSA; receipt stored verbatim for `openssl ts -verify` | [`src-tauri/src/anchoring/rfc3161.rs`](../src-tauri/src/anchoring/rfc3161.rs) |
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
> [`docs/SECURITY_AUDIT_REPORT_V3.md`](SECURITY_AUDIT_REPORT_V3.md).

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
| DoS hardening | Axum request timeouts, CORS narrowing, streaming body caps, per-IP rate limiting via `governor` | [`src-tauri/src/server/mod.rs`](../src-tauri/src/server/mod.rs); [`src-tauri/src/api/middleware/auth.rs`](../src-tauri/src/api/middleware/auth.rs) |

---

## Summary

Olympus is a **tamper-evident audit trail** for sensitive records.  It cannot
prevent a bad actor from withholding documents, but it makes it cryptographically
impossible to alter or delete a committed document without that fact being
detectable by any independent verifier who has the original commitment hash.
