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
Each batch of documents is signed using a cryptographic key (Ed25519).  A signed
"shard header" commits to the set of documents in a given batch.  A verifier can
check the signature independently and confirm no documents were added or removed
after signing.

### 4. Over-Redaction or Secret Redaction
When a document is released with portions redacted, Olympus can prove
that the redacted version is derived from the same original that was committed
before the redaction request arrived.  This prevents retroactive
changing of what was in the document before redacting it.

---

## How Does the Protocol Offer This Protection?

```
Document → Canonicalize → Hash → Merkle Tree → Signed Header → Hash-Chained Ledger
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

4. **Signed Shard Header** — The batch root is signed with an Ed25519 private
   key.  Anyone with the corresponding public key can verify the signature is
   authentic.

5. **Hash-Chained Ledger** — Every signed header is recorded in a ledger where
   each entry links back to the previous one.  Removing or reordering any entry
   breaks the chain and is detectable.

---

## What Olympus Does NOT Protect Against

- **Key compromise** — If the signing key is stolen, an attacker could sign
  forged headers.  Key management and rotation are outside this protocol.
- **Completeness** — Olympus cannot force a government agency to submit all
  records.  It only guarantees the integrity of what it has received.
- **Single-operator deletion** — If the only copy of the ledger is deleted and
  no replicas exist, the audit trail is lost.  Federation (planned for a future
  phase) addresses this.
- **Content confidentiality** — Olympus does not encrypt documents.  Access
  controls are a separate concern.

---

## Mitigations and Evidence

The table below maps each threat to the concrete mitigation implemented in this
repository, with links to the relevant source evidence.

### T1 — Silent After-the-Fact Modification

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Preimage resistance | BLAKE3 hash; changing any byte produces a different hash | [`protocol/hashes.py`](protocol/hashes.py) — `hash_bytes()` |
| Domain separation | Leaf / node / entry prefixes prevent cross-context collisions | [`protocol/hashes.py`](protocol/hashes.py) — `LEAF_PREFIX`, `NODE_PREFIX`, `ENTRY_PREFIX` |
| Merkle commitment | Single root commits all document parts; inclusion proof verifiable offline | [`protocol/merkle.py`](protocol/merkle.py) — `MerkleTree`, `verify_proof()` |
| Canonicalization | Deterministic byte sequence from any semantically equivalent input | [`protocol/canonical.py`](protocol/canonical.py), [`protocol/canonicalizer.py`](protocol/canonicalizer.py) |
| Cross-language test vectors | Canonicalization hash parity verified in Python, Go, JS, Rust | [`verifiers/test_vectors/canonicalizer_vectors.tsv`](verifiers/test_vectors/canonicalizer_vectors.tsv) |

### T2 — Retroactive Deletion or Reordering

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Hash-chained entries | Each `LedgerEntry.prev_entry_hash` binds to its predecessor | [`protocol/ledger.py`](protocol/ledger.py) — `LedgerEntry`, `Ledger.append()` |
| Chain verification | `verify_chain()` detects any gap or reordering | [`protocol/ledger.py`](protocol/ledger.py) — `Ledger.verify_chain()` |
| Append-only DB schema | No `UPDATE`/`DELETE` paths exist in the storage layer; PK enforces ordering | [`storage/postgres.py`](storage/postgres.py), [`migrations/001_init_schema.sql`](migrations/001_init_schema.sql) |
| SMT root divergence alert | Prometheus counter fires when replicas compute different roots | [`protocol/telemetry.py`](protocol/telemetry.py) — `smt_divergence_total` |

### T3 — Forged Audit Proofs

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Ed25519 shard header signature | Batch root signed before ledger append; verifiable with public key | [`protocol/shards.py`](protocol/shards.py) |
| Federation quorum certificate | Optional M-of-N quorum hash commits to multi-party agreement | [`protocol/federation/quorum.py`](protocol/federation/quorum.py), [`protocol/ledger.py`](protocol/ledger.py) |
| RFC 3161 timestamp token | SHA-256(BLAKE3 root) submitted to TSA; token stored alongside header | [`protocol/rfc3161.py`](protocol/rfc3161.py) |

### T4 — Over-Redaction or Secret Redaction

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| Redaction commitment | Document parts hashed individually into Merkle tree before any release | [`protocol/redaction.py`](protocol/redaction.py) — `RedactionProtocol.commit_document()` |
| Redaction proof binding | Revealed leaves verified against original committed root | [`protocol/redaction.py`](protocol/redaction.py) — `verify_redaction_proof()` |
| Semantic equivalence | Canonicalization ensures whitespace / formatting changes do not mask content | [`protocol/canonical.py`](protocol/canonical.py) — `normalize_whitespace()` |

### T5 — Infrastructure / Operational Attacks

| Property | Mitigation | Evidence |
|----------|-----------|---------|
| DB connection resilience | Connection pool with exponential-backoff retry + circuit breaker | [`storage/postgres.py`](storage/postgres.py) — `StorageLayer._get_connection()` |
| Supply-chain integrity | SBOM (CycloneDX) + `pip-audit` on every CI run | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — `supply-chain` job |
| Static security analysis | Bandit scan across all first-party code | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) — `lint` job |
| CodeQL extended queries | Semantic vulnerability patterns detected in CI | [`.github/workflows/codeql.yml`](.github/workflows/codeql.yml) |
| Observability / alerting | OpenTelemetry traces + Prometheus metrics expose anomalies in real time | [`protocol/telemetry.py`](protocol/telemetry.py) |

---

## Summary

Olympus is a **tamper-evident audit trail** for sensitive records.  It cannot
prevent a bad actor from withholding documents, but it makes it cryptographically
impossible to alter or delete a committed document without that fact being
detectable by any independent verifier who has the original commitment hash.
