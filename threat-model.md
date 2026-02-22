# Olympus Threat Model

*A plain-English summary for auditors, policymakers, and grant committees.*

---

## What Problem Are We Solving?

Government records — budgets, contracts, FOIA responses, meeting minutes — are
supposed to be public and permanent.  In practice, they can be quietly edited,
deleted, or buried without anyone noticing.  Olympus is designed to make such
tampering **detectable**, even by someone who was not watching when the original
document was published.

---

## Who Are the Adversaries?

| Adversary | What they might do |
|-----------|-------------------|
| **Government official or contractor** | Edit or delete a previously published document to hide inconvenient information. |
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
When a document is released under FOIA with portions redacted, Olympus can prove
that the redacted version is derived from the same original that was committed
before the FOIA request arrived.  This prevents an agency from retroactively
changing what was in the document before redacting it.

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

## Summary

Olympus is a **tamper-evident audit trail** for public records.  It cannot
prevent a bad actor from withholding documents, but it makes it cryptographically
impossible to alter or delete a committed document without that fact being
detectable by any independent verifier who has the original commitment hash.
