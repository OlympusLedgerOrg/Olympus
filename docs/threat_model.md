# Threat Model Walkthrough

This document is the reviewer-oriented threat model for Olympus. It complements
`docs/01_threat_model.md` by spelling out concrete federation assumptions,
adversary capabilities, and attack scenarios in plain language.

## System Goals

Olympus guarantees:

- document existence proofs for committed artifacts
- tamper-evident records via append-only linkage and signed shard headers
- independent verification of hashes, signatures, Merkle paths, and proofs
- resilience against individual node compromise once a federation quorum is in use

Olympus does **not** guarantee completeness of publication, lawful redaction
policy, or perfect availability under every operational failure.

## Adversary Types

| Adversary | Capability |
| --- | --- |
| Government actor | Attempts evidence suppression or publication delay |
| Malicious node | Tries to rewrite history or sign a conflicting shard header |
| Spam attacker | Floods ingestion with junk commits or low-value submissions |
| Network attacker | Intercepts, delays, or replays node-to-node communications |
| Key thief | Exfiltrates one node's signing key and tries to impersonate it |

## Attack Scenarios

### Ledger Rewriting

**Attack**

Federation nodes attempt to alter historical commits after they were already
observed by verifiers.

**Defense**

- Merkle proofs
- signed shard headers
- append-only ledger linkage
- external anchoring when timestamp tokens are present

**Reviewer takeaway**

Changing history changes the hashes. Replayed verification exposes the fork or
invalidates old proofs.

### Evidence Suppression

**Attack**

An authority pressures one node to delete or hide prior commits.

**Defense**

- replication across federation nodes
- public proof verification
- auditor comparison of shard history and ledger tails

**Reviewer takeaway**

Deletion on one node does not erase the commitment from other replicas or from
already-exported proofs.

### Sybil Node Attack

**Attack**

An attacker spins up many fake nodes to outvote honest operators.

**Defense**

- controlled federation registry
- institutional node operators
- quorum calculated only across registered active nodes

**Reviewer takeaway**

The prototype trust boundary is the static federation registry. Fake nodes do
not count unless admitted into that registry.

### Spam Submissions

**Attack**

An attacker floods the ledger with junk commits to degrade service or drown out
meaningful records.

**Possible mitigations**

- rate limiting
- proof-of-work
- reputation weighting
- operator review queues or submission quotas

**Reviewer takeaway**

Spam is primarily an availability and operations problem, not a cryptographic
integrity failure.

### Malicious Redaction Claim

**Attack**

An agency publishes a redacted artifact and falsely claims it corresponds to an
earlier committed document.

**Defense**

- canonical document hashing
- Merkle / SMT inclusion checks
- redaction proof verification
- signed shard headers tying the commitment to a specific state root

**Reviewer takeaway**

Olympus can show that a redaction claim matches a real commitment, but it cannot
force an agency to commit every document in the first place.
