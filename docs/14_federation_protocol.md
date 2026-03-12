# Federation Protocol Prototype (Phase 1+)

This document defines the **Phase 1+ federation prototype** for Olympus. It does **not** claim that v1.0 already ships a decentralized implementation; instead, it pins the smallest interoperable node-to-node protocol that future work must preserve.

The prototype is designed to extend the existing signed shard header and append-only ledger model without rewriting v1.0 semantics.

## Goals

- Define a deterministic **node-to-node protocol** for Stewards, Guardians, and Auditors.
- Specify **shard replication** as an append-only exchange of signed shard headers, ledger tails, and proofs.
- Define **header-signing consensus** via quorum acknowledgments over a single shard header hash.
- Preserve independent verification: every federation message is reducible to hashes, signatures, ledger linkage, and proofs already described elsewhere in the spec.

## Roles

- **Steward node**: Originates shard headers and serves canonical ledger/proof material.
- **Guardian node**: Replicates headers and ledger entries, verifies them, and signs acknowledgments.
- **Auditor node**: Observes public APIs, recomputes verification, and detects forks or gaps.

Role membership, trust roots, and dispute resolution policy are governed by `docs/10_federation_governance.md`.

## Prototype Assets in This Repository

- `protocol/federation.py` defines the `FederationNode` identity model, static
  registry loader, and `>= 2/3` quorum helpers.
- `examples/federation_registry.json` is the prototype registry shared by tests
  and CLI commands.
- `tools/olympus.py` exposes `node list` and `federation status` commands for
  operator visibility.

Each prototype node identity carries:

- `node_id`
- `pubkey`
- `operator`
- `endpoint`
- `jurisdiction`
- `status`

## Transport and Identity

- Transport is HTTPS with canonical JSON request/response bodies.
- Every node publishes an Ed25519 public key and fingerprint in the append-only identity registry.
- Every federation message includes:
  - `sender_id`
  - `sender_pubkey`
  - `sent_at`
  - `message_type`
  - `payload`
  - `signature`
- Signatures are computed over canonical JSON bytes of the unsigned message body.

## Existing v1.0 Read APIs Used by the Prototype

The federation prototype deliberately builds on the existing public verification surfaces:

- `GET /shards`
- `GET /shards/{shard_id}/header/latest`
- `GET /shards/{shard_id}/header/latest/verify`
- `GET /shards/{shard_id}/history`
- `GET /shards/{shard_id}/diff`
- `GET /ledger/{shard_id}/tail`
- `GET /shards/{shard_id}/proof`

These APIs are sufficient for a Guardian or Auditor to fetch the current signed state, verify chain linkage, and compare divergent views before any write-path federation automation exists.

## Message Types

### 1. Header Announcement

Steward → Guardians

```json
{
  "message_type": "header_announce",
  "payload": {
    "shard_id": "records/agency-a",
    "seq": 42,
    "header_hash": "<hex>",
    "root_hash": "<hex>",
    "previous_header_hash": "<hex>",
    "timestamp": "2026-03-08T00:00:00Z"
  }
}
```

Semantics:

- Announces the candidate shard header to be replicated.
- The `header_hash` must match the canonical shard header served at `GET /shards/{shard_id}/header/latest`.
- Guardians must reject announcements whose `previous_header_hash` does not extend their local append-only chain.

### 2. Replication Request

Guardian → Steward

```json
{
  "message_type": "replication_request",
  "payload": {
    "shard_id": "records/agency-a",
    "from_seq": 39,
    "to_seq": 42
  }
}
```

Semantics:

- Requests the missing signed headers, ledger tail, and any needed Merkle/SMT proofs for the specified sequence range.
- Requests are **range-based** so that gaps are explicit and auditable.

### 3. Replication Segment

Steward → Guardian

```json
{
  "message_type": "replication_segment",
  "payload": {
    "shard_id": "records/agency-a",
    "headers": ["<canonical header json>", "<canonical header json>"],
    "ledger_tail": ["<canonical ledger entry>", "<canonical ledger entry>"],
    "proof_refs": ["record_id=document:abc:1"]
  }
}
```

Semantics:

- Contains an append-only range of headers and ledger entries.
- Guardians verify every header signature, every `previous_header_hash`, and every ledger `previous_hash`.
- Guardians reject segments with missing sequence numbers, mismatched roots, or invalid proofs.

### 4. Guardian Acknowledgment

Guardian → Steward and other Guardians

```json
{
  "message_type": "guardian_ack",
  "payload": {
    "shard_id": "records/agency-a",
    "seq": 42,
    "header_hash": "<hex>",
    "replicated_at": "2026-03-08T00:00:10Z",
    "ledger_tail_hash": "<hex>"
  }
}
```

Semantics:

- States that the Guardian verified and stored the shard header and corresponding ledger state.
- Acknowledgments are append-only attestations; they never overwrite a prior acknowledgment.
- Guardians must not sign two different `header_hash` values for the same `(shard_id, seq)` unless they are explicitly publishing fork evidence.

### 5. Quorum Certificate

Derived artifact, served by Stewards or Auditors

```json
{
  "shard_id": "records/agency-a",
  "seq": 42,
  "header_hash": "<hex>",
  "scheme": "ed25519",
  "signer_bitmap": "<bitmap over active membership order>",
  "signatures": [{"node_id": "...", "signature": "<hex>"}],
  "quorum_threshold": 3
}
```

Semantics:

- A **quorum certificate** exists when signatures from at least `Q` distinct Guardians reference the same `header_hash`.
- `scheme` identifies the signature representation; the prototype uses `"ed25519"` and keeps room for future schemes (for example `"bls_aggregate"`).
- The certificate is independently verifiable from the included signatures, signer bitmap, and the published membership registry.
- Certificates are attached as append-only metadata; historical headers are never rewritten.

## Replication Algorithm

1. A Steward emits and signs a candidate shard header.
2. The Steward sends `header_announce` to all configured Guardians.
3. Each Guardian compares the announced `(shard_id, seq, previous_header_hash)` to its local state.
4. If a gap exists, the Guardian sends `replication_request`.
5. The Steward answers with `replication_segment`.
6. The Guardian verifies:
   - shard header signature validity,
   - header chain continuity,
   - ledger append-only linkage,
   - any referenced Merkle/SMT proofs,
   - optional anchor validity when tokens are present.
7. If verification succeeds, the Guardian persists the segment and emits `guardian_ack`.
8. When `Q` matching acknowledgments exist, the header is considered **federation-final**.

## Header-Signing Consensus

The prototype uses **quorum acknowledgment consensus**, not blind leader trust:

- The originating Steward signs the shard header hash first.
- Guardians independently verify the header and sign acknowledgments over that exact `header_hash`.
- Deterministic finality threshold:
  - Let `N` be the count of **active** federation members in the current registry epoch.
  - A root becomes canonical only when `Q = ceil(2N / 3)` distinct node signatures are present for the same `(shard_id, height, round, header_hash)`.
  - This rule supersedes earlier prototype discussions of `floor(N/2)+1`; the implementation uses only `FederationRegistry.quorum_threshold()`.
- If two distinct headers claim the same `(shard_id, height, round)`, the system has detected a fork.
- Deterministic fork resolution order:
  1. prefer the candidate with the highest number of valid signer approvals,
  2. then prefer the earliest valid certificate timestamp,
  3. then prefer the lexicographically lowest `header_hash` (stable tie-break for simultaneous roots).
- Replay protection:
  - Nodes reject any candidate root or quorum certificate whose `federation_epoch` is lower than the node's current epoch.
  - In addition, certificates must bind exactly to the current registry epoch and membership hash before they are accepted.

This makes header signing decentralized in the narrow protocol sense: no single Steward signature is sufficient for federation finality after the Phase 1+ cutover.

## Node Identity and Key Rotation Procedure

To avoid ambiguous authority during membership changes:

1. Node identity is always bound to `node_id` in the federation registry; verifiers must resolve verification keys from the registry, never from untrusted message payloads.
2. Key rotation appends the prior key to `key_history` with a `valid_until` timestamp and installs the new active key for the node.
3. Signature verification is timestamp-aware:
   - historical headers may verify with a key from `key_history` only when `header.timestamp <= valid_until`,
   - new headers after rotation must verify with the active key.
4. Registry epoch is part of every vote and quorum certificate. This binds signatures to a specific membership snapshot and prevents stale-epoch replay.

## VRF-Based Selections

The federation prototype now exposes deterministic VRF-style selection helpers
for committee and leader choice in a round:

- Selection seed binds `(shard_id, round_number, epoch, membership_hash)` using
  BLAKE3 domain separation (`OLY:VRF-SELECTION:V1`).
- Each active node receives a deterministic score from the seed and `node_id`.
- Committee selection picks the lowest `k` scores; leader selection picks the
  first committee member (`k=1`).

Because the seed includes epoch and membership hash, membership changes or epoch
advances produce a new selection ordering and prevent stale selection replay.

### Grinding-Attack Mitigation (Phase 1+ hardening)

Deterministic VRF scoring alone is vulnerable to grinding when an adaptive
adversary can generate many candidate proofs and reveal only favorable ones.
To harden this path, selection rounds support an additional entropy binding:

- participants publish a commitment to a private reveal value,
- participants later reveal the value,
- the protocol derives round entropy only from commitment-consistent reveals,
- optional non-interactive proof transcript hashes can be bound into the same
  entropy derivation so reveal material and proof context are coupled.

This commit-reveal entropy is then mixed into the VRF selection seed. The
result is still deterministic for verifiers, but no single party can bias the
seed by withholding unsuccessful local samples after seeing others' outputs.

## Safety and Liveness Notes

### Safety

- No Guardian may acknowledge a header without replaying signature and chain verification.
- No quorum certificate is valid if it mixes acknowledgments for different `header_hash` values.
- No node may truncate history during replication; all transfers are append-only ranges.

### Liveness

- A temporarily unavailable Guardian delays quorum but cannot rewrite prior committed history.
- Replication is pull-friendly: Guardians can recover after downtime by requesting the missing range.
- Auditors can reconstruct quorum status from public APIs plus signed acknowledgment artifacts.

### Finality Gadget Failure Modes (Layer 12 hardening notes)

Even with quorum certificates, finality assumptions can fail under:

- fully asynchronous network partitions (no timing guarantees),
- adaptive adversaries that target the currently leading set,
- cryptanalytic breaks (including quantum attacks on deployed signatures).

The federation roadmap addresses this with:

- post-quantum signature migration paths for quorum attestations,
- synchronous fallback operating modes when asynchronous liveness collapses,
- continuous monitoring, rotation, and incident response ("eternal vigilance")
  as an operational requirement, not an optional add-on.

## Explicit Non-Goals of the Prototype

- It does not specify transport encryption beyond HTTPS deployment expectations.
- It does not require a specific threshold-signature scheme; Ed25519 acknowledgments are sufficient for the prototype.
- It does not replace the legal/governance rules in `docs/10_federation_governance.md`.
- It does not change v1.0 into a production-ready decentralized network today; it defines the forward-compatible wire semantics needed to get there.
