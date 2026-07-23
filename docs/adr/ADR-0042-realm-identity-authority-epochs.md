# ADR-0042: Realm identity and authority epochs

- **Status:** Proposed (2026-07-21; revised 2026-07-23)
- **Builds on:**
  - ADR-0041 (role-separated, freshness-bound trust lists) — realm-authority
    keys are issued as `TrustRole::RealmAuthority` entries in a
    `TrustListSnapshotV1`, resolved through `TrustResolver`, not a second
    parallel trust mechanism. This ADR depends specifically on ADR-0041's
    `TrustRole::RealmAuthority`, `TrustListSnapshotV1`, role-indexed
    `rotation_policies`, and shared generic quorum core. If any of those
    contracts change before acceptance, this ADR must be updated and reviewed
    again before implementation.
  - ADR-0033 (checkpoint-quorum co-signatures) and ADR-0041 §4 — epoch
    transitions follow the established domain-separated-quorum *shape*
    (dedicated message function + dedicated verifier over the shared generic
    core), not a literal call to `quorum::verify_quorum` — see §3 below.
  - ADR-0031 (transition attestations + enforced insert-only ledger) — epoch
    fencing must compose with, not bypass, the `update_batch_inner` write-once
    guard and the H-4 write lock. ADR-0031 §4 (the peer-coverage/withholding
    gap) is explicitly reopened and partially resolved below.
  - ADR-0021 (SMT + CT-style operational hardening) — the "Monitor API" was
    named there and explicitly deferred; this ADR picks it up.
  - The existing `shards` registry (migration `0039_shards.sql`) and
    `PeerCheckpoint` wire v3 (already shard-scoped with
    `checkpoint_scope="shard"`, a validated `shard_id`, and an append-transition
    witness; equivocation and peer-identity locks key on `(identity, shard)` per
    migrations `0051` and `0053`).
- **Rollout gate:** ADR-0041 must be accepted and merged, its migration must be
  applied in a staging/test environment, and at least one complete
  `TrustRole::RealmAuthority` rotation cycle must succeed there before this
  ADR's migration may be applied in production.
- **Does not change:** any leaf/node hash, the existence/unified circuits, the
  proving ceremony, or `PeerCheckpoint`'s core v3 checkpoint fields. Shards
  with no `authority_realm_id` behave exactly as they do today — realm
  governance is opt-in per shard.

## Context

`shards` (migration 0039) has `shard_id, owner_user_id, label, created_by,
created_at, active` — one owner account, no epoch, no realm concept.
`PeerCheckpoint` is already shard-scoped and peer identity is already
canonicalized and locked per `(identity, shard)`. So the per-shard
*checkpoint* plumbing exists; per-shard *authority* does not.

`federation/` today is a single, flat model: arbitrary-membership,
checkpoint-only, Tor-gossiped, CT-style independent witnessing ("you don't
have to trust us, you can be us" — README). This ADR introduces a second,
narrower concept — a bounded, authoritative **realm** that can hold and
replicate a shard's actual event data — and states explicitly how the two
relate: **realm federation is strictly additive and opt-in per shard.** A
shard with no assigned realm keeps today's flat, checkpoint-only behavior
unchanged. Realm federation does not replace peer-checkpoint federation; it
is a stronger mode a shard can opt into.

ADR-0031 §4 named an open problem: peers have "~zero witness coverage of each
other's records" because gossip carries checkpoint roots only, never record
content. A node can therefore withhold a record while publishing honest
checkpoints over what it does retain.

This ADR improves that limitation for realm-governed shards, but does not claim
unconditional completeness. A missing interior sequence is detectable only
when an independent observer knows a later signed sequence or a signed
closed-epoch high-water mark, and when at least one realm replica or monitor
retains the complete event history needed for comparison. A withheld tail
before any independently observed successor remains undetectable. Replica
acceptance enforcement, transfer, scheduling, repair, and availability remain
deferred. These limits follow the repository threat model's **Completeness**
and **Single-operator deletion** non-guarantees in
[`docs/threat-model.md`](../threat-model.md#what-olympus-does-not-protect-against).
Ungoverned shards retain ADR-0031's original limitation unchanged.

## Decision

### 1. Realm registry and key lifecycle

Add a stable realm-identity table:

`realms`: `realm_id, label, capabilities (jsonb), created_at, active`, with
`PRIMARY KEY (realm_id)`.

Realm signing keys are versioned separately in an append-only table:

`realm_authority_keys`: `realm_id, key_version, bjj_pubkey_x, bjj_pubkey_y,
issuer_pubkey_hash, trust_snapshot_sequence, trust_snapshot_digest, trust_role,
created_at`.

The migration makes the invariants machine-checkable:

- `PRIMARY KEY (realm_id, key_version)` and `CHECK (key_version >= 1)`.
- `UNIQUE (issuer_pubkey_hash)` and `UNIQUE (bjj_pubkey_x, bjj_pubkey_y)`;
  one authority key cannot ambiguously name multiple realms or versions.
- `issuer_pubkey_hash` is the canonical 32-byte big-endian encoding of
  `Poseidon(bjj_pubkey_x, bjj_pubkey_y)`.
- ADR-0041's migration must expose an immutable normalized issuer-role
  projection. A composite foreign key binds
  `(trust_snapshot_sequence, trust_snapshot_digest, issuer_pubkey_hash,
  bjj_pubkey_x, bjj_pubkey_y, trust_role)` to the exact accepted
  `TrustedIssuer` entry. A `CHECK (trust_role = 'realm_authority')` prevents
  another role from satisfying that reference.
- Insert validation recomputes the authority hash and rejects non-canonical,
  off-curve, non-subgroup, role-mismatched, or coordinate/hash-inconsistent
  bindings before insertion. The composite foreign key prevents a later
  inconsistent binding even if application validation regresses.
- Database permissions and an immutable-row trigger reject `UPDATE` and
  `DELETE`; rotation is insertion only.

The canonical trust reference is:

```text
TrustRefV1 =
  u64_be(trust_snapshot_sequence) ||
  trust_snapshot_digest[32] ||
  issuer_pubkey_hash[32]
```

A key binding is active only when `TrustResolver::issuer_is_active_for` accepts
the referenced key for `TrustRole::RealmAuthority` at the decision time. There
is no bespoke realm trust lookup and no second trust list.

Realm identity is stable across key rotation. Rotating a realm key appends a
new key row and requires an explicit authority-epoch transition under §3, even
when `realm_id` is unchanged. A newer trust-list snapshot does **not**
automatically change a shard's key. Historical events remain verifiable
against the key and trust reference pinned by their epoch; new live writes fail
closed if the current epoch's key is no longer active.

`capabilities` records supported protocol ranges and schema versions for §6.
Any network advertisement must be signed by the key pinned to the advertised
authority epoch. Unsigned metadata is informational only and cannot affect
protocol selection.

### 2. Shard authority, owner interaction, and genesis

Extend `shards` with:

- `authority_realm_id` — nullable realm identifier.
- `authority_key_version` — nullable key version for that realm.
- `authority_epoch BIGINT NOT NULL DEFAULT 0`.

The schema adds a composite foreign key
`(authority_realm_id, authority_key_version) ->
realm_authority_keys(realm_id, key_version)` and this check:

```sql
CHECK (
  (authority_realm_id IS NULL AND authority_key_version IS NULL
   AND authority_epoch = 0)
  OR
  (authority_realm_id IS NOT NULL AND authority_key_version IS NOT NULL
   AND authority_epoch >= 1)
)
```

`owner_user_id` remains the local API admission and namespace control used by
the existing ingest gate. It is not cryptographic realm authority. Once a
realm is assigned, neither the owner nor an admin-scoped key may bypass the
signed event envelope, epoch check, or sequencing rules.

Opt-in uses the genesis transition `0 -> 1`. Genesis must record local
authorization evidence in addition to the new realm quorum's acceptance:

- `local_authorization_kind` is exactly `owner_signed_request` or
  `admin_recovery`.
- `local_authorizer_id` names the authenticated API-key/operator identity.
- `local_authorization_artifact_hash` is
  `BLAKE3("OLY:REALM:GENESIS-AUTH:V1" || lp(envelope_bytes))`, where
  `envelope_bytes` is the complete canonical, verified ADR-0036 signed-request
  envelope.
- `recovery_case_id`, `recovery_reason`, and
  `recovery_reason_hash = BLAKE3(UTF8(recovery_reason))` are required for
  `admin_recovery` and empty for `owner_signed_request`.

For `owner_signed_request`, the authenticated key's `user_id` must equal the
shard's current non-null `owner_user_id`, and the signed request must bind the
shard ID, new realm/key/trust reference, nonce, and issuance time. For
`admin_recovery`, the request must pass the signed admin-envelope gate with
`scope = "admin"`; the operator identity, non-empty case ID, and non-empty
reason are persisted so replaying nodes and auditors can identify a forced
assignment. A shard with no owner can opt in only through `admin_recovery`.

The transition message in §3 binds the authorization kind, identity, artifact
hash, case ID, and reason hash. The transition row stores those fields plus the
verified artifact and reason. This proves which local credential authorized
the opt-in; it does **not** prove owner consent, legal authority, correctness of
the recovery reason, or that an administrator was uncompromised. Those are
explicit trust-model limits.

After opt-in, authority changes occur only through §3. A governed shard cannot
be set back to `NULL`; de-governance requires a separate ADR.

### 3. Epoch fencing

`authority_epoch` advances exactly by one through a quorum-cosigned message
with the domain prefix `OLY:REALM:AUTHORITY:V1`. The implementation adds
`realm_authority_message` and `verify_realm_authority_quorum` as thin wrappers
over ADR-0041's shared generic quorum core; it cannot reuse the hardcoded
`OLY:SBT:QUORUM:V2` constructor.

The signed transition binds every authoritative field persisted by the
transition:

```text
OLY:REALM:AUTHORITY:V1 ||
  lp(shard_id) ||
  lp(old_epoch_be) || lp(new_epoch_be) ||
  lp(old_realm_id_or_empty) ||
  lp(old_authority_key_version_be_or_empty) ||
  lp(old_authority_pubkey_hash_or_empty) ||
  lp(old_trust_ref_or_empty) ||
  lp(old_epoch_final_sequence_be) ||
  lp(old_epoch_final_event_digest_or_empty) ||
  lp(new_realm_id) ||
  lp(new_authority_key_version_be) ||
  lp(new_authority_pubkey_hash) ||
  lp(new_trust_ref) ||
  lp(local_authorization_kind) ||
  lp(local_authorizer_id_or_empty) ||
  lp(local_authorization_artifact_hash_or_empty) ||
  lp(recovery_case_id_or_empty) ||
  lp(recovery_reason_hash_or_empty)
```

`old_trust_ref` and `new_trust_ref` use the injective `TrustRefV1` encoding in
§1. Genesis uses empty old-authority fields, final sequence zero, and an empty
final-event digest. Non-genesis transitions use
`local_authorization_kind = "none"` and empty local-authorization fields.

The signer set and threshold come from
`rotation_policies[TrustRole::RealmAuthority]` in the currently accepted
`TrustListSnapshotV1`; this ADR does not invent a per-shard signer set.

`shard_authority_transitions` stores every field above, the canonical message
digest, quorum signatures, verified local authorization evidence, and
acceptance time. It has `PRIMARY KEY (shard_id, new_epoch)`,
`CHECK (new_epoch = old_epoch + 1)`, composite foreign keys to both referenced
realm keys, and immutable-row enforcement. Transition rows are insert-only.

Transition application is one database transaction and one per-shard
serialization boundary:

1. Lock the shard authority row and its event cursor.
2. Compare the complete stored old realm, key version, epoch, trust reference,
   and cursor against the signed old state.
3. Require the old cursor to equal `old_epoch_final_sequence` and, when
   non-zero, require its canonical event digest to match the signed final-event
   digest.
4. Validate trust, quorum signatures, and any genesis authorization evidence.
5. Insert the unique transition row.
6. Update the materialized `shards` pointer with a compare-and-swap predicate
   over the complete old state; exactly one row must change.
7. Commit both operations together.

A uniqueness conflict, failed comparison, or zero-row pointer update aborts the
transaction. Concurrent transitions cannot fork one epoch, and a crash cannot
persist history without its pointer or a pointer without its history. Replay
reconstructs transitions in increasing `new_epoch` order and verifies each
signed predecessor state.

Live event application additionally holds the existing H-4 write lock inside
`update_batch_inner`; authority validation, canonical event insertion, SMT
mutation, and sequence advancement share that transaction and serialization
boundary. This follows ADR-0031 PR2's move of the write-once check inside the
lock to avoid a check-then-write TOCTOU window.

### 4. Signed event envelope

The normative constructor is
`olympus_crypto::federation::event_message_v1`. Wire serialization is not the
signing contract. It constructs the following bytes and returns their 32-byte
BLAKE3 digest:

```text
OLY:FEDERATION:EVENT:V1 ||
  lp(shard_id_utf8) ||
  lp(u64_be(authority_epoch)) ||
  lp(u64_be(sequence)) ||
  lp(issuer_pubkey_hash[32]) ||
  lp(resource_key[32]) ||
  lp(payload_hash[32])
```

`lp(x)` is a four-byte big-endian length followed by `x`.
`issuer_pubkey_hash` is the 32-byte big-endian encoding of
`Poseidon(authority_pubkey_x, authority_pubkey_y)`. The BJJ message is
`Fr::from_le_bytes_mod_order(message_digest)`, matching Olympus's current BJJ
signing convention.

The event wire field is `payload_canonical_b64`. After base64 decoding, the
bytes must be a UTF-8 JSON object and must equal
`olympus_crypto::canonical::canonicalize_bytes(decoded)` byte-for-byte. This is
the existing `canonical_v2` JCS/NFC/decimal encoding. Non-canonical input is
rejected rather than silently reserialized. `payload_hash` is BLAKE3 over those
exact canonical bytes. `resource_key` is the existing shard-bound 32-byte
ledger key.

The positive interoperability fixture
[`test_vectors/federation_event_v1.json`](../../test_vectors/federation_event_v1.json)
contains the source and canonical payload, payload/resource/key hashes, complete
preimage, message digest, reduced BJJ field message, deterministic test key,
expected signature, and `expected_valid = true`. Rust and every standalone
verifier must consume that fixture; changing one encoded byte must reject.

Event ingestion separates receipt from canonical application:

- `realm_event_inbox` may store a validly signed duplicate or out-of-order
  envelope as `pending`, keyed by its signed digest. Pending rows are not
  canonical ledger history and do not update the SMT or cursor.
- `realm_event_cursors` has one row per `(shard_id, authority_epoch)` with
  `last_sequence` and `last_event_digest`.
- Canonical application locks the cursor and shard, requires
  `sequence = last_sequence + 1`, revalidates the current accepted transition,
  key, signature, payload hash, and resource key, then inserts the canonical
  event, applies the SMT update through `update_batch_inner`, and advances the
  cursor in the same transaction.
- `PRIMARY KEY (shard_id, authority_epoch, sequence)` protects canonical
  history. The same digest is idempotent; a different digest for that tuple is
  persisted as equivocation evidence and never applied.
- A transition out of an epoch cannot commit until the cursor reaches its
  signed `old_epoch_final_sequence`; therefore transition/event ordering is
  machine-checkable.
- Historical replay may apply an old epoch only while reconstructing the
  append-only transition and event chain. The live path accepts only the
  current epoch.

A later received sequence or signed closed-epoch high-water mark makes an
interior gap observable. Out-of-order events remain pending until predecessors
arrive. Automated transfer, acceptance enforcement, scheduling, and repair are
deferred to ADR-0044; a missing tail with no independently observed successor
is still outside the completeness guarantee described in the Context section.

### 5. Monitor API

Extend `federation/api.rs` with a **public, read-only surface that does not
require `x-admin-key`** for signed tree heads, checkpoint history,
equivocation evidence, and per-shard event-gap/lag status. This implements the
Monitor API deferred by ADR-0021 now that realm-governed shards produce real
gap data.

The public status is intentionally limited to verifiable or coarse operational
data: signed heads, signed authority-transition identifiers, missing sequence
ranges, last applied sequence, and bounded lag counts/timestamps. It must not
expose record payloads, peer/onion topology, internal queue contents, database
errors, or unsigned diagnostic detail. Endpoints are paginated and rate-limited.
Richer operational diagnostics remain on the authenticated admin surface.

This evidence is considered public by design. Deployments that need private
operational telemetry may add a separate authenticated view, but may not hide
or weaken the public cryptographic evidence required for independent
monitoring.

### 6. Capability negotiation

`PeerCheckpoint.wire_version` is currently hard-rejected on mismatch. Realm
capabilities are advertised as ranges in `realms.capabilities`, for example:

```json
{
  "checkpoint_wire": { "min": 3, "max": 3 },
  "event_wire": { "min": 1, "max": 1 },
  "realm_schema": { "min": 1, "max": 1 }
}
```

The same capability object is returned as a backward-compatible extension of
the existing `GET /federation/identity` response over the existing Tor
transport. No separate version-agnostic channel is introduced. The response
includes the current `realm_id`, `authority_epoch`, authority-key hash, a
monotonic capability revision, and a BJJ signature over:

```text
OLY:REALM:CAPABILITIES:V1 ||
  lp(realm_id) ||
  lp(authority_epoch_be) ||
  lp(authority_pubkey_hash) ||
  lp(capability_revision_be) ||
  lp(capabilities_hash)
```

Older peers may ignore the added fields. Capable peers verify the signature and
choose the highest mutually supported version before checkpoint or event
exchange. A peer advertisement can never lower the receiver's compiled minimum
security floor.

The initial implementation may continue to emit only the current wire version.
When no overlap exists, it returns a structured `unsupported_protocol` error
containing the supported range and the minimum version to upgrade to, rather
than silently failing or inferring an older envelope. `PeerCheckpoint`'s v3
checkpoint fields remain unchanged.

### Explicitly deferred to later ADRs

Snapshot-plus-event-tail *transfer* (authority-epoch fencing must be proven
first), replica/locality policy, reconciliation/repair automation, governed-to-
ungoverned downgrade, and higher-level user/workspace ownership are out of
scope. The intended ordering remains:

trust recovery → realm/authority foundation → signed events →
checkpoints/monitors → replication/transfer/repair.

## Consequences

- Gives movable shard authority a real fencing token instead of relying on the
  flat `owner_user_id`; makes interior omissions conditionally detectable for
  realm-governed shards under the explicit observer, replica-retention, and
  signed-high-water assumptions above. It does not prove source completeness or
  eliminate ADR-0031 §4 for ungoverned shards.
- Reuses the existing role-aware trust resolver, generic quorum core, H-4 lock,
  write-once guard, shard-scoped checkpoint identity, and BJJ signing pattern
  instead of creating parallel mechanisms.
- No leaf/node hash, circuit, verifier-key, proof format, or ceremony change.
- Requires a forward migration for `realms`, append-only
  `realm_authority_keys`, append-only `shard_authority_transitions`, event
  sequence constraints, and the three new `shards` columns. The migration
  number is claimed at implementation time, after ADR-0041's migration and
  after the repository's then-current migration head (`0053` as of
  2026-07-23).
- Must not land before the rollout gate at the top of this ADR is satisfied.
