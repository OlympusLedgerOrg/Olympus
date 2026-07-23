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
content, so a node can withhold a record while publishing honest checkpoints
over what it does keep — undetectably. §4 was left as an explicit human
decision, "do not implement before resolving." This ADR resolves it **for
realm-governed shards only**: a designated realm replica is expected to hold
full event data by construction, so a gap in its replayed event sequence is a
detectable, attributable fault — not an undetectable omission. For shards that
remain outside any realm, §4's limitation is unchanged (ADR-0031's Option 3
— accept and document the limitation — continues to apply until a shard opts
in).

## Decision

### 1. Realm registry and key lifecycle

Add a stable realm-identity table:

`realms`: `realm_id, label, capabilities (jsonb), created_at, active`.

Realm signing keys are versioned separately in an append-only table:

`realm_authority_keys`: `realm_id, key_version, bjj_pubkey_x, bjj_pubkey_y,
issuer_pubkey_hash, trust_ref, created_at`.

A key binding exists only when the referenced key is a `TrustedIssuer` entry
tagged `TrustRole::RealmAuthority` in the accepted `TrustListSnapshotV1`
identified by `trust_ref`. The binding is checked through
`TrustResolver::issuer_is_active_for(pubkey, TrustRole::RealmAuthority, at)`;
there is no bespoke realm trust lookup and no second trust list.

Realm identity is stable across key rotation. Key rows are never rewritten or
deleted. Rotating a realm key appends a new `realm_authority_keys` row and
requires an explicit authority-epoch transition under §3, even when the
`realm_id` does not change. A newer trust-list snapshot therefore does **not**
automatically change a shard's authority key. Historical events remain
verifiable against the key binding and trust snapshot pinned by their recorded
epoch; new live writes fail closed if that epoch's key is no longer active.

`capabilities` records supported protocol ranges and schema versions for §6.
The database value is operational metadata, but any network advertisement of it
must be signed by the realm key pinned to the current authority epoch; an
unsigned advertisement is informational only and cannot affect protocol
selection.

### 2. Shard authority, owner interaction, and genesis

Extend `shards`:

- `authority_realm_id` — nullable FK to `realms`. `NULL` means ungoverned
  (current behavior, unchanged).
- `authority_key_version` — nullable key version for the assigned realm. It is
  `NULL` exactly when `authority_realm_id` is `NULL`.
- `authority_epoch BIGINT NOT NULL DEFAULT 0`.

`owner_user_id` remains the local API admission/namespace control used by the
existing ingest authorization gate. It does not become cryptographic realm
authority. Once `authority_realm_id` is set, neither the owner nor an
admin-scoped key may bypass the signed event envelope, current-epoch check, or
realm sequencing rules. Local authorization may allow a caller to submit a
write; the realm authority decides whether that write is ordered and committed.

Opt-in uses a defined genesis transition:

- An ungoverned shard begins at `(authority_realm_id = NULL,
  authority_key_version = NULL, authority_epoch = 0)`.
- The first realm assignment is the transition `0 -> 1`.
- The request must pass the existing local shard-administration gate. If the
  shard has an `owner_user_id`, the owner must authorize the opt-in unless an
  operator uses the explicit admin recovery path.
- The new realm's role-scoped rotation quorum must co-sign the genesis
  transition, proving that the realm accepts responsibility for the shard.

After opt-in, authority changes occur only through §3. Ordinary row updates may
not set a governed shard back to `NULL`; downgrade or de-governance requires a
separate ADR.

### 3. Epoch fencing

`authority_epoch` advances exactly by one through a quorum-cosigned message
with the domain prefix `OLY:REALM:AUTHORITY:V1`. Per ADR-0041 §4, this cannot
be a literal call to `quorum::verify_quorum` — that function's existing message
constructor hardcodes `OLY:SBT:QUORUM:V2`. The implementation adds
`realm_authority_message` and `verify_realm_authority_quorum` as thin wrappers
over ADR-0041's shared generic quorum core.

The signed transition binds both the old and new authority state:

```
OLY:REALM:AUTHORITY:V1 ||
  lp(shard_id) ||
  lp(old_epoch_be) || lp(new_epoch_be) ||
  lp(old_realm_id_or_empty) ||
  lp(old_authority_pubkey_hash_or_empty) ||
  lp(new_realm_id) ||
  lp(new_authority_pubkey_hash) ||
  lp(new_trust_snapshot_sequence_be)
```

The signer set and threshold come from
`rotation_policies[TrustRole::RealmAuthority]` in the currently accepted
`TrustListSnapshotV1`; this ADR does not invent a per-shard signer set.

Every accepted transition is appended to `shard_authority_transitions` with
its canonical message digest, old/new authority state, trust reference, quorum
signatures, and acceptance timestamp. Transition rows are never updated or
deleted. The current columns on `shards` are a materialized pointer to the
latest accepted transition, not the historical source of truth.

The live write path validates the event's epoch and issuer key **inside the same
locked section** `update_batch_inner` already uses for the H-4
write-lock/read-modify-write. The current shard authority state is read and
compared in that critical section before applying the leaf update. This follows
the same pattern ADR-0031 PR2 used when the write-once guard was moved inside
the lock to avoid a check-then-write TOCTOU window.

### 4. Signed event envelope

The signature input is the output of a single constructor in
`olympus-crypto`; wire serialization is not itself the signing contract:

```
OLY:FEDERATION:EVENT:V1 ||
  lp(shard_id) ||
  lp(authority_epoch_be) ||
  lp(sequence_be) ||
  lp(issuer_pubkey_hash) ||
  lp(resource_key) ||
  lp(payload_hash)
```

`payload_hash` is the 32-byte BLAKE3 digest of the event's canonical payload.
`resource_key` is the existing shard-bound 32-byte ledger key. The resulting
message digest is BJJ-signed using the existing Olympus BJJ signing pattern.

Replay and equivocation rules are explicit:

- `sequence` starts at 1 and is contiguous within each
  `(shard_id, authority_epoch)`.
- A database uniqueness constraint covers
  `(shard_id, authority_epoch, sequence)`.
- Re-receiving the same signed digest is idempotent; a different digest at the
  same tuple is equivocation evidence.
- `shard_id` prevents cross-shard replay, `authority_epoch` prevents
  cross-epoch replay, and `issuer_pubkey_hash` must equal the key pinned by the
  accepted transition for that epoch.
- Historical replay may apply an older epoch only while rebuilding from the
  append-only transition/event history. The live write path accepts only the
  current epoch.

Events replicate to a realm's designated replicas. A non-contiguous sequence
is a detectable, attributable gap and becomes input to later repair work. The
scheduler and automated repair policy — including whether to reuse the OTS
upgrade-worker's lease/claim/backoff shape — are deferred to ADR-0044; this ADR
does not depend on ADR-0044 already existing or being accepted.

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

```
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

```
OLY:REALM:CAPABILITIES:V1 ||
  lp(realm_id) ||
  lp(authority_epoch_be) ||
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
  flat `owner_user_id`; closes ADR-0031 §4 for realm-governed shards
  specifically, without overclaiming a fix for ungoverned ones.
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
