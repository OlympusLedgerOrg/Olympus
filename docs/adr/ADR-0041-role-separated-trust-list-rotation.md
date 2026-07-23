# ADR-0041: Role-separated trust-list rotation, quorum enforcement, and signer activation

- **Status:** Proposed (2026-07-21)
- **Decision owners:** Olympus maintainers
- **Security boundary:** BJJ authority acceptance and local signing-key activation
- **Builds on:**
  - `api/trusted_issuers.rs` — the existing multi-issuer trust set introduced for audit finding M-3.
  - ADR-0005 — canonical length-prefixed (`lp`) message framing.
  - ADR-0009 — Poseidon and Baby Jubjub EdDSA.
  - ADR-0031 — append-only transition attestations and reconstructable state.
  - ADR-0033 — checkpoint-quorum co-signatures. This ADR reuses the shape of domain-separated M-of-N verification, not the checkpoint message domain.
- **Supersedes:** The implicit policy that every entry in `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` is authorized for every BJJ-backed trust purpose.
- **Does not change:** Any ledger leaf or node hash, SMT proof, circuit, verification key, ceremony-manifest artifact format, credential signature domain, checkpoint signature domain, or snapshot-persistence signature domain.

## Context

Olympus currently resolves its BJJ issuer trust set once at process startup from the node bootstrap key and `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`. The resulting flat list is consumed by unrelated security domains, including SBT-backed scope resolution and ZK ceremony-manifest verification.

This creates four problems:

1. **Authority is not scoped by role.** Presence in one shared list implicitly authorizes a key for every consumer.
2. **Trust configuration has no list-level freshness.** A stale or replayed trust list can remain in use without a signed sequence, expiry, or predecessor binding.
3. **Rotation is neither authenticated nor reconstructable.** Operators edit environment variables and restart nodes without a signed, append-only transition record.
4. **The bootstrap exception prevents complete revocation.** A bootstrap key injected outside versioned trust state becomes a permanent parallel root.

The current design also conflates two different questions:

- **Read side:** which public keys this node accepts as authorized.
- **Write side:** which locally held private key this node uses for each signing purpose.

This ADR separates those concerns.

## Decision

Replace the unscoped startup trust list with a role-separated, signed, versioned trust-list state machine. The authoritative runtime trust state is derived from a validated snapshot and append-only transition history. Environment variables may supply one-time bootstrap material and local policy limits, but they do not remain an unaudited second trust database after genesis.

Local signer activation is implemented as a separate, purpose-typed subsystem with its own records and sequence space.

## 1. Trust-list snapshot

```rust
pub struct TrustListSnapshotV1 {
    pub format_version: u16,
    pub sequence: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub previous_snapshot_digest: Option<[u8; 32]>,
    pub active_roles: BTreeSet<TrustRole>,
    pub entries: Vec<TrustedIssuer>,
    pub rotation_policies: BTreeMap<TrustRole, RotationPolicy>,
    pub recovery_keys: BTreeMap<TrustRole, BabyJubJubPubKey>,
}

pub struct TrustedIssuer {
    pub pubkey: BabyJubJubPubKey,
    pub roles: BTreeSet<TrustRole>,
    pub valid_from: i64,
    pub valid_until: i64,
}

#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TrustRole {
    CredentialAuthority,
    RevocationAuthority,
    CheckpointAuthority,
    FederationAuthority,
    CeremonyCoordinator,
    RealmAuthority,
}
```

`RealmAuthority` is reserved for ADR-0042 and grants nothing until a consumer explicitly requests that role.

### Snapshot invariants

A valid snapshot must satisfy all of the following:

- `format_version == 1`.
- Genesis is the unique snapshot with `sequence == 1` and `previous_snapshot_digest == None`.
- Every later snapshot increments sequence by exactly one and names the digest of the immediately preceding accepted snapshot.
- `issued_at < expires_at`.
- Snapshot lifetime is within the operator-configured maximum.
- `active_roles` is canonically ordered and contains only defined protocol roles.
- Every issuer's `roles` set is non-empty.
- Entries and issuer-role sets are canonically ordered.
- Duplicate public keys merge only when all non-role metadata is identical; otherwise parsing fails as ambiguous.
- Public-key coordinates pass existing BJJ validation.
- `valid_from` and `valid_until` are mandatory.
- Each issuer satisfies:

```text
snapshot.issued_at <= issuer.valid_from < issuer.valid_until
issuer.valid_until <= snapshot.expires_at
```

- For every role in `active_roles`, at least one issuer contains that role and its validity window covers the snapshot's activation time.
- Every role in `active_roles` has exactly one rotation policy and one recovery key.
- Roles not in `active_roles` grant no runtime authority, even if an entry, policy, or recovery key for that role is present for staged migration purposes.
- A snapshot may not remove a role from `active_roles` implicitly; doing so is a governed change affecting that role and must satisfy its prior policy or recovery authorization.

The protocol enforces coverage only at snapshot activation boundaries and during trust decisions. It does not guarantee that a node possesses the private key for any authorized issuer, that an external signer is online, or that an authorized issuer will produce truthful statements.

Legacy environment entries may omit validity windows only as genesis-import input. Genesis tooling must materialize bounded values before producing the signed snapshot.

The canonical snapshot digest is:

```text
BLAKE3(
  "OLY:TRUST:SNAPSHOT:V1" ||
  canonical_snapshot_body
)
```

`canonical_snapshot_body` includes `active_roles`, role-scoped policies, recovery keys, and every issuer field. It uses one normative deterministic encoder with published test vectors. Default Serde JSON output is not itself a protocol encoding.

## 2. Role-scoped governance

```rust
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotationPolicyProfile {
    Production,
    LocalOnly,
}

pub struct RotationPolicy {
    pub profile: RotationPolicyProfile,
    pub signers: Vec<BabyJubJubPubKey>,
    pub threshold: u16,
}
```

`profile` is part of the signed canonical snapshot body. Policy validation is machine-checkable:

- signers are unique and canonically ordered;
- `1 <= threshold <= signers.len()`;
- `Production` requires `threshold >= 2`;
- `LocalOnly` may use `threshold == 1`;
- a production node rejects any active role governed by a `LocalOnly` policy unless the node itself is explicitly running the separately named local-only deployment mode;
- changing a policy profile is a governed change authorized by the prior policy.

The profile records the intended enforcement mode; it does not prove signer independence, separate custody, or that two listed public keys are controlled by different people or devices.

Each role has its own policy in `rotation_policies`. Two roles may intentionally use identical policies, but that is an explicit signed choice.

A routine transition is authorized under the relevant role policies in the **currently accepted** snapshot, never the candidate snapshot. A candidate therefore cannot lower its own threshold, replace its own signers, and self-authorize.

A transition modifying multiple roles must satisfy every affected role's prior policy.

## 3. Transition states and ordered activation

```rust
pub enum TrustTransitionState {
    Staged,
    Accepted,
    Active,
}
```

- **Staged:** Canonical encoding, signatures, role scope, and transition invariants have been validated. Staging is advisory and does not reserve a sequence slot.
- **Accepted:** The node has made a durable monotonic commitment to the transition.
- **Active:** The snapshot is currently effective for trust decisions.

Once a successor is Accepted, the node must not accept a conflicting successor for the same predecessor and sequence, even before the accepted snapshot becomes Active.

A successor may become Active only when:

1. its predecessor is the current Active snapshot;
2. its sequence is exactly the predecessor sequence plus one;
3. its `previous_snapshot_digest` matches the predecessor digest;
4. its `effective_at` is greater than or equal to the predecessor's `effective_at`;
5. the decision-time clock has reached `effective_at`; and
6. freshness, coverage, and authorization checks still pass at activation time.

Retroactive activation that would place a successor before its predecessor is rejected. The activation scheduler processes accepted successors strictly in sequence order and performs activation as one atomic state change. On restart, reconciliation loads the current Active snapshot, walks only the contiguous Accepted successor chain, and activates eligible snapshots in order. It fails closed on a gap, conflicting successor, decreasing `effective_at`, or an eligible successor whose predecessor is not Active.

A transition record distinguishes at least `validated_at`, `accepted_at`, and `effective_at`.

## 4. Freshness and rollback protection

Required production configuration:

```text
OLYMPUS_TRUST_LIST_MAX_AGE_SECS
OLYMPUS_TRUST_LIST_MAX_LIFETIME_SECS
```

An accepted snapshot must satisfy:

```text
now >= issued_at - permitted_clock_skew
now < expires_at
now - issued_at <= OLYMPUS_TRUST_LIST_MAX_AGE_SECS
expires_at - issued_at <= OLYMPUS_TRUST_LIST_MAX_LIFETIME_SECS
```

The node persists the highest accepted sequence, its digest, and enough transition metadata to reconstruct the accepted chain outside the replaceable trust-list file.

A snapshot is rejected when it:

- rolls back to an older sequence;
- presents a different digest at an already accepted sequence;
- skips a sequence without a complete validated chain;
- names the wrong predecessor digest;
- is expired or implausibly future-dated;
- violates role-coverage invariants;
- violates activation ordering;
- or lacks authorization under the previous accepted policy.

Development mode may relax missing freshness configuration or expiry of a locally generated development snapshot. It must not silently accept invalid signatures, malformed keys, predecessor mismatch, same-sequence equivocation, unauthorized role mutation, activation reordering, or canonicalization failure.

Rollback resistance in the initial implementation is relative to the integrity and persistence of the local accepted-state store. This ADR does **not** claim resistance to rollback of an entire machine or VM snapshot together with every local state store. Strong rollback resistance across that boundary requires an external anchor, TPM-backed monotonic counter, remote witness, or equivalent mechanism.

This ADR does not change the current ceremony-manifest timestamp semantics. A future manifest-format change must sign the artifact timestamp before issuer validity can safely be evaluated against that timestamp rather than the decision-time clock.

## 5. Quorum domain separation

The shared verification loop is extracted without allowing callers to pass untyped raw field elements.

```rust
pub(crate) struct QuorumMessage(Fr);

fn verify_generic_quorum(
    message: &QuorumMessage,
    signers: &[QuorumSigner],
    threshold: usize,
    sigs: &[CollectedSignature],
) -> QuorumStatus;
```

Only domain-specific constructors may create a `QuorumMessage`.

Routine trust rotation binds the complete transition:

```rust
pub fn trust_rotation_message(
    previous_snapshot_digest: &[u8; 32],
    next_snapshot_digest: &[u8; 32],
    previous_sequence: u64,
    next_sequence: u64,
    effective_at: i64,
) -> QuorumMessage;
```

Its canonical message is:

```text
OLY:TRUST:ROTATE:V1 ||
  lp(previous_snapshot_digest) ||
  lp(next_snapshot_digest) ||
  lp(previous_sequence_be64) ||
  lp(next_sequence_be64) ||
  lp(effective_at_be64)
```

Recovery uses a separate constructor and domain:

```text
OLY:TRUST:RECOVER:V1 ||
  lp(role) ||
  lp(previous_snapshot_digest) ||
  lp(recovery_snapshot_digest) ||
  lp(previous_sequence_be64) ||
  lp(next_sequence_be64) ||
  lp(reason_code) ||
  lp(effective_at_be64)
```

`verify_quorum`, `verify_checkpoint_quorum`, and trust-rotation verification become thin wrappers over the shared normalize/deduplicate/verify/count/threshold core. Existing SBT and checkpoint message construction and behavior remain unchanged and require regression coverage.

## 6. Append-only transition records

Each transition candidate persists as an insert-only record containing at least:

- previous and next sequence;
- previous and next digest;
- canonical next-snapshot bytes or a durable reference;
- transition type;
- transition state;
- validation, acceptance, and effective times;
- authorization thresholds, profiles, and signer sets;
- submitted signatures and valid signer identities;
- verification result;
- and, for recovery, the reason code.

```rust
pub enum TrustTransitionKind {
    Genesis,
    Rotation,
    Recovery,
}
```

Staged candidates do not reserve protocol sequence numbers. Multiple Staged candidates may exist for one predecessor and proposed `next_sequence`; they are identified by candidate ID and digest and may be discarded or superseded before acceptance.

The database enforces successor uniqueness only once a candidate reaches `Accepted` or `Active`, using equivalent partial unique constraints for:

- `next_sequence`;
- `next_snapshot_digest`; and
- `(previous_snapshot_digest, next_sequence)`.

The transition from Staged to Accepted must atomically acquire those constraints and update the monotonic accepted-state marker. If another candidate already owns the successor slot, acceptance fails and the losing candidate remains Staged or is marked rejected. Accepted and Active rows are immutable. Corrections are represented by later transitions, never updates or deletes.

This requires a forward database migration. It does not alter ledger hashes, SMT state, circuits, or verification keys.

## 7. Offline recovery

Each role has one pinned offline recovery key that is not a member of that role's routine quorum.

A recovery transition must:

- reference the currently accepted snapshot;
- increment sequence by exactly one;
- produce a complete replacement snapshot;
- be signed by the recovery key pinned for the affected role;
- install a new routine policy or primary authority for that role;
- and rotate the recovery key when operationally possible.

A role-specific recovery key may modify only the recovering role's effective content. For a snapshot `S` and role `r`, define the canonical per-role projection:

```text
project(S, r) = canonical_encode(
  r in S.active_roles,
  sorted [(issuer.pubkey, issuer.valid_from, issuer.valid_until)
          for issuer in S.entries where r in issuer.roles],
  S.rotation_policies.get(r),
  S.recovery_keys.get(r)
)
```

For every unrelated role `u`, recovery requires:

```text
project(previous_snapshot, u) == project(recovery_snapshot, u)
```

This semantic projection permits a shared `TrustedIssuer` entry's role set to change for the recovering role without falsely treating an unrelated role as modified. Implementations must compare the canonical projections, not serialized whole-entry bytes.

The only global envelope fields permitted to change during role-scoped recovery are:

- `sequence`, which must increase by exactly one;
- `previous_snapshot_digest`, which must become the current accepted digest;
- `issued_at` and `expires_at`, subject to normal freshness and lifetime bounds;
- and transition metadata such as `effective_at`, which remains outside the snapshot body and must obey ordered activation.

`format_version` must remain unchanged for a V1 recovery. All other snapshot content is governed through the per-role projections above. A transition affecting multiple roles requires valid recovery authorization for every affected role or authorization through the relevant routine policies.

```rust
pub enum RecoveryReason {
    QuorumCompromise,
    QuorumUnavailable,
    KeyLoss,
    EmergencyRevocation,
    OperatorDirectedTest,
}
```

Recovery must not depend on the Axum server being available. Genesis import, recovery, reconstruction, and acceptance of a signed recovery file ship as pre-server CLI paths.

Compromise of enough routine quorum keys to meet a role's threshold can authorize a malicious transition before recovery occurs. Expiry, monitoring, and offline recovery may bound damage; they do not prevent threshold compromise.

## 8. Genesis authorization boundary

Genesis is not a rotation because no previous snapshot exists, but production genesis is still a domain-separated, threshold-authorized operation.

```rust
pub struct GenesisApprovalPolicy {
    pub profile: RotationPolicyProfile,
    pub signers: Vec<BabyJubJubPubKey>,
    pub threshold: u16,
}
```

The approval policy is supplied explicitly to `node-admin init-genesis`, canonically encoded, displayed with the snapshot digest for operator confirmation, and persisted with the genesis record. Its signer set is unique and canonically ordered. `1 <= threshold <= signers.len()`; `Production` requires `threshold >= 2`, while `LocalOnly` may use threshold `1`. Production mode rejects a `LocalOnly` genesis approval policy.

The exact canonical approval message is:

```text
OLY:TRUST:GENESIS:V1 ||
  lp(snapshot_digest) ||
  lp(canonical_snapshot_body) ||
  lp(canonical_genesis_approval_policy)
```

`canonical_snapshot_body` is the complete body used by `OLY:TRUST:SNAPSHOT:V1`, including sequence, validity bounds, `active_roles`, issuer entries, role policies, and recovery keys. The verifier recomputes `snapshot_digest` from those same bytes and rejects any mismatch before checking approvals. Every bootstrap signature must verify against this exact `OLY:TRUST:GENESIS:V1` message; signatures over a digest alone, another encoding, another policy, or another genesis payload are invalid. Duplicate signatures from one signer count once, signatures from keys outside the approval signer set do not count, and acceptance requires the configured threshold.

Authoritative genesis additionally requires:

1. Explicit CLI invocation, for example `node-admin init-genesis`.
2. Exclusive database access.
3. Demonstrable absence of any prior Accepted state.
4. Operator confirmation of the snapshot digest and approval-policy digest.
5. Successful verification of the approval threshold in production.

The current primary key and `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` may be consumed once as genesis-import material. After genesis is accepted:

- the signed snapshot and transition chain are authoritative;
- startup does not re-add the bootstrap key;
- legacy environment entries do not expand the trust set;
- and changing legacy environment variables does not mutate accepted state.

Compatibility import must be explicitly enabled, must warn prominently, becomes unavailable once persistent genesis exists, and is prohibited for the production Phase-2 ceremony.

## 9. Runtime trust API

Callers stop scanning a raw `Vec<TrustedIssuer>`.

```rust
pub trait TrustResolver {
    fn issuer_is_active_for(
        &self,
        pubkey: &BabyJubJubPubKey,
        role: TrustRole,
        at: i64,
    ) -> bool;

    fn active_issuers_for(
        &self,
        role: TrustRole,
        at: i64,
    ) -> Vec<&TrustedIssuer>;

    fn snapshot_sequence(&self) -> u64;
    fn snapshot_digest(&self) -> [u8; 32];
}
```

`at` is the decision-time clock unless a consumer's artifact format cryptographically binds its own timestamp. Unsigned artifact timestamps must not be supplied as trust-decision time.

## 10. Local signer activation

The trust list defines **who is authorized**. The signer subsystem defines **which authorized private key this node currently uses**.

Signer activation is not a `TrustTransitionKind` and does not share the trust-transition sequence space.

```rust
pub enum SigningPurpose {
    CredentialIssuance,
    Revocation,
    CheckpointSigning,
    FederationCosigning,
}

impl SigningPurpose {
    pub fn required_trust_role(self) -> TrustRole {
        match self {
            SigningPurpose::CredentialIssuance => TrustRole::CredentialAuthority,
            SigningPurpose::Revocation => TrustRole::RevocationAuthority,
            SigningPurpose::CheckpointSigning => TrustRole::CheckpointAuthority,
            SigningPurpose::FederationCosigning => TrustRole::FederationAuthority,
        }
    }
}

pub struct SignerActivationRecord {
    pub sequence: u64,
    pub purpose: SigningPurpose,
    pub previous_pubkey: Option<BabyJubJubPubKey>,
    pub next_pubkey: BabyJubJubPubKey,
    pub trust_snapshot_sequence: u64,
    pub trust_snapshot_digest: [u8; 32],
    pub activated_at: i64,
}

pub struct ActiveSigners {
    pub credential_issuer: ArcSwapOption<SigningIdentity>,
    pub revocation_signer: ArcSwapOption<SigningIdentity>,
    pub checkpoint_signer: ArcSwapOption<SigningIdentity>,
    pub federation_cosigner: ArcSwapOption<SigningIdentity>,
}
```

A signer activation is valid only when the record's `trust_snapshot_sequence` and `trust_snapshot_digest` identify the snapshot that is **Active and effective at `activated_at`**. An Accepted historical or future snapshot is insufficient.

Validation proceeds as follows:

1. Read the current effective trust snapshot for `activated_at`.
2. Require its sequence and digest to equal the record's referenced sequence and digest.
3. Require `next_pubkey` to be active for `purpose.required_trust_role()` at `activated_at` in that snapshot.
4. Immediately before committing the signer-activation row and swapping the in-memory signer, atomically re-read or lock the effective trust-state marker.
5. Reject the activation if the effective sequence or digest changed, if the key is no longer authorized, or if `activated_at` no longer falls under that effective snapshot.
6. Commit the append-only activation record and update the purpose-specific active signer in the same transaction or equivalent compare-and-swap boundary.

This prevents reactivating a revoked key by referencing an older accepted snapshot and closes the race where a trust rotation becomes Active between initial validation and signer activation.

One identity may initially populate all four slots to reproduce current behavior. The architecture nevertheless preserves purpose separation so future roles can use different custody models, including HSM-backed and disk-backed identities.

Signer-activation records are append-only, independently sequenced, and auditable.

## 11. Failure behavior and observability

Production fails closed with exit code `2` on:

- missing required trust policy;
- expired or excessively old snapshots;
- rollback, gaps, predecessor mismatch, or activation-order violations;
- same-sequence equivocation;
- malformed or ambiguous entries;
- invalid role policies or policy profiles;
- insufficient valid signatures;
- unauthorized role mutation;
- invalid recovery scope;
- invalid genesis approval;
- canonicalization disagreement;
- role-coverage failure;
- stale signer-activation references;
- or inability to read persisted monotonic state.

Logs identify stable reason codes, the rejected sequence, transition kind, previous and candidate digests, required and valid signature counts, and affected roles. They must not expose private keys, secret configuration, or credentials.

Metrics should expose the active sequence, seconds until expiry, last accepted transition time, rejected-transition count by reason, and whether staged or accepted successors exist.

## Security invariants

1. Trust for one role never implies trust for another.
2. A key holds multiple roles only when signed state explicitly says so.
3. No startup-only key bypasses the accepted snapshot.
4. Routine transitions are authorized under prior role policies.
5. Signatures bind the complete predecessor-to-successor transition.
6. Accepted sequence numbers increase by exactly one.
7. Every non-genesis snapshot commits to its predecessor.
8. A node rejects state older than its persisted accepted state.
9. Conflicting Accepted snapshots at one sequence fail closed; Staged candidates do not reserve that sequence.
10. Active snapshots advance only from the current Active predecessor with nondecreasing effective time.
11. Expired or excessively old policy cannot remain trusted indefinitely.
12. Routine quorum members alone cannot invoke recovery.
13. A role's recovery key cannot modify another role's canonical effective projection.
14. Current trust state reconstructs from immutable accepted transitions.
15. Every conforming implementation computes identical digests and approval messages.
16. Existing credentials keep their original signature meaning; this ADR changes only whether an issuer is currently accepted for a role.
17. Local signer activation is independently auditable and may use only a key recognized by the current effective trust snapshot.

## Threat model

This ADR protects against stale trust configuration, replay of older trust lists, accidental cross-role key use, unauthorized below-threshold changes, partial or reordered updates, out-of-order activation, loss of a routine quorum, replay of genesis approvals onto another payload, reactivation of locally revoked signing keys through historical snapshots, and untraceable manual trust edits.

It does not protect against compromise of enough quorum keys to meet a configured threshold, simultaneous compromise of a role's routine quorum and recovery key, malicious software bypassing verification, rollback of all local and external monotonic anchors, unsafe operator policy, multiple signer entries controlled by one adversary, unavailable authorized private keys, or false claims signed by an otherwise authorized issuer.

A valid trust-list decision proves only that Olympus accepted an issuer for a stated role under the configured policy and recorded transition history. It does not prove that the issuer's underlying assertions are true, that listed signers are independently controlled, or that an authorized signer is available.

## Alternatives considered

- **Keep one shared flat issuer list:** Rejected; it preserves implicit cross-role authority and has no authenticated history.
- **Use separate environment variables per role:** Insufficient; it adds role separation but not freshness, rollback resistance, quorum authorization, or auditability.
- **Use per-entry expiration only:** Insufficient; it cannot prove that the list itself is current.
- **Sign individual add/remove operations:** Rejected; partial operations create ordering, omission, and crash-consistency hazards.
- **Let the candidate policy authorize itself:** Rejected; a candidate could lower its own threshold and self-validate.
- **Use the routine quorum as recovery:** Rejected; recovery must remain useful when the routine quorum is compromised or unavailable.
- **Depend on a central online trust-list service:** Rejected as the sole mechanism; distribution may be centralized for convenience, but acceptance remains local and cryptographic.

## Consequences

### Positive

- Credential, revocation, checkpoint, federation, ceremony, and future realm authority become explicitly separated.
- Unified keys remain supported only through explicit signed role assignments.
- Trust updates become atomic, authenticated, monotonic, and reconstructable.
- Nodes detect stale, rolled-back, equivocated, and out-of-order state.
- Routine rotation and catastrophic recovery use structurally separate keys.
- Genesis approvals bind the complete genesis payload and approval policy.
- Local signing-key activation gains purpose separation, current-state binding, and auditability.
- Existing credential, checkpoint, circuit, and SMT formats remain unchanged.

### Costs and risks

- Production gains real key-management and expiry responsibilities.
- Incorrect clock or lifetime configuration can prevent startup.
- Nodes must protect a monotonic accepted-state marker.
- Recovery-key custody requires a documented offline process.
- Canonical encoding becomes a security-critical protocol surface.
- Partial unique constraints and activation reconciliation require careful transactional implementation.
- Legacy migration and pre-server recovery tooling require care.
- The shared quorum-verifier extraction touches existing call sites and requires behavior-preservation tests.

## Implementation plan

1. Introduce `TrustRole`, `RotationPolicyProfile`, snapshot, policy, transition, and recovery types.
2. Implement canonical snapshot, per-role projection, genesis approval, and transition encoders with cross-platform test vectors.
3. Extract the shared typed quorum-verification core and preserve existing SBT/checkpoint behavior.
4. Add trust-rotation, recovery, and genesis message constructors and verifiers.
5. Implement the role-aware `TrustResolver` API.
6. Update credential and ceremony consumers to request explicit roles.
7. Implement the genesis authorization boundary and legacy import.
8. Add persistent accepted-state, partial successor-uniqueness constraints, and append-only transition tables.
9. Implement role-scoped offline recovery and pre-server CLI paths.
10. Remove unconditional bootstrap-key injection after genesis.
11. Add startup freshness, rollback, coverage, policy-profile, and equivocation checks.
12. Add an ordered activation scheduler and startup reconciliation that atomically promote contiguous Accepted snapshots at `effective_at`.
13. Implement purpose-typed `ActiveSigners` and append-only signer-activation records with atomic effective-state rechecks.
14. Add CLI commands to inspect, stage, sign, verify, accept, activate, reconstruct, recover, and initialize genesis.
15. Document rotation, expiry monitoring, backups, recovery custody, and disaster recovery.
16. Exercise one routine rotation, stale-node rejection, ordered activation, signer activation, reconstruction, and recovery dry run before production ceremony use.
17. Deprecate the legacy flat issuer environment variable after migration tooling is proven.

## Required validation

Tests must cover at least:

- explicit multi-role keys and wrong-role rejection;
- signed active-role membership and coverage;
- mandatory issuer bounds;
- production and local-only policy profiles, including rejection of threshold `1` under production;
- expired, old, and future-dated snapshots;
- rollback, skipped sequence, wrong predecessor, and same-sequence equivocation;
- multiple Staged candidates without sequence reservation and atomic acceptance conflict handling;
- duplicate and conflicting issuer entries;
- duplicate quorum signatures and threshold boundaries;
- candidate-policy self-authorization attempts;
- atomic multi-role transitions;
- delayed activation, decreasing-effective-time rejection, predecessor-active enforcement, and restart reconciliation;
- stale-node rejection;
- recovery replay, wrong predecessor, unrelated-role projection preservation, and shared-entry role removal;
- trust-state reconstruction;
- canonical digest and genesis approval-message stability across platforms;
- genesis approval replay rejection for changed snapshot bodies, digests, signer sets, profiles, or thresholds;
- legacy genesis import followed by bootstrap-key removal;
- active-signer rejection for unrecognized keys and historical accepted snapshots;
- atomic rejection when effective trust state changes during signer activation;
- independent signer-purpose activation;
- and regression tests proving the extracted generic verifier preserves existing SBT and checkpoint behavior.

## Rollout gate

ADR-0041 must be implemented, documented, and operationally exercised before:

- ADR-0042 relies on `RealmAuthority`;
- the production multi-contributor Phase-2 ceremony makes coordinator trust load-bearing across consumer nodes;
- or Olympus represents trust-list rotation as recoverable and rollback-resistant.

Until then, the current mechanism remains manually distributed startup configuration, not a complete trust-management protocol.
