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
- `roles` is non-empty.
- Entries and roles are canonically ordered.
- Duplicate public keys merge only when all non-role metadata is identical; otherwise parsing fails as ambiguous.
- Public-key coordinates pass existing BJJ validation.
- `valid_from` and `valid_until` are mandatory.
- Each issuer satisfies:

```text
snapshot.issued_at <= issuer.valid_from < issuer.valid_until
issuer.valid_until <= snapshot.expires_at
```

- At every activation boundary, each production-active role retains at least one issuer whose validity window covers the activation time.
- Each production-active role has a rotation policy and recovery key.
- Production rotation policies require `threshold >= 2`. A distinct, explicitly named `local_only` profile may permit threshold `1` for genuinely single-operator deployments.

Legacy environment entries may omit validity windows only as genesis-import input. Genesis tooling must materialize bounded values before producing the signed snapshot.

The canonical snapshot digest is:

```text
BLAKE3(
  "OLY:TRUST:SNAPSHOT:V1" ||
  canonical_snapshot_body
)
```

`canonical_snapshot_body` uses one normative deterministic encoder with published test vectors. Default Serde JSON output is not itself a protocol encoding.

## 2. Role-scoped governance

```rust
pub struct RotationPolicy {
    pub signers: Vec<BabyJubJubPubKey>,
    pub threshold: u16,
}
```

Each role has its own policy in `rotation_policies`. Two roles may intentionally use identical policies, but that is an explicit signed choice.

A routine transition is authorized under the relevant role policies in the **currently accepted** snapshot, never the candidate snapshot. A candidate therefore cannot lower its own threshold, replace its own signers, and self-authorize.

A transition modifying multiple roles must satisfy every affected role's prior policy.

## 3. Transition states

```rust
pub enum TrustTransitionState {
    Staged,
    Accepted,
    Active,
}
```

- **Staged:** Canonical encoding, signatures, role scope, and transition invariants have been validated.
- **Accepted:** The node has made a durable monotonic commitment to the transition.
- **Active:** The snapshot is currently effective for trust decisions.

Once a successor is Accepted, the node must not accept a conflicting successor for the same predecessor and sequence, even before the accepted snapshot becomes Active.

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
- or lacks authorization under the previous accepted policy.

Development mode may relax missing freshness configuration or expiry of a locally generated development snapshot. It must not silently accept invalid signatures, malformed keys, predecessor mismatch, same-sequence equivocation, unauthorized role mutation, or canonicalization failure.

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

Each accepted transition persists as an insert-only record containing at least:

- previous and next sequence;
- previous and next digest;
- canonical next-snapshot bytes or a durable reference;
- transition type;
- transition state;
- validation, acceptance, and effective times;
- authorization thresholds and signer sets;
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

The database enforces uniqueness for `next_sequence`, `next_snapshot_digest`, and `(previous_snapshot_digest, next_sequence)`. Accepted rows are immutable. Corrections are represented by later transitions, never updates or deletes.

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

A role-specific recovery key may modify only that role's issuer entries, rotation policy, and recovery key. Global envelope fields may change only as required to produce a valid contiguous next snapshot. All unrelated role-controlled content must remain byte-equivalent to the prior snapshot.

A transition affecting multiple roles requires valid recovery authorization for every affected role or authorization through the relevant routine policies.

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

Genesis is not a quorum transition because no previous snapshot exists.

Authoritative genesis requires:

1. Explicit CLI invocation, for example `node-admin init-genesis`.
2. Exclusive database access.
3. Demonstrable absence of any prior Accepted state.
4. Operator confirmation of the resulting snapshot digest.
5. In production, bootstrap signatures from configured offline operator approval keys.

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

A signer may be activated only when its public key is active for the purpose's required role in the referenced accepted trust snapshot.

One identity may initially populate all four slots to reproduce current behavior. The architecture nevertheless preserves purpose separation so future roles can use different custody models, including HSM-backed and disk-backed identities.

Signer-activation records are append-only, independently sequenced, and auditable.

## 11. Failure behavior and observability

Production fails closed with exit code `2` on:

- missing required trust policy;
- expired or excessively old snapshots;
- rollback, gaps, or predecessor mismatch;
- same-sequence equivocation;
- malformed or ambiguous entries;
- invalid role policies;
- insufficient valid signatures;
- unauthorized role mutation;
- invalid recovery scope;
- canonicalization disagreement;
- role-coverage failure;
- or inability to read persisted monotonic state.

Logs identify stable reason codes, the rejected sequence, transition kind, previous and candidate digests, required and valid signature counts, and affected roles. They must not expose private keys, secret configuration, or credentials.

Metrics should expose the active sequence, seconds until expiry, last accepted transition time, rejected-transition count by reason, and whether a staged or accepted successor exists.

## Security invariants

1. Trust for one role never implies trust for another.
2. A key holds multiple roles only when signed state explicitly says so.
3. No startup-only key bypasses the accepted snapshot.
4. Routine transitions are authorized under prior role policies.
5. Signatures bind the complete predecessor-to-successor transition.
6. Accepted sequence numbers increase by exactly one.
7. Every non-genesis snapshot commits to its predecessor.
8. A node rejects state older than its persisted accepted state.
9. Conflicting snapshots at one sequence fail closed.
10. Expired or excessively old policy cannot remain trusted indefinitely.
11. Routine quorum members alone cannot invoke recovery.
12. A role's recovery key cannot modify unrelated roles.
13. Current trust state reconstructs from immutable accepted transitions.
14. Every conforming implementation computes identical digests.
15. Existing credentials keep their original signature meaning; this ADR changes only whether an issuer is currently accepted for a role.
16. Local signer activation is independently auditable and may use only a key recognized by the referenced accepted trust snapshot.

## Threat model

This ADR protects against stale trust configuration, replay of older trust lists, accidental cross-role key use, unauthorized below-threshold changes, partial or reordered updates, loss of a routine quorum, and untraceable manual trust edits.

It does not protect against compromise of enough quorum keys to meet a configured threshold, simultaneous compromise of a role's routine quorum and recovery key, malicious software bypassing verification, rollback of all local and external monotonic anchors, unsafe operator policy, or false claims signed by an otherwise authorized issuer.

A valid trust-list decision proves only that Olympus accepted an issuer for a stated role under the configured policy and recorded transition history. It does not prove that the issuer's underlying assertions are true.

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
- Nodes detect stale, rolled-back, and equivocated state.
- Routine rotation and catastrophic recovery use structurally separate keys.
- Local signing-key activation gains purpose separation and auditability.
- Existing credential, checkpoint, circuit, and SMT formats remain unchanged.

### Costs and risks

- Production gains real key-management and expiry responsibilities.
- Incorrect clock or lifetime configuration can prevent startup.
- Nodes must protect a monotonic accepted-state marker.
- Recovery-key custody requires a documented offline process.
- Canonical encoding becomes a security-critical protocol surface.
- Legacy migration and pre-server recovery tooling require care.
- The shared quorum-verifier extraction touches existing call sites and requires behavior-preservation tests.

## Implementation plan

1. Introduce `TrustRole`, snapshot, policy, transition, and recovery types.
2. Implement canonical snapshot and transition encoders with cross-platform test vectors.
3. Extract the shared typed quorum-verification core and preserve existing SBT/checkpoint behavior.
4. Add trust-rotation and recovery message constructors and verifiers.
5. Implement the role-aware `TrustResolver` API.
6. Update credential and ceremony consumers to request explicit roles.
7. Implement the genesis authorization boundary and legacy import.
8. Add persistent accepted-state and append-only transition tables.
9. Implement role-scoped offline recovery and pre-server CLI paths.
10. Remove unconditional bootstrap-key injection after genesis.
11. Add startup freshness, rollback, coverage, and equivocation checks.
12. Add an activation scheduler and startup reconciliation that atomically promote Accepted snapshots at `effective_at`.
13. Implement purpose-typed `ActiveSigners` and append-only signer-activation records.
14. Add CLI commands to inspect, stage, sign, verify, accept, activate, reconstruct, recover, and initialize genesis.
15. Document rotation, expiry monitoring, backups, recovery custody, and disaster recovery.
16. Exercise one routine rotation, stale-node rejection, signer activation, reconstruction, and recovery dry run before production ceremony use.
17. Deprecate the legacy flat issuer environment variable after migration tooling is proven.

## Required validation

Tests must cover at least:

- explicit multi-role keys and wrong-role rejection;
- mandatory issuer bounds and role coverage;
- expired, old, and future-dated snapshots;
- rollback, skipped sequence, wrong predecessor, and same-sequence equivocation;
- duplicate and conflicting issuer entries;
- duplicate quorum signatures and threshold boundaries;
- the production threshold floor;
- candidate-policy self-authorization attempts;
- atomic multi-role transitions;
- delayed activation and restart reconciliation;
- stale-node rejection;
- recovery replay, wrong predecessor, and unrelated-role modification;
- trust-state reconstruction;
- canonical digest stability across platforms;
- legacy genesis import followed by bootstrap-key removal;
- active-signer rejection for unrecognized keys;
- independent signer-purpose activation;
- and regression tests proving the extracted generic verifier preserves existing SBT and checkpoint behavior.

## Rollout gate

ADR-0041 must be implemented, documented, and operationally exercised before:

- ADR-0042 relies on `RealmAuthority`;
- the production multi-contributor Phase-2 ceremony makes coordinator trust load-bearing across consumer nodes;
- or Olympus represents trust-list rotation as recoverable and rollback-resistant.

Until then, the current mechanism remains manually distributed startup configuration, not a complete trust-management protocol.
