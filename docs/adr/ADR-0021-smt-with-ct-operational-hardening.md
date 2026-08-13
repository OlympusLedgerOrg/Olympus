# ADR-0021: CD-HS-ST with CT-style operational hardening

- **Status:** Accepted; implemented — 2026-08-13. Of the four operational
  controls this ADR named, two were built under later ADRs and are complete:
  **witness cosigning** (ADR-0032/ADR-0033, `src-tauri/src/quorum/checkpoint.rs`)
  and **gossip/equivocation detection** (`src-tauri/src/federation/gossip.rs`,
  `equivocation.rs`, over the Tor transport — no longer in-memory doubles).
  The remaining two, **Monitor API** and **Maximum Merge Delay (MMD)**, are
  implemented by this revision: `src-tauri/src/api/monitor/` (`GET
  /monitor/checkpoints`, `/monitor/checkpoints/latest`, `/monitor/proof/{content_hash}`,
  `/monitor/mmd/{content_hash}`) and `src-tauri/src/mmd.rs`
  (`OLYMPUS_MMD_SECONDS`). See "Implementation status" below for what these
  do and do not cover — in particular, the tree the Monitor API's proof
  endpoint serves inclusion witnesses against.
- **Date:** 2026-05-10 (scaffold); 2026-08-13 (implementation)
- **Reference discussion:** Olympus architecture chat, 2026-05-10

## Context

Olympus needs keyed inclusion and non-inclusion proofs for press-freedom records while also making operational equivocation (split-view behavior) publicly detectable. The existing CD-HS-ST (single global sparse Merkle tree keyed by `H(GLOBAL_KEY_PREFIX || shard_id || record_key)`) is the cryptographic source of truth.

The missing deployment hardening is CT-grade operational practice around signed roots: witness cosigning, gossip comparisons, monitor APIs, and a maximum merge delay (MMD) policy.

## Decision

Keep the **SMT (CD-HS-ST)** as the only ledger commitment tree and add **RFC-6962-inspired operational controls** around signed roots.

**Implementation note (2026-08-13):** the operational controls this decision
calls for — signed roots, witness cosigning, gossip, the Monitor API, MMD —
ended up implemented against a **second tree**, the Poseidon ledger-snapshot
tree, not the CD-HS-ST SMT this section names. See "Known limitation" below
for the full explanation and why that gap was not closed in this revision.

### Why SMT over an RFC-6962 history tree

- **Non-inclusion proofs are first-class** (critical for proving keyed absence vs hidden records).
- **Keyed lookups are native** (`shard_id + record_key`), unlike index-based history trees.
- **Mutable-but-tamper-evident state** maps directly to keyed sparse tree updates.
- **Proof size remains fixed-depth** for a 256-level sparse tree.

### Why adopt CT operational practices anyway

- **Witness cosigning:** independent parties co-sign roots to reduce single-operator trust.
- **Gossip:** independent monitors compare envelopes and detect split-view evidence.
- **Maximum Merge Delay (MMD):** a policy on how quickly a submitted record must
  appear in a published, signed checkpoint, with a way to check whether that
  held for a given record. (Implemented as a server-reported classification,
  not non-repudiable proof — see "Implementation status" below.)
- **Monitor API:** public read-only surfaces for root/proof/evidence verification.

## Explicit non-goals

- ❌ No parallel RFC-6962 history tree.
- ❌ No RFC-6962 `consistency_proof` endpoint — the SMT-native equivalent
  below covers the same property.
- ❌ No production witness onboarding *ceremony* (the M-of-N mechanism itself
  — ADR-0033 — is implemented and live; the operational process of vetting
  and onboarding real independent institutions as witnesses is a governance
  activity, not a code deliverable).

## Implementation status

### Witness cosigning and gossip — done, under other ADRs

These are no longer scaffolds. Don't re-implement them here:

- **Witness cosigning** is `OLY:CHECKPOINT:QUORUM:V2` (ADR-0033), reusing the
  SBT-quorum M-of-N primitive under a checkpoint-root domain tag. Live in
  `src-tauri/src/quorum/checkpoint.rs`; collected via
  `federation::cosign::collect_cosignatures` over the Tor peer protocol.
  ADR-0032 explains why this reused the SBT-quorum primitive instead of a
  parallel witness-specific scheme.
- **Gossip** is a real Tor hidden-service transport (`federation::tor`,
  `federation::gossip`), not the in-memory doubles this ADR originally
  scoped down to. `federation::equivocation::check_and_flag` detects a
  signing identity publishing two different roots at the same
  `checkpoint_timestamp` or `tree_size`, inside the same transaction that
  stores the incoming peer checkpoint (closing the detect-then-store race
  the module's own doc comments describe). See `docs/federation.md`.

### Monitor API and MMD — implemented by this revision

`src-tauri/src/api/monitor/` (doc comment there is authoritative for route
shapes):

- `GET /monitor/checkpoints` / `GET /monitor/checkpoints/latest` — recent /
  latest signed `own_checkpoints` rows for a shard: the "get-sth" /
  "get-sth-history" surfaces. Every field a caller needs to independently
  recompute `checkpoint_signing_message_v2` / `checkpoint_anchor_hash_v2`
  and check the BJJ/Ed25519 signatures is included; nothing here asks the
  caller to trust this server's own verdict.
- `GET /monitor/proof/{content_hash}` — the "get-proof-by-hash" surface: the
  raw, stored Poseidon ledger-snapshot inclusion witness for a committed
  record (path elements, direction bits, BJJ signature, optional signed
  timestamp), reusing exactly the parse/lookup `POST /ingest/proofs/verify`
  already used server-side (`src-tauri/src/api/ingest/snapshot_evidence.rs`)
  so the two can never disagree about what a stored witness means.
- `GET /monitor/mmd/{content_hash}` — MMD status: how long after ingest a
  record's first covering signed checkpoint appeared (or, if none exists
  yet, how long it has been waiting), classified against the
  `OLYMPUS_MMD_SECONDS` policy (`src-tauri/src/mmd.rs`, default 24 h) as one
  of `covered_within_policy` / `covered_late_breach` /
  `pending_within_policy` / `pending_breach` (the latter two of those four
  are the breach states — `pending_within_policy` is explicitly not one).
  **Only half of this is independently verifiable**: the covering
  checkpoint is a signed, offline-checkable `own_checkpoints` row, but the
  ingest timestamp it's measured against (`ingest_records.ts`) is an
  unsigned server-clock column with no cryptographic receipt. This endpoint
  is a server-reported policy classification a submitter or a monitor can
  use as a diagnostic and audit signal, not a non-repudiable proof they can
  hand to a third party — see the module's own doc comment
  (`src-tauri/src/api/monitor/mmd.rs`) for the full reasoning. Closing that
  gap would need an authenticated submission receipt issued at ingest time
  (an RFC-6962-style SCT), which this revision does not add.

All three routes are unauthenticated (rate-limited only) and mounted on both
the default loopback listener and, when the `federation` feature is
compiled, the Tor-facing listener — a Monitor API only a local process can
reach defeats the point.

### Known limitation: which tree the proof endpoint covers

Olympus has **two** Merkle structures in play, and only one is signed today:

1. The **BLAKE3 CD-HS-ST SMT** (`crate::smt::tree::PersistentSmt`, depth
   256) this ADR's Decision section names as "the only ledger commitment
   tree" — the parser-bound, shard-keyed structure ADR-0003/0004/0005
   describe, written by every `/ingest/files` commit
   (`smt::tree::update_batch_inner`'s write-once guard).
2. The **Poseidon ledger-snapshot tree** (`olympus_crypto::ledger_snapshot`,
   depth 20), a separate ZK-circuit-sized structure frozen per record at
   ingest time (`ingest_records.snapshot_*`, migration 0029) specifically so
   a `document_existence` Groth16 witness stays small.

`own_checkpoints.ledger_root` — the value this ADR's "signed roots" and
"witness cosigning" all sign — is the **Poseidon snapshot root**, not the
BLAKE3 SMT root. `PersistentSmt::prove` (the BLAKE3 tree's own inclusion-proof
method) has no production caller anywhere in this codebase and nothing signs
or externally anchors its output. `GET /monitor/proof` therefore serves the
Poseidon snapshot witness — the tree that is actually checkpointed, signed,
and (via `OLYMPUS_ANCHOR_*`) externally anchored — not the BLAKE3 SMT.

This was an honest scope boundary, not an oversight: a proof against an
unsigned root would have no signed statement for a monitor to check it
against, which would misrepresent what this API can actually establish.
ADR-0044 (merged after this revision) closes the "signing both" half: every
own-checkpoint emitted with the BJJ authority private key loaded now also
BJJ-signs the BLAKE3 CD-HS-ST SMT's per-shard subtree root
(`olympus_crypto::SmtRootAttestation`, domain `OLY:SMT:ROOT:V1`), jointly
bound to the same `(ledger_root, tree_size)` the Poseidon side signs — see
its "What this does not do (yet)" section. That does not by itself change
what `GET /monitor/proof` serves: reconciling which tree is "the" canonical
commitment, or wiring this endpoint to serve BLAKE3 witnesses now that a
signed root exists to check them against, remains open follow-up work.

## SMT-native equivalent of CT consistency checks

Olympus does **not** implement RFC-6962 prefix consistency proofs. The SMT-native equivalent is:

1. Retrieve two signed roots (`old_root`, `new_root`).
2. Re-check inclusion/non-inclusion proofs against each root as needed.
3. Detect contradiction/equivocation via signed conflicting root envelopes.

## Threat model coverage

| Mechanism | Defends against | Notes |
|---|---|---|
| Signed roots | Silent state rewrites without detectable root change | Base cryptographic checkpointing |
| Witness cosigning | Single-operator unilateral root claims | Operator-set M-of-N threshold (`OLYMPUS_FEDERATION_QUORUM_THRESHOLD`, clamped ≥ 1); no fixed default ratio — this is a deployment policy choice, not a protocol constant |
| Gossip comparison | Split-view/equivocation across auditors | Detects same-`checkpoint_timestamp`-or-`tree_size` conflicting signed roots from one signing identity, over Tor |
| MMD status | Hidden records / delayed publication after receipt | `GET /monitor/mmd/{content_hash}` — a server-reported classification, not signed timing evidence (the covering checkpoint is signed; the ingest timestamp it's measured against is not) — see "Monitor API and MMD" above |
| Inclusion/non-inclusion proofs | Hidden records and denial of committed records | `GET /monitor/proof/{content_hash}` — anchored to signed checkpoint roots (Poseidon snapshot tree; see "Known limitation" above) |

## Consequences

- We preserve one global CD-HS-ST data structure and avoid dual-tree operational complexity for the ledger commitment itself — but see "Known limitation" above: the Monitor API's proof surface and the checkpoint-signing/witness-cosigning/anchoring stack all operate on the separate Poseidon snapshot tree, not this one.
- Operational trust posture aligns with CT deployment lessons without forcing RFC-6962 semantics onto an SMT.
- Witness cosigning, gossip, the Monitor API, and MMD are all implemented; production witness *onboarding* (vetting and registering real independent institutions) remains an operational/governance activity, not a further code deliverable.
