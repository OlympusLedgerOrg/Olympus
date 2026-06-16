# ADR-0031: Transition attestations + enforced insert-only ledger (and the peer-coverage gap)

- **Status:** **Proposed — 2026-06-16.** PR1 + PR2 are specified and agent-ready
  (`docs/briefs/ADR-0031-PR1-*.md`, `docs/briefs/ADR-0031-PR2-*.md`). The
  cross-peer coverage question (§4) is an **open decision** — it is framed here,
  not resolved.
- **Builds on:**
  - ADR-0005 (structured length-prefix framing — `lp(x)` is the normative byte
    encoding for the new `persist_message`).
  - ADR-0009 (Poseidon / BJJ-EdDSA — the attestation is signed under the BJJ
    authority key, the same key family that signs SBTs and own-checkpoints).
  - ADR-0021 (SMT + CT-style operational hardening — the persistence-challenge
    option in §4 is a CT-style "prove-you-still-hold-it" probe).
  - ADR-0022 (lazy deep-node storage — the enforcement check in PR2 lives inside
    `update_batch_inner`, which already owns the H-4 write lock).
- **Does not change:** any leaf/node hash, any circuit, any vkey, any ceremony
  manifest, or the `PeerCheckpoint` wire format. The existence/unified circuits
  and the SSMF golden vectors are untouched. There is **no migration-class hash
  event** here.

## Context

Olympus commits ingested records into a parser-bound sparse Merkle tree and
periodically emits a signed checkpoint (`anchoring/own_checkpoint.rs::build_and_persist`)
that signs the Poseidon `snapshot_root` under the BJJ authority key, anchors a
domain-separated digest externally (RFC 3161 / Rekor / OTS), and — under the
`federation` feature — gossips a `PeerCheckpoint` to peers over Tor.

Two properties are weaker than the threat model assumes:

1. **Insert-only is implied but not stated as an invariant.** The persistent
   writer (`PersistentSmt::update_batch_inner`, `src-tauri/src/smt/tree.rs:264`)
   has a `write_once` guard that rejects rewriting an existing key to a
   *different* `value_hash` — but it is a *parameter* (`update_batch_write_once`
   sets it `true`; `update_batch` sets it `false`). There is **no leaf-delete /
   tombstone path** anywhere (`LeafUpdate` is the only mutation entry; there is
   no `remove` and no `DELETE FROM smt_*`). So the ledger is *already* physically
   insert-only — but nothing names it as a guaranteed invariant, nothing signs an
   attestation that two consecutive roots are related by *append only*, and the
   non-`write_once` ingest path can silently overwrite a value.

2. **A checkpoint says "I am at root R over N leaves" — it does not say "and R is
   R_prev plus appends."** A peer (or an external verifier) receiving two
   checkpoints `(R_prev, N_prev)` then `(R, N)` cannot tell a legitimate
   append-only transition from a rewrite/rollback that happens to land on a
   well-formed root. The signed checkpoint binds *a* state, not the *transition*
   between states.

3. **Peers have ~zero witness coverage of each other's records.** Gossip exchanges
   **only** `PeerCheckpoint { ledger_root, tree_size, timestamp, authority_pubkey_hash,
   groth16_proof, public_signals, bjj_signature }` (`src-tauri/src/federation/checkpoint.rs:20`)
   via `POST /federation/checkpoint` (`federation/gossip.rs:172`). No key-level or
   record-level data crosses the wire. So a node that *withholds* or *loses* an
   individual record — while continuing to publish well-formed checkpoints over
   the records it does keep — is **undetectable by peers**. This is the coverage
   ("W" / withholding) gap, and it is the crux that §4 must answer.

## Decision

Ship two foundational changes now (PR1, PR2), and **decide** the coverage
question (§4) before building the challenge path (PR3).

### 1. `TransitionAttestation` primitive (PR1 — `olympus-crypto`)

Add a domain-separated, length-prefixed message and a signable attestation type to
`crates/olympus-crypto`, so every consumer (the checkpoint producer, the future
challenge path, both reference verifiers) derives the exact same bytes:

- `SNAPSHOT_PERSIST_PREFIX: &[u8] = b"OLY:SNAPSHOT:PERSIST:V1"` — a new ASCII
  domain prefix, registered next to `SBT_OPEN_PREFIX` / `SBT_COMMIT_BIND_PREFIX`
  in `crates/olympus-crypto/src/lib.rs`, with a pinned equality assertion in the
  same `#[test]` block that pins the other prefixes (the constant-stability test).
- `persist_message(original_root, snapshot_root, snapshot_size) -> [u8; 32]` —
  `BLAKE3(SNAPSHOT_PERSIST_PREFIX || lp(original_root) || lp(snapshot_root) || lp(u64_be(snapshot_size)))`,
  using the ADR-0005 `lp(x)` length-prefix framing already used by `leaf_hash`.
- `TransitionAttestation` — a crypto-only struct holding `original_root: [u8;32]`,
  `snapshot_root: [u8;32]`, `snapshot_size: i64`, plus a `message(&self) -> [u8;32]`
  helper that returns `persist_message(...)`. It carries the data + recomputes the
  signing digest; it does **not** know about the DB or the wire envelope (those live
  in `src-tauri`).

The signature itself is **BJJ-EdDSA over the digest reduced mod l**, exactly the
SBT-open pattern (`m = BLAKE3(prefix | …) reduced mod l`), so it reuses the
persisted BJJ authority key and the existing offline BJJ verifier.

**Invariant added to CLAUDE.md:** the `OLY:SNAPSHOT:PERSIST:V1` prefix and
`persist_message` framing live **only** in `olympus-crypto`; changing either is a
breaking signature change that must update both reference verifiers in the same
commit.

### 2. Enforce insert-only + emit the attestation (PR2 — `src-tauri`)

- **Make insert-only the enforced ledger invariant, not an opt-in flag.** The
  ingest write path must always run with the write-once guard. Concretely: route
  ledger ingest through `update_batch_write_once` (or flip the ingest caller's
  `write_once` to `true`) so an attempt to rewrite a committed key to a different
  `value_hash` is rejected `400`/`409` instead of silently overwriting. The guard
  already lives in the correct place — inside `update_batch_inner`, under the H-4
  write lock, against the leaves `build_working_set` just read — so this is a
  caller/wiring change plus a regression test, not a new TOCTOU surface. Removal is
  *already* impossible (no delete path); document that as the second half of the
  invariant.
- **Emit a `TransitionAttestation` at checkpoint time.** In
  `anchoring/own_checkpoint.rs::build_and_persist` (which already resolves the BJJ
  key and reads `original_root` / `snapshot_root` / `snapshot_size` from the latest
  ingest snapshot), construct `TransitionAttestation { original_root, snapshot_root,
  snapshot_size }`, BJJ-sign `attestation.message()` reduced mod l, and persist the
  signature alongside the `own_checkpoints` row (new nullable columns via a forward
  migration). This is *additive*: the existing checkpoint/anchor/gossip path is
  unchanged; the attestation rides along.

PR2 **imports `TransitionAttestation`, `SNAPSHOT_PERSIST_PREFIX`, and
`persist_message` from `olympus-crypto`** — so PR1 must land first (see
"Sequencing").

### 3. What this buys (and what it does not)

- An external verifier holding two consecutive own-checkpoints + their transition
  attestations can confirm the issuer *asserted* "R_prev → R over N_prev → N is a
  persist (append-only) transition" under the BJJ key. Combined with the enforced
  insert-only writer, a rollback/rewrite requires the issuer to sign a *false*
  transition attestation — which is now a detectable, attributable equivocation
  (it pairs with `federation/equivocation.rs`).
- It does **not** prove the transition was append-only in zero-knowledge, and it
  does **not** close the peer-coverage gap (§3.3). A node can still withhold an
  individual record and sign perfectly honest checkpoints + attestations over the
  records it *does* keep. That is §4.

### 4. Cross-peer coverage — OPEN DECISION (do not implement before resolving)

The withholding gap (§3.3) is a design fork, not a task. It needs a human decision
about which world Olympus is in. Three options, with a recommendation:

- **Option 1 — Submitter-challenge (recommended).** Coverage comes from the data
  owner, not from peers. A submitter who ingested record `k` periodically calls a
  new `POST /federation/persistence-challenge` (or queries any node) and demands a
  current inclusion proof of `k` against the latest signed root. A node that has
  withheld/lost `k` cannot produce one, and the failure is attributable. This is a
  CT-style "prove you still hold it" probe (fits ADR-0021), needs **no new gossip
  privacy machinery**, and leaks nothing to peers. Cost: only the submitter (not
  arbitrary peers) detects withholding of their own records.
- **Option 2 — Opt-in blinded record gossip.** Peers gossip *blinded* record-level
  commitments (e.g. salted/Pedersen-hidden key digests) so a peer can witness the
  *set* of another peer's records and detect omissions without learning content.
  This gives true cross-peer coverage but adds a new privacy-sensitive wire format,
  a new circuit/commitment scheme, and a much larger ceremony/audit surface. If
  chosen, the useful first step is **an ADR-0021 addendum + a wire-format spec**,
  not code.
- **Option 3 — Accept the limitation.** Document that targeted withholding of an
  individual record is undetectable by peers, and rely on external anchoring +
  submitter retention for durability. No code; a threat-model note.

**Recommendation:** Option 1 as the shipped coverage story (drives PR3 =
`/federation/persistence-challenge`), with Option 2 recorded as a future opt-in
behind its own ADR. PR3's exact shape (challenge wire format, proof type, rate
limiting) is contingent on this decision and is therefore **not yet briefed**.

## Sequencing

```
PR1 (olympus-crypto primitives)  →  PR2 (enforce + emit)  →  [DECIDE §4]  →  PR3 (challenge path)
```

PR2 has a hard compile-time dependency on PR1 (`use olympus_crypto::{TransitionAttestation,
SNAPSHOT_PERSIST_PREFIX, persist_message}`). Hand them to an implementation agent
**in this order**, or instruct the agent to land them together as a stacked pair —
never PR2 alone (it would otherwise stub the constants locally, violating the
"domain constants live only in olympus-crypto" law).

## Consequences

- **No hash/circuit/ceremony change.** Pure additive signature primitive + a
  caller-wiring change + a forward-only migration adding nullable columns.
- The insert-only invariant becomes *stated and enforced* rather than incidental,
  closing the silent-overwrite window on the non-`write_once` ingest path.
- Transition attestations make rollback/rewrite an attributable signed
  equivocation rather than an invisible state swap.
- The peer-coverage gap is explicitly named and deferred to a human decision
  (§4) instead of being papered over.
