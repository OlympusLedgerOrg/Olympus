# Federation M-of-N Quorum Credentials: Design & Gating Decision

**Date:** 2026-05-26
**Status:** Implemented — explicit M-of-N signature-set quorum is production
code (always compiled, fully unit-tested). The privacy-preserving ZK
attestation (`federation_quorum` circuit) is gated as next-phase behind the
`quorum-circuit` cargo feature (off by default), mirroring the `unified-circuit`
gating decision in [`2026-05-26-unified-circuit-gap.md`](2026-05-26-unified-circuit-gap.md).

This builds on two sibling efforts and reuses their infrastructure rather than
duplicating it:
- `claude/gate-unified-circuit-next-phase` — established the "next-phase circuit
  gated behind a cargo feature, Rust-only gating, setup builds all artifacts"
  pattern this feature follows for `federation_quorum`.
- `claude/circuit-soundness-docs-arity` — clarified (audit C-1) that Olympus has
  no in-circuit EdDSA verifier and that `baby_jubjub::verify_signature` is the
  authoritative off-circuit path. The quorum signature-set verifier relies on
  exactly that primitive; no API change was needed.

---

## Why this design (not EVM / not a new chain)

The federation already has multi-node checkpoint gossip + equivocation
detection over Tor, all built on Baby Jubjub EdDSA-Poseidon. The natural
evolution of "make credential issuance harder to compromise" is **M-of-N
federation co-signing using the cryptography already in the stack** — not an
on-chain multisig. It works offline, has no chain dependency, and the existing
`peer_nodes` trust model supplies the signer set.

## Two layers, two trust postures

| Layer | What it proves | Status | Trust |
|-------|----------------|--------|-------|
| Explicit signature set (`crate::quorum`) | `M` distinct pinned signers each produced a valid BJJ-EdDSA signature over the quorum message | **Production** — always compiled, unit-tested | Authoritative |
| ZK quorum proof (`federation_quorum` circuit) | `≥ M of N` signed **without revealing which** | **Next-phase** — ceremony-pending, `--features quorum-circuit` | Privacy add-on; never the sole check |

The explicit set is the security-critical mechanism. The ZK proof is an optional
privacy layer (hides *which* peers signed); it is never the only thing standing
between a holder and a valid credential.

## Security properties (explicit set)

- **Domain separation.** Quorum co-signatures use the `OLY:SBT:QUORUM:V1` tag,
  disjoint from single-issuer (bare `commit_id`) and revocation
  (`OLY:SBT:REVOKE:V1`) signatures. No cross-role replay.
- **Pinned set.** `N` and `M` are frozen on the row at issue time → verification
  is reproducible and independent of later membership changes.
- **Distinctness.** Signers are de-duplicated by canonical (`Fr`-normalised)
  identity, so one signer can't satisfy a threshold of two.
- **Fail-closed.** Non-member signatures, malformed fields, and non-canonical
  encodings are dropped, never counted. An empty/corrupt pinned set yields zero
  valid signatures → not satisfied.
- **Subgroup / malleability guards.** Each signature goes through
  `baby_jubjub::verify_signature`, which enforces R8 + pubkey prime-order
  subgroup membership and a canonical `S < l` bound (audit C-1 hardening).
- **Co-sign authorization.** A node only co-signs for issuers in *its own*
  trusted-peer set, and always recomputes `commit_id` itself — it never signs an
  opaque digest. The requester's own quorum signature authenticates the request.

## ZK circuit soundness sketch (`federation_quorum.circom`)

- `enabled[i]` constrained binary.
- One `circomlib` `EdDSAPoseidonVerifier` per slot, gated by `enabled[i]`: a slot
  with `enabled=1` MUST carry a signature that verifies under the public pinned
  pubkey `(signerAx[i], signerAy[i])` over `msg`.
- Slots bound 1:1 to the **distinct** public pinned pubkeys (host de-dupes), so
  the enabled count = distinct members who signed.
- `sum(enabled) ≥ threshold` enforced by an in-circuit comparator.
- Privacy: only the `enabled[]` selector is private, so the proof reveals the
  *count* meets threshold but not *which* members signed.
- Padding: when the real set < `N`, trailing slots repeat the last real pubkey
  (`enabled=0`) and borrow an on-curve `(R8, S)` from an enabled slot so the
  unconditional in-circuit scalar-mults stay satisfiable.

## Ceremony-pending caveats

- No trusted setup has been run for `federation_quorum`; the committed vkey is a
  placeholder (gitignored, stubbed by `build.rs`). Proof generation/verification
  is therefore inert until `--features quorum-circuit` is built against a real
  vkey.
- The circuit and Rust witness have NOT been exercised end-to-end (no circom
  compilation / ceremony in CI). The native pre-check (`QuorumProofWitness::
  verify_inputs`, which uses the authoritative off-circuit verifier) IS
  unit-tested, but in-circuit soundness must be reviewed before the ceremony.
- `FEDERATION_QUORUM_N = 8` caps the provable set size; larger sets still verify
  via the explicit signature set.

## Constraint budget

~`N` `EdDSAPoseidonVerifier` instances (N=8). Estimated well under the ptau20
ceiling; `setup_circuits.sh` pins `REQUIRED_POWER=19` conservatively. Re-check
with `snarkjs r1cs info federation_quorum.r1cs` before adjusting `N`.
