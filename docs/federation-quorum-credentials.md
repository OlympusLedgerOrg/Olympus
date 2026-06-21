# M-of-N Federation Quorum Credentials

_Audience: operators and developers. For the operational runbook context see
[`docs/federation.md`](federation.md) §7; for the next-phase ZK gating decision
see the [Design Rationale & Gating Decision](#appendix-design-rationale--gating-decision) appendix below._

## Motivation

Olympus credentials (SBTs, `src-tauri/src/api/credentials.rs`) are normally
signed by a single BJJ authority key. For high-stakes credential types a single
issuing key is a single point of compromise. This feature lets a credential
require an **M-of-N federation quorum**: `M` of a pinned set of `N` known
federation signers must co-sign before the credential is considered valid.

This is the natural evolution of the federation that already exists — the same
Baby Jubjub EdDSA-Poseidon primitive that signs checkpoints
(`zk::witness::baby_jubjub`), the same pinned-peer trust model (`peer_nodes`),
no new chain dependency, and it works offline. A holder of the `N` public keys
re-verifies the quorum with no node contact.

## Trust model

- **N (the signer set)** = the issuing node's BJJ authority key + every
  `trusted` peer's pinned authority key (`peer_nodes`), assembled at issue time
  by `quorum::trusted_signer_set`. It is **pinned on the credential row**
  (`key_credentials.quorum_signers`, JSONB) so verification is reproducible even
  if federation membership later changes — exactly like the single-issuer
  `issuer_pubkey_{x,y}` columns.
- **M (the threshold)** = `quorum_threshold` on the request, defaulting to
  `OLYMPUS_FEDERATION_QUORUM_THRESHOLD` (or 1). Pinned on the row. Must be
  `1 ≤ M ≤ N`.
- A credential is valid iff `M` **distinct** members of the pinned set have a
  signature that verifies over the quorum message. Fail-closed throughout: an
  unknown signer, a non-member signature, a duplicate signer, or any parse
  failure simply doesn't count toward the quorum.

## Message domain

Every quorum signer signs the same field element:

```text
quorum_msg = Fr_le( BLAKE3("OLY:SBT:QUORUM:V2" | len(commit_id_hex) || commit_id_hex) )
```

The `OLY:SBT:QUORUM:V2` tag keeps a quorum co-signature structurally disjoint
from a single-issuer signature (over the bare `commit_id`) and from a
revocation signature (`OLY:SBT:REVOKE:V1`). A signature minted in one role can
never be replayed in another. `commit_id` itself length-prefixes every
component, so it already binds `(holder, type, issued_at, details|commitment)`.

## Issuance flow

`POST /credentials` with `{"quorum": true, "quorum_threshold": M}`:

1. Compute `commit_id` (plaintext details, or the Pedersen commitment for
   `commit: true` rows) — unchanged from the single-sig path. The single-issuer
   signature is still produced and stored, so quorum is purely **additive**:
   existing scope resolution (`middleware/auth.rs`) and single-sig verification
   keep working.
2. Assemble the pinned signer set `N`.
3. The issuing node signs `quorum_msg` with its authority key — this is both one
   of the `N` signatures and the authentication token for the co-sign requests.
4. **Collect peer co-signatures over Tor** (`federation::cosign::collect_cosignatures`):
   for each trusted peer, `POST /federation/cosign`. Each returned signature is
   verified against the peer's *pinned* pubkey before counting — a peer can only
   contribute a signature attributed to its registered identity. Collection
   stops once the threshold is reached.
5. Verify `valid ≥ M` (`quorum::verify_quorum`). If not, **fail closed with
   `409 Conflict`** — nothing partial is accepted.
6. Persist `quorum_threshold`, `quorum_signers` on the row and the collected
   signatures in `credential_quorum_signatures`.
7. Best-effort: build the ZK quorum proof (see below) and store it.

### The co-sign endpoint (`POST /federation/cosign`)

Peer-facing, Tor-exposed, **no API key** — authenticated cryptographically. A
co-signer:

1. Independently **recomputes `commit_id`** from the request fields (it never
   signs an opaque digest it didn't derive) and rejects a mismatch.
2. Verifies the requester's quorum signature over `quorum_msg`.
3. Checks the requester is one of *its own* trusted peers (`peer_nodes`).
4. Only then signs `quorum_msg` with its authority key and returns the
   signature.

This means each node applies its own membership policy: it will only co-sign for
issuers it has explicitly added as trusted peers.

## Verification

`POST /credentials/{id}/verify` loads the pinned signer set + the stored
signatures, recomputes `commit_id`, and runs `quorum::verify_quorum`. The
response carries `quorum: {threshold, total_signers, valid_signatures,
satisfied}`. This is the authoritative check and needs no federation feature —
any party with the pinned pubkeys can replicate it offline.

## Optional ZK attestation (next-phase)

The `federation_quorum` Circom circuit
(`proofs/circuits/federation_quorum.circom`) proves "**≥ M of these N pinned
signers co-signed**" **without revealing which subset signed** — the per-slot
`enabled` selector vector is private; the pinned pubkey set and threshold are
public. It instantiates one `circomlib` `EdDSAPoseidonVerifier` per slot (gated
by the selector bit) and enforces `sum(enabled) ≥ threshold`.

Status — **ceremony-pending**, mirroring the `unified-circuit` gate:

- The circuit, the Rust witness (`zk::witness::quorum`), the prover
  (`prove_quorum`), and the verifier (`federation_quorum_verifier`) are all
  authored and wired behind the `quorum-circuit` cargo feature (off by default).
- The trusted-setup ceremony has not been run, so the vkey is a placeholder and
  `build.rs` stubs the artifacts. Until a real vkey is staged, proof generation
  is skipped (issuance still succeeds via the explicit signature set) and
  verification of any stored proof fails closed.
- `proofs/setup_circuits.sh` builds the `federation_quorum` artifacts alongside
  the others; gating is Rust-only. `FEDERATION_QUORUM_N = 8` (a pinned set
  larger than 8 still verifies via the explicit signature set but cannot be
  proved by the current circuit).

To bring the ZK path online: run the Phase-2 ceremony for `federation_quorum`
(see `proofs/phase2_ceremony.sh`), stage the real vkey, and build with
`--features quorum-circuit`.

## Schema (migration 0032)

- `key_credentials.quorum_threshold INTEGER` — `M`; NULL on single-sig rows.
- `key_credentials.quorum_signers JSONB` — pinned `N` set.
- `key_credentials.quorum_proof JSONB` / `quorum_proof_signals JSONB` — optional
  ZK proof + its public signals (NULL pre-ceremony).
- `credential_quorum_signatures` — one row per `(credential, signer)`; the
  UNIQUE constraint makes a double-submitted signer a no-op.

## Configuration

- `OLYMPUS_FEDERATION_QUORUM_THRESHOLD` — default `M` (clamped to `≥ 1`).
- Build features: `federation` (peer co-sign transport) and, for the optional ZK
  attestation, `quorum-circuit`.

---

## Appendix: Design Rationale & Gating Decision

_Folded in from the 2026-05-26 design/gating audit record (consolidated here per security audit V4). The explicit M-of-N signature-set quorum is production code — always compiled and unit-tested; the privacy-preserving ZK attestation (`federation_quorum` circuit) is gated next-phase behind the `quorum-circuit` cargo feature (off by default)._

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

- **Domain separation.** Quorum co-signatures use the `OLY:SBT:QUORUM:V2` tag,
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
