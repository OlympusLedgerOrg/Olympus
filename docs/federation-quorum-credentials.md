# M-of-N Federation Quorum Credentials

_Audience: operators and developers. For the operational runbook context see
[`docs/federation.md`](federation.md) §7; for the next-phase ZK gating decision
see [`docs/audits/2026-05-26-federation-quorum-credentials.md`](audits/2026-05-26-federation-quorum-credentials.md)._

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

```
quorum_msg = Fr_le( BLAKE3("OLY:SBT:QUORUM:V1" | len(commit_id_hex) || commit_id_hex) )
```

The `OLY:SBT:QUORUM:V1` tag keeps a quorum co-signature structurally disjoint
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
