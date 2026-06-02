# Checkpoint Bundle Schema (`bundle.json`)

> **Status:** v1 — pinned, frozen format. Breaking changes require a
> new schema version with a side-by-side migration path.

`docs/court-evidence.md` §3 documents:

```bash
node verify.js verify-checkpoint --bundle <bundle.json>
```

This file specifies the wire format of `<bundle.json>` so the
JavaScript verifier in `verifiers/javascript/verify.js` and the
producer in `src-tauri/src/api/admin/checkpoint_bundle.rs` agree on
the same bytes.

## Producer

The bundle is produced by the admin-gated route:

```
GET /admin/checkpoints/{id}/bundle
Headers: x-admin-key: <OLYMPUS_ADMIN_KEY>
```

`{id}` is the `own_checkpoints.id` UUID returned from the anchoring
cron's tick log or `GET /admin/checkpoints`. The response body is a
`bundle.json` document conforming to this schema.

## Schema (v1)

All numeric fields the cryptography commits to are **strings**, never
JSON numbers, to avoid IEEE-754 rounding on a 64-bit BigInt round-trip
through `JSON.parse`. Hex fields are lowercase, no `0x` prefix, no
whitespace.

```json
{
  "schema":  "olympus-checkpoint-bundle/v1",
  "checkpoint": {
    "id":                     "<uuid>",
    "ledger_root":            "<decimal Fr>",
    "tree_size":              "<decimal integer>",
    "checkpoint_timestamp":   "<decimal integer, unix seconds>",
    "authority_pubkey_hash":  "<decimal Fr>"
  },
  "bjj_eddsa_poseidon": {
    "scheme":     "BabyJubJub-EdDSA-Poseidon",
    "pubkey": {
      "x": "<decimal Fr>",
      "y": "<decimal Fr>"
    },
    "signature": {
      "r8x": "<decimal Fr>",
      "r8y": "<decimal Fr>",
      "s":   "<decimal Fr>"
    },
    "message": "<decimal Fr>",
    "message_doc": "Poseidon BJJ-EdDSA signs `ledger_root` (the Poseidon snapshot root, decimal Fr). Verify with iden3 BJJ EdDSA-Poseidon: 8·S·B == 8·R + 8·Poseidon(R,A,M)·A."
  },
  "ed25519": {
    "scheme":         "Ed25519 (RFC 8032)",
    "pubkey_hex":     "<64 hex chars>",
    "signature_hex":  "<128 hex chars>",
    "message_hex":    "<64 hex chars: anchor_hash>",
    "message_doc": "Ed25519 signs `anchor_hash`. Verify with any RFC 8032 implementation: ed25519_verify(pubkey, signature, anchor_hash)."
  },
  "anchor_hash": {
    "algorithm": "BLAKE3",
    "domain":    "OLY:CHECKPOINT_ANCHOR:V1",
    "value_hex": "<64 hex chars>",
    "recompute_doc": "BLAKE3(OLY:CHECKPOINT_ANCHOR:V1 | '|' | ledger_root_utf8 | '|' | tree_size_be_8 | '|' | checkpoint_timestamp_be_8 | '|' | authority_pubkey_hash_utf8 | '|' | sig_r8x_utf8 | '|' | sig_r8y_utf8 | '|' | sig_s_utf8). Empty Optional<&str> serialises as the empty UTF-8 string."
  },
  "groth16": {
    "scheme":   "Groth16 over BN254 (snarkjs format)",
    "circuit":  "document_existence",
    "vkey_ref": "proofs/keys/verification_keys/document_existence_vkey.json",
    "proof":          { "pi_a": [...], "pi_b": [[...]], "pi_c": [...] },
    "public_signals": [ "<decimal Fr>", ... ]
  }
}
```

## Field-by-field

| Field | Source row column | Notes |
|---|---|---|
| `checkpoint.id` | `own_checkpoints.id` | UUID v4. |
| `checkpoint.ledger_root` | `own_checkpoints.ledger_root` | Poseidon snapshot root, decimal Fr. |
| `checkpoint.tree_size` | `own_checkpoints.tree_size` | i64, decimal string. |
| `checkpoint.checkpoint_timestamp` | `own_checkpoints.checkpoint_timestamp` | i64 unix seconds, decimal string. |
| `checkpoint.authority_pubkey_hash` | `own_checkpoints.authority_pubkey_hash` | Poseidon hash of BJJ pubkey coords, decimal Fr. |
| `bjj_eddsa_poseidon.signature.r8x/r8y/s` | `own_checkpoints.sig_r8x/r8y/s` | All decimal Fr. |
| `bjj_eddsa_poseidon.pubkey.x/y` | derived from current BJJ authority key | Bundle producer re-derives + verifies match `authority_pubkey_hash` before emission. |
| `bjj_eddsa_poseidon.message` | recomputed | The Poseidon BJJ-EdDSA "message" is `ledger_root` directly (see `babyjubjub-permissive`). |
| `ed25519.pubkey_hex` | `own_checkpoints.ed25519_pubkey_hex` | Migration 0042. |
| `ed25519.signature_hex` | `own_checkpoints.ed25519_signature_hex` | Migration 0042. Signed at `build_and_persist` time. |
| `ed25519.message_hex` | `hex(own_checkpoints.anchor_hash)` | The Ed25519 signature is over the raw 32-byte anchor_hash bytes. |
| `anchor_hash.value_hex` | `hex(own_checkpoints.anchor_hash)` | BLAKE3-OLY:CHECKPOINT_ANCHOR:V1 domain digest. |
| `groth16.proof` | `own_checkpoints.groth16_proof` | snarkjs JSON shape (`pi_a`/`pi_b`/`pi_c`). |
| `groth16.public_signals` | `own_checkpoints.public_signals` | Decimal Fr array. |

## Verification

The JS verifier runs **four independent checks**:

1. **Anchor digest reconstruction.** Recompute `BLAKE3(OLY:CHECKPOINT_ANCHOR:V1 | …)` from the `checkpoint.*` fields and assert it equals `anchor_hash.value_hex`. (This rebinds every signed/anchored field to the row.)
2. **Ed25519.** `ed25519_verify(pubkey_hex, signature_hex, anchor_hash bytes)`. RFC 8032 verify.
3. **BJJ-EdDSA-Poseidon.** Recompute Poseidon(R, A, M); check `8·S·B == 8·R + 8·hRAM·A` on Baby Jubjub. Pubkey coords must additionally hash to `authority_pubkey_hash`.
4. **Groth16.** Defer to `verifiers/rust/olympus-verifier verify --vkey <…> --proof <bundle.groth16.proof> --public-signals <bundle.groth16.public_signals> --circuit document_existence`. The JS verifier prints the exact command and exits 0 only if Rust verify also returned 0 in the test pipeline.

Optional check (operator-side, not in the JS verifier itself):
- The JS verifier prints `ledger_root`, `tree_size`, and `anchor_hash.value_hex` so the operator can independently look up the RFC 3161 / Rekor / OTS receipts for the same `anchor_hash` and verify those out-of-band, per court-evidence.md §3 commands 4–6.

## Why these fields, not a freer envelope

Every column above is **the byte sequence the underlying cryptography commits to**. Adding a field to `bundle.json` after the fact does not re-sign anything; reading a different column or trimming whitespace will silently invalidate the signature. The schema is deliberately minimal:

- No human-readable formatting (timestamps stay numeric).
- No JSON numbers for cryptographic field elements.
- No nesting beyond the four top-level scheme groupings, so a reader can audit which group contributes to which check.
- The `*_doc` fields are documentation **only** — they MUST NOT participate in any hash or signature recomputation.

A future v2 schema (e.g. for a different circuit, a different signature scheme, or a chain of own-anchored receipts inline) MUST bump `schema` to `olympus-checkpoint-bundle/v2` and the producer/verifier MUST refuse mixed versions.
