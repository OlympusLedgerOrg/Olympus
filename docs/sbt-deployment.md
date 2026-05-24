# Native Soulbound Tokens (SBTs)

Olympus issues credentials as **Olympus-native** Soulbound Tokens —
non-transferable, BJJ-EdDSA-signed records stored in the embedded
PostgreSQL.  Every credential row carries the issuer's BJJ public key
and a signature over a BLAKE3 commitment of its fields, so anyone with
the federation's public key can verify a credential offline without
contacting the issuing node.

There is no blockchain mirror.  An earlier draft (see git history
prior to migration 0027) wired the schema for an optional ERC-5484
EVM projection; that path was retired alongside the rest of the
EVM/sequencer stack in #927 and dropped from the schema in migration
0027.

## Trust model

A credential is bound to a `holder_key` — an opaque string that can be
a UUID, an email, a `bjj:<x>:<y>` pubkey, an ENS name, or anything
else the issuer chooses.  Olympus treats it as opaque bytes for the
hash; the issuer is responsible for whatever real-world binding they
attach to it (notarised ID, key-signing party, etc.).

The signature is BJJ-EdDSA over `Fr_from_le_bytes(commit_id)` where:

```
commit_id = BLAKE3(
    "OLY:SBT:V1"
    | len(holder_key) || holder_key
    | len(credential_type) || credential_type
    | issued_at_unix (i64 big-endian)
    | len(details_json) || details_json
)
```

`details_json` is `serde_json::to_vec(&details)` of the issuer's JSON —
verifiers must match byte-for-byte.  Length-prefixing every variable
field prevents boundary-collision attacks.

Revocation gets its own digest (`OLY:SBT:REVOKE:V1 | commit_id_hex |
revoked_at_unix`) so a captured issuance signature cannot be replayed
as a revocation.

## API surface

All routes are HTTP and require API-key auth with `admin` (issue,
revoke) or `read`/`verify`/`admin` (read, list, server-side verify).

| Route | Method | Scope | Purpose |
|---|---|---|---|
| `/credentials` | POST | `admin` | Issue a new credential |
| `/credentials` | GET | `read`/`verify`/`admin` | List, optionally filtered by `holder` and `type` |
| `/credentials/{id}` | GET | `read`/`verify`/`admin` | Read one credential with signatures attached |
| `/credentials/{id}/revoke` | POST | `admin` | Sign + record a revocation |
| `/credentials/{id}/verify` | POST | `verify`/`read`/`admin` | Re-verify on the server (debug convenience) |

The full credential JSON includes:

```jsonc
{
  "id": "…uuid…",
  "holder_key": "user:abc",
  "credential_type": "press_credential",
  "issued_at": "2026-05-22T17:30:00+00:00",
  "revoked_at": null,
  "issuer": "olympus:federation",
  "commit_id": "<64 hex chars>",
  "details": { "claims": ["FOIA filer"] },
  "issuer_pubkey": { "r8x": "<decimal Fr>", "r8y": "<decimal Fr>", "s": "" },
  "issued_signature": { "r8x": "…", "r8y": "…", "s": "…" },
  "revoked_signature": null
}
```

## Issuing a credential

```bash
curl -X POST "$OLYMPUS_API/credentials" \
  -H "X-API-Key: $OLYMPUS_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "holder_key": "email:alice@example.com",
    "credential_type": "press_credential",
    "details": {
      "outlet": "ExampleWire",
      "issued_for": "2026 election coverage"
    }
  }'
```

Response is the full credential JSON with the freshly-computed
`issued_signature` populated.  The same JSON is what a verifier
ingests later; Olympus does not need to be online for the verifier to
check it.

## Offline verification (no Olympus node)

A holder, lawyer, or auditor can verify a credential against the
federation's public key by recomputing `commit_id` and checking the
BJJ-EdDSA signature. Any iden3 `babyjubjub-rs` consumer in Rust, or a
`circomlibjs` consumer in JavaScript, works. The Rust reference is in
[`crates/olympus-crypto`](../crates/olympus-crypto) and the JavaScript
reference is in [`verifiers/javascript/`](../verifiers/javascript/);
the snippet below is illustrative pseudocode of the digest formula:

```text
# Illustrative pseudocode — see verifiers/{rust,javascript}/ for the real reference.
commit = BLAKE3(
    "OLY:SBT:V1"
    || len32(holder)    || holder
    || len32(ctype)     || ctype
    || i64_be(issued_at)
    || len32(details)   || details
)
msg = int_le(commit) mod BN254_FR
assert babyjubjub.verify(pubkey, signature, msg)
```

## UI

Operators with an `admin`-scoped API key issue, list, revoke, and
re-verify credentials at `/credentials` in the desktop app.  See
`app/public-ui/src/pages/CredentialsPage.tsx`.

## Bootstrap-minted authority credential

On first boot the federation also issues itself a single
`authority_sbt` credential (see `src-tauri/src/bootstrap.rs`
`ensure_system_sbt`).  It serves as a self-bound declaration that the
BJJ pubkey is the federation's authority key.  Pre-migration-0027
this row was created without a signature; if you upgrade an existing
deployment, the row is preserved but its `issued_signature` will be
`null`.  Re-issue via `POST /credentials` to obtain a signed authority
claim on the upgraded schema.
