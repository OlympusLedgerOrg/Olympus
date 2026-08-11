# Key rotation runbook

This is the operational procedure for rotating each long-lived Olympus secret in **v0.10.x, as
the code works today**. It documents what is currently possible, what each rotation breaks, and
the exact order of operations that avoids the known traps. In-band rotation (a key registry with
validity windows, role-separated trust, and signed trust-list snapshots per
[ADR-0041](adr/ADR-0041-role-separated-trust-list-rotation.md)) is roadmap work, not a v0.10
capability — see [ROADMAP.md](../ROADMAP.md).

Security assumptions behind every procedure here are the ones stated in
[threat-model.md](threat-model.md), in particular its non-protections: key compromise itself is
outside the protocol's guarantees, and **v0.10 has no in-band revocation** — historical
verification of old-key signatures rests entirely on the operator-configured trusted-issuer
windows and on out-of-band notice to relying parties. Rotation limits future exposure; it does
not retroactively distrust anything a compromised key already signed within its window.

Read [court-evidence.md §6.1](court-evidence.md#61-bundle-byte-identity-and-bjj-key-rotation)
first if you export checkpoint bundles for legal use: rotation has consequences for historical
bundle export that you must handle **before** rotating, not after.

## Key inventory

| Key | Purpose | Persistence | Rotation today |
| --- | --- | --- | --- |
| `OLYMPUS_BJJ_AUTHORITY_KEY` | SBT/credential signing, checkpoint attestations, trusted-issuer entry 0 | Env var (production's sole surface); OS keychain and DB column (dev only) | Manual procedure below |
| `OLYMPUS_INGEST_SIGNING_KEY` | Ed25519 shard/redaction/snapshot signing | Env var only; Olympus never persists it — operator escrow in a secret manager is the required durable copy | Manual procedure below |
| `OLYMPUS_ANCHOR_SIGN_KEY` | Ed25519 anchoring/receipt signing | Env var; **falls back to the ingest key when unset** | Same as ingest key |
| `OLYMPUS_ADMIN_KEY` | `x-admin-key` break-glass admin header | Env var | Restart with new value |
| `OLYMPUS_REDACTION_BLIND_SECRET` | Redaction blinding salt | Env var, or derived from the BJJ key | **Do not rotate** (see below) |
| Ceremony coordinator key | Signs ZK ceremony manifests | Offline, operator-held | Requires re-signing manifests (see trap below) |
| API keys | HTTP caller authentication | `api_keys` table (BLAKE3 hash) | Supported: issue new + revoke old |
| Account Ed25519 signing keys | User/operator payload signing | `account_signing_keys` (public keys only) | Supported: register + revoke with `replaced_by_key_id` |
| Federation onion identity | Tor hidden-service address | Arti key files | Supported: `POST /federation/identity/rotate` ([federation.md §3](federation.md)) |

The last three rows already have complete in-band flows and are only summarised here. The rest of
this document covers the keys that do **not**.

## Rotating the BJJ authority key

The BJJ authority key is the trust root: it signs SBT credentials, anchors the trusted-issuer
set (it is always entry 0, with an unbounded validity window), signs checkpoint transition
attestations, and binds checkpoint bundles. There is no in-band rotation endpoint. The manual
procedure is:

### 1. Before rotating — export and escrow

- **Export every checkpoint bundle you may need later.** After rotation, the bundle producer
  refuses (`409 Conflict`) to export checkpoints emitted under the old key, because the live
  key's Poseidon hash no longer matches the row's stored `authority_pubkey_hash`
  (`src-tauri/src/api/checkpoint_bundle.rs`). Historical bundles already exported remain
  verifiable — the verifying material is pinned inside them.
- **Escrow the old private key** (offline, access-controlled). It is the only way to export
  old checkpoint bundles after rotation, and the only recovery path if the rotation is aborted.
- Record the old public key coordinates. If you don't have them, they are the decimal strings
  `bjj_pubkey_x` / `bjj_pubkey_y` on the non-revoked `purpose = 'authority'` row in
  `account_signing_keys`.

### 2. Keep the old key trusted for historical verification

Add the **old** public key to `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON` with a `valid_until` at the
rotation time, so credentials issued under it keep resolving scopes (validity is checked
against each credential's `issued_at`):

```json
[{ "x": "<old_x_decimal>", "y": "<old_y_decimal>", "valid_until": ROTATION_UNIX_SECONDS }]
```

`ROTATION_UNIX_SECONDS` is a placeholder — substitute the Unix timestamp of the rotation moment
(`date +%s` at the time you rotate), as a bare JSON number. Do not copy a fixed value: a
timestamp earlier than a credential's `issued_at` rejects that credential.

Malformed entries are dropped with a warning, not a startup failure — check the logs for
`trusted_issuers:` warnings after restart to confirm the entry parsed.

> **Ceremony-manifest exception:** if any ceremony manifest was coordinator-signed by the old
> authority key (the dev fallback when `OLYMPUS_CEREMONY_COORDINATOR_KEY` is unset), the entry
> for the old key must **omit `valid_until`** — manifest verification checks issuer validity at
> the current wall-clock time, not at issuance time (see the coordinator trap below). Production
> deployments are protected from this coupling by the startup gate that refuses a coordinator
> key equal to the runtime authority key (`src-tauri/src/startup.rs`, audit A-3), so this
> exception normally applies to dev/test databases only.

### 3. Update the persisted authority row

Bootstrap behaviour (`src-tauri/src/bootstrap.rs::ensure_bjj_authority`) makes this step
mandatory, not optional:

- The env-var tier does **not** compare the supplied key against the persisted pubkey. Starting
  with a new `OLYMPUS_BJJ_AUTHORITY_KEY` succeeds, but `persist_bjj_pubkey` only fills NULL
  columns — the authority row would silently keep the **old** pubkey.
- The keychain and dev-column tiers **do** compare, and refuse to start on a mismatch.

So, with the node stopped:

```sql
-- One non-revoked authority row exists (unique index on public_key = '').
-- RETURNING makes the update fail closed: it must print exactly one row.
-- Zero rows means the predicate matched nothing, and restarting anyway
-- would leave the registry holding a pubkey the runtime no longer signs
-- under — abort, do not restart.
UPDATE account_signing_keys
SET bjj_pubkey_x = '<new_x_decimal>',
    bjj_pubkey_y = '<new_y_decimal>',
    bjj_private_dev = NULL
WHERE user_id = '00000000-0000-0000-0000-000000000001'
  AND purpose = 'authority' AND revoked_at IS NULL
RETURNING key_id;
```

Proceed only if exactly one `key_id` is returned; on zero rows, stop and inspect the table
(more than one is impossible under the unique index, but zero happens when the row was
already revoked or the predicate is wrong).

This update-in-place loses the old row as an audit record — a known deficiency of the v0.10
scheme (the schema has `revoked_at` / `replaced_by_key_id`, but the singular authority row and
the unique index on `public_key` prevent a supersession chain today). Keep your own rotation log
until the registry work on the roadmap lands.

On **dev installs**, also update or clear the OS keychain entry (service `olympus-desktop`,
account `bjj_authority_key`): a stale keychain entry deriving to the old pubkey will hard-fail
startup with "keychain-key/pubkey mismatch" the moment the env var is absent. Production never
reads or writes the keychain — the env var is its sole persistence surface (audit M-7), so no
keychain step exists there.

### 4. Restart and verify

Restart with the new `OLYMPUS_BJJ_AUTHORITY_KEY`. Then verify:

- Old SBT credentials still resolve scopes (issue a request with a key backed by an
  old-key-signed credential, or `POST /credentials/verify` one).
- New credential issuance works and verifies under the new key.
- The system authority SBT: the bootstrap self-mint is idempotent on the *existence* of a
  non-revoked `olympus:system` / `authority_sbt` row, so the old self-signed SBT remains and
  verifies via the old key's trusted-issuer entry. If you want the system SBT re-issued under
  the new key, revoke the old one first (`POST /credentials/{id}/revoke`) and restart.
- Ceremony manifests still verify (dev: check startup logs; production: startup would `exit(2)`
  on failure).
- Old checkpoint bundles you exported in step 1 still verify offline.

### On suspected compromise

Everything above, plus: set `valid_until` on the compromised key's issuer entry to the last
moment you consider its signatures trustworthy, and publish an out-of-band revocation notice.
**There is no in-band revocation mechanism for compromised old keys in v0.10** — a relying
party that does not receive your notice will continue to accept old-key signatures within the
window you configured. See [court-evidence.md §6.1](court-evidence.md).

## Rotating the Ed25519 ingest signing key

Olympus never persists this key (no database row, no keychain entry — memory only, zeroized on
shutdown), so the escrowed copy in your secret manager **is** the key: losing it is
unrecoverable, and rotating it means replacing that escrowed value. Note the retention split:
the old **private** key needs no retention after rotation (nothing re-signs under it), but the
old **public** key must stay available to bundle verifiers — via each bundle's embedded
`signer_pubkey` plus your out-of-band distribution — which is a different mechanism from the
BJJ trusted-issuer retention described above.

Set the new `OLYMPUS_INGEST_SIGNING_KEY` and restart. Consequences to handle:

- **Checkpoints:** unaffected. Each `own_checkpoints` row pins the signing pubkey at emission;
  bundle verification uses the pinned key, never the live one.
- **Redaction bundles:** `GET /redaction/issuer-key` serves **only the current key**
  (`src-tauri/src/api/redaction/issuer_key.rs`). Bundles signed under the old key remain valid,
  but verifiers who fetch the issuer key from the live endpoint will no longer obtain the key
  that signed them. Archive the old public key and distribute it out-of-band alongside old
  bundles (each bundle also embeds its issuer pubkey; the endpoint is the discovery path).
- **Anchoring:** if `OLYMPUS_ANCHOR_SIGN_KEY` is unset, anchoring falls back to the ingest key
  (`src-tauri/src/anchoring/own_checkpoint.rs`, `rekor.rs`) — rotating the ingest key then also
  rotates your anchoring identity. Set a dedicated `OLYMPUS_ANCHOR_SIGN_KEY` to decouple them.
- Legacy note: rows flagged `snapshot_sig_legacy` (pre-BJJ Ed25519 snapshot signatures,
  migration `0034`) are permanently `Pending` and unaffected by any rotation.

## Rotating `OLYMPUS_ADMIN_KEY`

Generate a new value (≥ 32 chars; the production preflight rejects placeholder-like values),
update the environment, restart. There is no overlap window — the old value stops working at
restart, so coordinate with anyone holding the old key. The comparison is constant-time and the
key is never persisted, so no database or keychain step exists. ADR-0036 signed-request
enforcement is a separate factor and is unaffected.

## Do not rotate `OLYMPUS_REDACTION_BLIND_SECRET`

This value is a deterministic salt, not a signing key: object-level redaction commitments must
reproduce byte-identically across restarts and re-ingests. Changing it makes previously
committed object roots unreproducible. It has no compromise-rotation story in v0.10 — if it is
explicitly set, protect it like the BJJ key it defaults to being derived from.

## The ceremony-coordinator trap

`CeremonyManifest::verify_coordinator_signature` (`src-tauri/src/zk/manifest.rs`) checks the
coordinator's trusted-issuer validity window against the **current wall-clock time**, not the
manifest's `created_unix`. This is deliberate: `created_unix` is not covered by the coordinator
signature, so trusting it would let an attacker slide a manifest into a retired issuer's window.

The operational consequence: **you cannot retire a ceremony-coordinator key by giving its
trusted-issuer entry a bounded `valid_until`** while manifests signed by it are still deployed.
The moment `valid_until` passes, every such manifest fails verification — which in production is
a startup refusal (`exit(2)`). Until the manifest format signs its timestamp (roadmap; noted in
ADR-0041), the only safe options are:

1. Keep the retired coordinator key's issuer entry **unbounded** (no `valid_until`), or
2. Re-run manifest generation with the new coordinator key for **every** circuit
   (`generate_manifest`, see [proofs/CEREMONY_INTEGRITY.md](../proofs/CEREMONY_INTEGRITY.md))
   and ship the re-signed manifests before bounding the old entry.

On coordinator-key **compromise**, option 2 is the only one available: re-sign all manifests,
deploy, then bound (or remove) the compromised entry in the same maintenance window.

## External PostgreSQL credentials

See [external-postgresql-roles.md](external-postgresql-roles.md#credential-rotation) for
rotating the `olympus_runtime` / `olympus_migrator` role passwords.

## Key custody and backups

A database backup without key custody is an unverifiable restore. Whatever backs up PostgreSQL
must be paired with escrow of: the current BJJ authority key, any escrowed prior authority keys,
the ingest signing key (or the knowledge that it is env-derived in dev), and the ceremony
coordinator key. Store them under separate access control from the database backups.
