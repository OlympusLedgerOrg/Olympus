# ADR-0043: Local secret storage and recovery — OS-keychain-first with encrypted-blob fallback

- **Status:** Proposed (2026-08-11; research/design only)
- **Scope note:** this ADR records a survey, a proposed posture, and a
  migration inventory. It makes **no** source change to `AppState` or any
  signing path; implementation is follow-up work.
- **Decision owners:** Olympus maintainers
- **Security boundary:** at-rest custody and in-memory handling of node-local
  long-lived secrets — the BJJ authority key, the Ed25519 ingest signing key,
  the redaction blind secret, `OLYMPUS_ADMIN_KEY`, and minted per-user BJJ
  master keys.
- **Builds on:**
  - `src-tauri/src/bootstrap.rs` — the existing dev-only keychain tier
    (service `olympus-desktop`, account `bjj_authority_key`; production never
    reads or writes the keychain — audit M-7).
  - `src-tauri/src/state.rs` — `SharedSecret32 = Arc<Zeroizing<[u8; 32]>>`,
    the central in-memory wrapper.
  - ADR-0041 / migration `0056` — rotation _semantics_ (registry supersession,
    role-scoped trust, validity windows). This ADR is about where key material
    physically lives and how it is recovered, which ADR-0041 does not address.
  - `docs/key-rotation.md` — the operational escrow guidance this ADR turns
    into a mechanism.
- **Does not change:** any hash or signature domain, ledger format, SMT proof,
  circuit, ceremony artifact, credential format, or wire format. Storage is
  strictly outside the cryptographic statement surface — but see
  "Cryptography-adjacent surfaces" below for the parts of the _design_ that
  still need crypto-review scrutiny.

## Context

Olympus has no dedicated secret-storage abstraction. The current state:

- **Persistence is env-var-first.** `OLYMPUS_BJJ_AUTHORITY_KEY` and
  `OLYMPUS_INGEST_SIGNING_KEY` are the production persistence surface. The
  process environment is a plaintext store (`/proc/self/environ` on Linux;
  service-manager unit files; shell history during setup) that no in-process
  zeroization can reach.
- **The keychain tier is dev-only** (audit M-7): bootstrap reads/writes the OS
  keychain for the BJJ key only when `!is_production()`, and stores the key as
  a hex `String` via `keyring` v4's `get_password`/`set_password` text API.
- **In-memory coverage is partial.** `AppState` holds the three 32-byte
  secrets as `Arc<Zeroizing<[u8; 32]>>` and derives `Clone` — a clone is a
  refcount bump, not a byte copy, so the state-level story is sound. The V6
  audit's confirmed zeroize gap is everything that _leaves_ that
  representation: owned `[u8; 32]` copies moved into process-lifetime tasks,
  hex-encoding escapes into plain `String`s, and un-scrubbed decode
  intermediates. Appendix A is the complete inventory.
- **There is no recovery story.** `docs/key-rotation.md` says "escrow the old
  private key (offline, access-controlled)" — a manual instruction with no
  supporting mechanism. A lost BJJ authority key makes historical SBTs and
  snapshots unverifiable except through already-exported trust material; a
  lost ingest key is explicitly unrecoverable ("the escrowed copy in your
  secret manager **is** the key").

The #1604–#1609 series fixed rotation _semantics_. The open gap is physical
custody: where the bytes live on a user's machine, what happens when the OS
provides no secure store, and how an operator recovers from loss.

## Survey: OS-native storage via the `keyring` crate

Facts below were verified against crates.io and upstream documentation on
2026-08-11; anything not independently verifiable is marked.

**Crate.** `keyring` (keyring-rs, now under `open-source-cooperative`),
current version 4.1.6 (2026-08-01). v4 split the project into `keyring-core`
(the `Entry` API and error model) plus per-platform credential-store crates.
The default `v1` feature enables macOS/iOS Keychain
(`apple-native-keyring-store`), Windows Credential Manager
(`windows-native-keyring-store`), and Secret Service over pure-Rust zbus
(`zbus-secret-service-keyring-store`). A Linux kernel-keyutils store exists
but is **not** in the default set. **Footgun:** if no platform store feature
is enabled, the crate silently falls back to a mock store — a CI assertion
that a real store is compiled in is mandatory.

**API shape.** `Entry::new(service, user)` plus
`set_password`/`get_password` (UTF-8) and `set_secret`/`get_secret`
(binary). The current bootstrap code uses the text API with hex encoding;
any new abstraction should use the binary API — a 32-byte key needs no hex
round-trip (which today creates un-zeroized heap `String` copies), and 32
bytes is far below every platform's size cap (Windows' generic-credential
blob cap is 2560 bytes).

**Error model** (`keyring-core` 1.0.0): `NoEntry`, `NoStorageAccess`,
`PlatformFailure`, `NoDefaultStore`, `Ambiguous`, `BadEncoding`,
`TooLong`, `Invalid`, plus store-format variants. The fallback decision maps
cleanly: `NoEntry` = first run (generate/enroll); `NoStorageAccess` /
`PlatformFailure` / `NoDefaultStore` = keychain unavailable → encrypted-blob
fallback.

**What each backend actually is.**

- macOS: Keychain Services generic-password items (file-based keychain via
  the `keychain` feature; the newer data-protection keychain behind
  `protected` requires signed builds with entitlements).
- Windows: the **wincred** API (`CredWrite`/`CredRead`,
  `CRED_TYPE_GENERIC`) — a per-user credential vault encrypted at rest via
  DPAPI keyed to the logon credentials. This is _not_ direct DPAPI/CNG use;
  wincred adds named, enumerable, user-visible storage on top of DPAPI's
  access model.
- Linux: the `org.freedesktop.secrets` D-Bus Secret Service (gnome-keyring,
  or KWallet ≥ 5.97), with secrets grouped in collections; the default
  collection is normally unlocked by PAM at desktop login.

**Linux failure modes — the reason a fallback tier is non-optional.** On
headless systems, servers, containers, and many minimal window managers there
is no Secret Service provider (often no session D-Bus at all): the store
surfaces `PlatformFailure` wrapping the bus error. A session with a bus but
no _default collection_ (observed under WSL/systemd) fails until a fallback
collection is chosen; a locked collection that cannot be unlocked
non-interactively surfaces as `NoStorageAccess` (the "unlocked at login" PAM
behavior only holds when the login password equals the keyring password —
auto-login and out-of-band password changes break it, and headless sessions
prompt into nowhere). The keyutils backend works headless but holds keys **in
kernel memory only — nothing survives a reboot** (the kernel "persistent"
keyring persists across sessions with an expiry timer, not across boots), so
it can serve as a per-boot cache at most. Olympus's Critical Invariants
require the Ed25519 and BJJ keys to be _persisted_; keyutils alone cannot
satisfy that, which is what forces the encrypted-blob tier.

**Access-control granularity — what the OS store does and does not give.**
On every desktop platform, code running as the logged-in user can generally
read the stored secrets; none of the three stores provides strong per-app
isolation by default:

- macOS is the strongest: file-based keychain items carry per-item ACLs and
  cross-app access triggers a consent prompt with code-signature checks —
  but users can click through, and unsigned dev builds weaken the identity
  check. Real per-app isolation (keychain access groups) requires the
  data-protection keychain + signed builds, which Olympus's currently
  unsigned macOS bundle cannot use.
- Windows Credential Manager is per-user, not per-app: any process in the
  logon session can `CredRead`/`CredEnumerate` every generic credential. It
  is a well-known credential-dumping target.
- Secret Service unlocks at collection granularity: once the login
  collection is unlocked (normally the whole session), any app on the
  session bus can read all items — the spec has no caller identification.
  (The oo7 project documents this explicitly and exists partly to route
  sandboxed apps through the Flatpak Secret portal instead.)

**Design consequence:** the OS keychain is "encrypted at rest, user-session
gated" — not an app-isolation boundary. Anything stronger belongs to the
hardening tier below.

**Alternatives considered.** `tauri-plugin-stronghold` is not OS storage
(the passphrase problem remains) and a Tauri maintainer has stated it is no
longer recommended and slated for removal in v3 — rejected. `oo7` is a
Linux-only Secret Service client with Flatpak portal support — a candidate
Linux backend if Olympus ever ships as Flatpak, not a cross-platform answer.
Direct `CryptProtectData` (DPAPI) is best seen as a Windows-specific
implementation detail of the fallback blob (same access model as wincred, no
size cap), not a separate tier. Tauri 2 has no first-party secure-storage
plugin; since Olympus needs keys in the Rust core, calling `keyring` from
the backend directly is the natural fit.

## Proposed decision

Adopt a three-tier posture. Tiers 1–2 are the default; tier 3 is an explicit
future hardening milestone, not part of the initial implementation.

**Tier 1 — OS keychain first.** Store each secret as a _binary_ keychain
entry (`set_secret`/`get_secret`) under the existing `olympus-desktop`
service with per-secret account names. Treat `NoEntry` as first-run;
`NoStorageAccess`/`PlatformFailure`/`NoDefaultStore` route to tier 2. CI
must assert a real credential store is compiled in (mock-store detection).

**Tier 2 — encrypted-blob fallback** for platforms/environments with no
usable OS store (headless Linux being the driving case):

```
passphrase ──Argon2id(salt, m, t, p, context)──▶ 32-byte KEK
KEK  ──AEAD (XChaCha20-Poly1305)──▶ wraps a random 32-byte DEK
DEK  ──AEAD──▶ encrypts the key blob
```

- **KDF:** Argon2id with parameters at or above RFC 9106's second
  recommendation (m = 64 MiB, t = 3, p = 4) — deliberately above the OWASP
  server-login floor (19 MiB/t=2/p=1), since a desktop unlock tolerates
  ~0.5–1 s. Parameters are stored beside the blob and versioned so they can
  be raised on rewrap.
- **Framing:** random 16-byte CSPRNG salt stored in cleartext beside the
  blob; a versioned header (magic, KDF params, salt, nonces) bound as AEAD
  associated data; a fixed domain-separation context (working name
  `OLY:KEYSTORE:KEK:V1`) mixed into the derivation so the KEK is bound to
  this purpose.
- **KEK→DEK indirection** is load-bearing: passphrase rotation rewraps only
  the DEK, and the same DEK can be wrapped by multiple enrollments (a
  passphrase _and_ a tier-3 wrap), which is also the recovery mechanism.
- **AEAD:** XChaCha20-Poly1305 — its 192-bit nonce is safe to generate
  randomly; AES-256-GCM's 96-bit nonce demands stricter discipline for no
  benefit here.
- On Windows, the same blob MAY additionally be DPAPI-wrapped (defense in
  depth at zero UX cost). Linux keyutils MAY cache the unwrapped DEK per
  boot; it must never be the durable store.

**Tier 3 — future hardening (explicitly out of scope for the first
implementation).**

- **TPM 2.0 sealing** (Linux via `tss-esapi`, Windows via the CNG Platform
  Crypto Provider): seal the DEK-wrapping KEK to the TPM, optionally
  PCR-bound. Operational surface is real (lockout auth, PCR brittleness
  across firmware updates, "TPM cleared" recovery) — always an _additional_
  wrap of the DEK, never the only one.
- **macOS Secure Enclave:** holds only non-exportable P-256 keys — it can
  never contain the Ed25519/BJJ keys themselves (wrong curves). It can hold
  a P-256 key that ECIES-wraps the DEK, optionally gated by Touch ID via
  `SecAccessControl`. Blocked until the macOS bundle is code-signed.
- **WebAuthn/passkeys with the PRF (hmac-secret) extension:** an
  authenticator-derived 32-byte secret used as HKDF input for a wrapping
  KEK. This is an **access gate deriving a wrapping secret, not a storage
  mechanism** — nothing is stored on the authenticator, and losing it loses
  that KEK, so a second enrollment must always exist. Desktop PRF
  availability outside browsers was still uneven as of this survey
  (unverified in detail).

**Recovery posture.** The tier-2 blob doubles as the recovery artifact: an
operator with the passphrase can restore keys onto a new machine from a
backup of the blob (keychain-only storage has no such property — macOS
keychain items don't leave the machine, wincred doesn't export). The proposed
default is therefore: **even when tier 1 is available, maintain a tier-2
blob as the escrow/recovery copy**, turning `docs/key-rotation.md`'s manual
"escrow the old private key" instruction into a concrete, testable artifact.
Multiple enrollment (DEK wrapped by both the OS-keychain-held KEK and the
passphrase KEK) makes this natural. Loss scenarios then reduce to: lost
passphrase + intact OS store → re-enroll a new blob; lost machine + intact
blob backup → restore and, if compromise is suspected, rotate via the
ADR-0041/migration-0056 supersession path.

### Threat model

Defends against:

- **Offline theft of the blob** (stolen disk, backup, sync folder): each
  passphrase guess costs a memory-hard Argon2id evaluation; at 64 MiB/t=3
  the attacker's throughput is bounded by memory bandwidth, not cores.
- **Tampering:** AEAD + header-as-AAD makes parameter downgrade (e.g.
  weakening stored Argon2 params) and blob substitution detectable.
- **Accidental disclosure** (world-readable dotfiles, committed `.env`
  files, `/proc/self/environ`): secrets leave the environment-variable
  surface entirely.

Does **not** defend against:

- **A live-memory attacker or malware running as the user** — it reads the
  unwrapped key from process memory or the OS store (per the ACL survey
  above), or keylogs the passphrase. This residual risk is identical for
  tiers 1 and 2; only tier 3 narrows it (and only partially).
- **Weak passphrases** — Argon2id multiplies guess cost; it cannot rescue a
  guessable passphrase.
- **Coercion or a compromised machine at enrollment time.**

The zeroize-gap remediation (Appendix A) is complementary: it shrinks the
window in which the live-memory attacker finds bare key bytes outside the
`Zeroizing` wrappers, and it is worth doing regardless of which storage tier
holds the at-rest copy.

### Cryptography-adjacent surfaces (flagged for crypto-review scrutiny)

Per repo standards, the following parts of this design are
cryptographic-code-adjacent and must get the same review scrutiny as domain
prefixes and signing digests, even though none of them touches a ledger
statement:

1. **The KDF context string** (`OLY:KEYSTORE:KEK:V1`) joins the domain-tag
   namespace in `crates/olympus-crypto` conventions — it must be registered
   alongside the existing `OLY:` constants, be disjoint from every signing
   domain, and never be reused for a second purpose.
2. **Key derivation layering:** Argon2id output feeding an HKDF expand step
   (if per-secret subkeys are derived from one KEK) needs explicit,
   length-prefixed `info` framing — the same injection-prevention rule as
   ADR-0005 message framing.
3. **AEAD nonce discipline** and the AAD header layout are consensus-free
   but corruption-critical: a malformed header must fail closed
   (reject-not-default), mirroring the strict-decode posture of
   `decode_hash32`/`hex_to_fr`.
4. **The dev-mode derivations that already exist** —
   `OLY:INGEST:ED25519:DEV:V1 || bjj_key` and
   `OLY:REDACTION:BLIND-SECRET:V1 || bjj_key` — interact with storage: if
   the BJJ key moves out of the env var, these derivations follow it. Any
   change of their inputs is a break-glass event (the blind secret must
   reproduce byte-identically or committed object roots become
   unreproducible — `docs/key-rotation.md` already forbids rotating it).
5. **M-7 revisit:** the audit decision that production never touches the
   keychain was made when the keychain tier was a hex-string convenience.
   Adopting tier 1 in production reverses M-7 and needs an explicit,
   recorded decision — not a silent behavior change.

### Open questions (deliberately unresolved here)

- **Does production adopt tier 1 at all**, or does production stay
  env/file-based (tier 2 only) with tier 1 reserved for the desktop/dev
  experience? The M-7 reversal is a policy call for the maintainers.
- **Passphrase UX:** where in the Tauri first-run flow the tier-2 passphrase
  is collected, and what happens on headless first-run (`olympus-server`
  binary) where no UI exists — flag-driven non-interactive enrollment?
- **Precedence:** does the env var remain an authoritative override above
  tier 1 (as it is today for the keychain), or become an import-once
  migration source? Related: migrating existing installs off
  `bjj_private_dev` (the dev-only DB column) and the existing hex keychain
  entry.
- **Blob location and permissions** per platform (XDG state dir vs. app data
  dir; 0600 enforcement; what `pg_embed`'s data directory precedent
  suggests).
- **Scope of stored secrets:** the redaction blind secret is derived from
  the BJJ key by default — storing it separately is only needed when
  explicitly set. `OLYMPUS_ADMIN_KEY` is a shared operator credential, not a
  node key — probably out of scope for the store. The Ed25519 ingest key is
  currently memory-only-by-design in production; giving it an at-rest home
  changes its documented custody model and needs its own decision.
- **Whether minted per-user BJJ master keys** (`/admin/users` mint flow)
  should ever transit the store, or remain return-once-and-forget.

## Consequences

- A follow-up implementation PR series can be scoped mechanically: (1) a
  `secret_store` module implementing tiers 1–2 behind a trait, (2) bootstrap
  integration + migration of the existing keychain/DB-dev tiers, (3) the
  Appendix A zeroize remediation, (4) docs (`key-rotation.md` recovery
  section rewrite). Tier 3 is its own milestone.
- Until then, nothing changes: this ADR plus the inventory below is the
  agreed map.

---

## Appendix A — raw-secret call-site migration inventory

Complete inventory of call sites touching raw long-lived secret bytes, swept
at main @ `265e7884` (post-#1608). #1609 merged after the sweep and shifted
line numbers slightly in `api/ingest/files/snapshot.rs` and
`anchoring/own_checkpoint.rs` (spot-checked refs below are updated; treat
line numbers as anchors, symbol names as authoritative). This is the
**migration list only** — no migration is performed in this PR. Sites marked ⚠ are the V6-audit-relevant
zeroize gaps; the rest are listed for completeness so the eventual migration
can be checked off against this table.

### Baseline

| Item                              | Status                                                                                                                                                     |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `zeroize` (src-tauri)             | `Cargo.toml:219`, no `derive` feature — wrapper-only                                                                                                       |
| `zeroize` (olympus-crypto)        | optional, enabled only by the `redaction` feature                                                                                                          |
| `zeroize` (babyjubjub-permissive) | with `derive`; `crypto-bigint` also zeroize-enabled                                                                                                        |
| `keyring`                         | `Cargo.toml:223`, `keyring = "4"`                                                                                                                          |
| `ed25519-dalek`                   | v2 with default features → `SigningKey: ZeroizeOnDrop`, but the coverage is inherited from defaults, **not pinned** by an explicit feature — worth pinning |
| Central wrapper                   | `state.rs:40` `SharedSecret32 = Arc<Zeroizing<[u8; 32]>>`; `AppState` derives `Clone` (refcount bump — sound)                                              |

### Worst gaps (long-lived unwrapped copies) — remediation priority order

1. ⚠ `anchoring/cron.rs:52` — `bjj_key: Option<[u8; 32]>` moved into the
   process-lifetime anchor-cron task (fed from `main.rs:328` /
   `bin/olympus-server.rs:185` via `secret_bytes(...).copied()`). A
   permanent bare copy of the root authority key outside the guard.
2. ⚠ `federation/gossip.rs:47` — `bjj_key: [u8; 32]` owned by the
   process-lifetime gossip task (fed from `main.rs:390` /
   `bin/olympus-server.rs:222`). Second permanent copy.
3. ⚠ `api/admin_users.rs:257` — `hex::encode(*bjj_priv)` escapes the
   `Zeroizing` created at `:224` into `MintKeyResponse.bjj_private_key_hex:
String`, and the struct derives `Debug` (`:164`) — one `{:?}` away from
   logging a per-user master private key.
4. ⚠ `bootstrap.rs` — the whole bootstrap path handles the root key
   unwrapped: `BootstrapResult.bjj_authority_key: [u8; 32]` (`:14`),
   `FreshlyGenerated.bjj_authority_key_hex: Option<String>` (`:37`),
   `hex::encode(key)` (`:425`), the extra `.to_owned()` heap copy for the
   keychain `spawn_blocking` (`:744`). Acknowledged as deferred in
   `main.rs:295-299`.
5. ⚠ Per-request owned copies via `let x = *secret_bytes(...)`:
   `credentials/issue.rs:115`, `credentials/revoke.rs:39`,
   `federation/cosign.rs:144` and `:277`, `redaction/redact.rs:86`; most
   notably `api/ingest/files/route.rs:282`, held across the entire ingest
   transaction. The borrow-only pattern at `federation/api.rs:170` is the
   model to converge on.
6. ⚠ Env→bytes decode intermediates never scrubbed: `state.rs:241-248`
   (ingest key), `state.rs:286-288` (blind secret), `bootstrap.rs:221`
   (BJJ env hex → `Vec<u8>`), `anchoring/rekor.rs:428`,
   `anchoring/own_checkpoint.rs:83-86` (re-created on **every** checkpoint
   tick).
7. `OLYMPUS_ADMIN_KEY` — zero coverage by construction: a fresh plain
   `String` per admin request (`api/middleware/auth.rs:428`,
   `api/keys/admin.rs:20`); comparison is BLAKE3-then-`ConstantTimeEq`
   (fine); the env var itself is the exposure.
8. `bin/generate_manifest.rs:185-195` — raw `[u8; 32]` coordinator key with
   a silent fallback to the production BJJ authority key (offline tool, but
   it is the same root secret).

### Full inventory by secret

**BJJ authority key** (root secret) — storage: `state.rs:68` (covered),
`bootstrap.rs:14`/`:37` (uncovered), dev-only DB column
`account_signing_keys.bjj_private_dev` (write `bootstrap.rs:441-442`, read
`:361-377`), dev-only keychain hex entry (`bootstrap.rs:726-753`),
`commands.rs:214` `InitialSecretsSerde` (covered, no `Clone`). Load
precedence env → keychain → DB dev column → generate
(`bootstrap.rs:220-425`). Reads: `bootstrap.rs:64,80,126,231,302,378,423`;
wrap-in `main.rs:192-194` / `olympus-server.rs:148-150`; borrows into
`resolve_ingest_signing_key` and `resolve_redaction_blind_secret`
(`main.rs:202-213`); owned copies per items 1, 2, 5 above; borrows down the
checkpoint path (`federation/checkpoint.rs:176`, `federation/gossip.rs:89,113`,
`anchoring/cron.rs:109,113`, `anchoring/own_checkpoint.rs:119`,
`api/ingest/files/snapshot.rs:37,205`); `bin/generate_manifest.rs:186`.

**Ed25519 ingest/redaction signing key** — storage: `state.rs:94`
(covered), memory-only in production by documented design. Load:
`state.rs:240-259` (env `String` + bare `[u8; 32]` intermediates,
uncovered); dev derivation `state.rs:264-269`. Reads:
`api/redaction/issuer_key.rs:40,47` (borrow, clean),
`api/redaction/redact.rs:86` (owned ⚠), `api/redaction/bundle_v3.rs:290,296`
(borrow). Env-only paths bypassing `AppState`: `anchoring/rekor.rs:109-138`

- `:428-431`, `anchoring/own_checkpoint.rs:80-87` (per-tick ⚠).

**Redaction blind secret** — `state.rs:105` (covered); load
`state.rs:283-295` (env intermediates uncovered); all consumer reads are
borrow-only through the segmenters
(`zk/segment.rs:559,561,698,723,755`, `zk/segment/text.rs:137`,
`zk/segment/ooxml.rs:387,409`, `zk/segment/pdf_textrun.rs:627,676,712`,
`zk/segment/pdf_xref.rs:1139,1153`, `zk/pdf_objects.rs:777,802,1087`) into
`olympus-crypto/src/redaction.rs:184,226,242,312`, which zeroizes its own
intermediates. The best-behaved secret; the model for the others.

**Admin key** — never in `AppState`; per-request env reads
(`api/middleware/auth.rs:428`, `api/keys/admin.rs:20`,
`api/user_auth/handlers.rs:89`); value never logged
(`startup.rs:186-208`). No Rust code ever writes a `.env` file (verified).

**API keys / minted user keys** — `derive_api_key_from_bjj`
(`auth.rs:393-398`) returns a plain `String` by design (it is handed to the
user once); `bootstrap.rs:126,167,196` handles it unlogged (red-team C-1);
`api/admin_users.rs:224-225` wraps the minted private key at generation
(exemplary) but `:257` + the `Debug` derive at `:164` defeat it (item 3
above). Renderer keychain IPC (`commands.rs:767-821`) uses a separate
`api_key` account with the authority-account separation asserted at
`commands.rs:911`.

**Signing primitives** — `crates/babyjubjub-permissive` is the strongest
coverage in the workspace (`PrivateKey` is `Zeroize + ZeroizeOnDrop`,
deliberately not `Clone`/`Copy`, redacted `Debug`, every signing
intermediate wrapped and scrubbed; `raw()` has no non-test caller). The
boundary weakness is `src-tauri/src/zk/witness/baby_jubjub.rs:107-129`:
`from_private`/`sign` take bare `&[u8; 32]`, which is what forces every
caller to hold unwrapped arrays — changing this signature (e.g. to accept
`&Zeroizing<[u8; 32]>` or a borrowed newtype) is the single highest-leverage
migration step, because items 1, 2, and 5 exist to feed it.
