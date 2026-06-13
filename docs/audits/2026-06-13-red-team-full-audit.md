# Olympus — Full Red-Team Security Audit (2026-06-13)

**Scope:** Whole-system adversarial review of Olympus v0.10.0 across seven attack
surfaces: authentication/authorization & HTTP middleware; the zero-knowledge
proof layer; SBT credentials / M-of-N quorum / federation co-sign; core crypto
primitives, canonicalization & the Sparse Merkle Tree; file ingest / redaction /
untrusted-document parsing; database / SQL / migrations / secret handling; and
federation / Tor / gossip / equivocation / external anchoring.

**Method:** Read-only source review (no code modified) against the committed
tree at `claude/olympus-red-team-audit-f1mdes`, cross-checked against the ADRs
and the documented invariants in `CLAUDE.md`.

**Headline result:** **No Critical and no exploitable-by-an-external-attacker
High** were found. The codebase is mature and bears clear evidence of prior
audit rounds (tracked IDs H-2/H-4/H-5/H-7/H-10/H-12, M-3/M-4/M-5/M-6, C-1,
F-1/F-RT-1, OTS-1/2, etc.), with regression tests pinning most invariants. The
two High findings are both **trust-anchoring / status-coupling weaknesses in the
public `/credentials/{id}/verify` advisory endpoint** — they degrade the
"any third party can re-verify" guarantee rather than granting privilege on the
node itself (the privilege-granting path, `resolve_sbt_scopes`, is correctly
anchored and fails closed).

Severity counts: **2 High · 2 Medium · 13 Low · many Info/positive.**

---

## High

### H-1 — `/credentials/{id}/verify` anchors trust in the row's own stored pubkey/signer-set, not a trusted root
**File:** `src-tauri/src/api/credentials/verify.rs:146-226` · doc `docs/federation-quorum-credentials.md:89-95`

The public verify endpoint validates the issued signature against
`row.issuer_pubkey_x/y` and the quorum against `row.quorum_signers` — both read
from the **same row the signatures are stored on**. There is no comparison to
`state.bjj_trusted_issuers`. Anyone who can craft/influence a `key_credentials`
row (or any future insert path that doesn't pin the authority key) can choose an
arbitrary issuer keypair, sign `commit_id`, and have the endpoint return
`issued_signature_valid: true` — likewise quorum with an attacker-chosen signer
set + threshold (the R3-01 message binding only prevents *partial* downgrade of
an honest row, not whole-row forgery).

Contrast: the privilege path `resolve_sbt_scopes` (`auth.rs:172-181`) **does**
anchor to the trusted-issuer set + validity window. So this is High, not
Critical: the endpoint grants no scopes — but it is mounted on the public Tor
onion and documented as the "authoritative" offline check, making a
forged-but-"valid" cert a relying-party-deception / transparency-fraud vector.

**Fix:** In `verify.rs`, before reporting `issued_signature_valid`, require
`(issuer_pubkey_x, issuer_pubkey_y)` to match a `state.bjj_trusted_issuers`
entry whose `covers(issued_unix)` holds (mirror `auth.rs:172-181`); validate
each pinned quorum signer against the trusted/peer set; add an explicit
`issuer_trusted: bool` to the response. Update the doc claim.

### H-2 — Quorum verification never checks revocation
**File:** `src-tauri/src/api/credentials/verify.rs:191-226`

The `quorum` block runs `verify_quorum` regardless of `is_revoked`. A revoked
quorum SBT returns `is_revoked: true` **and** `quorum.satisfied: true`
simultaneously. A relying party keying off `satisfied` (the documented
authoritative bit) accepts a revoked credential.

**Fix:** Gate `satisfied` (or add a top-level `valid`) on `!is_revoked`, or
document loudly that `satisfied` is signature-count-only and must be AND-ed with
`!is_revoked`.

---

## Medium

### M-1 — JS canonical-JSON encoder is not byte-equivalent to the Rust canonicalizer (number domain)
**Files:** `crates/olympus-crypto/src/canonical.rs:401-472` · `verifiers/javascript/verifier.js:534-540` · `verifiers/javascript/test_canonical_json.js:90-111`

Rust canonicalizes numbers as exact decimals over the raw JSON token stream
(never through a float). The JS `canonicalJsonEncode` does
`JSON.parse → JSON.stringify`, collapsing every number through an IEEE-754
double. For values that don't round-trip a double (integers > 2^53, high-
precision decimals, `1e21`, `0.1`, …) the JS encoder emits **different canonical
bytes** → a different BLAKE3 commitment. The conformance suite hides this: the JS
test `skip`s any vector it can't reproduce, so CI is green while the encoders
disagree across a large slice of the number domain. A relying party using the
exported JS `canonicalJsonEncode` to re-derive a commitment can get a false
reject (or, with crafted double-equal-but-distinct numbers, commitment ambiguity
on the JS leg). The Rust *verifier* doesn't canonicalize (consumes
pre-canonicalized bytes), so the two bundle-verifiers don't disagree — the risk
is the JS function used as an independent re-derivation oracle.

**Fix:** Port the exact-decimal text-level algorithm into JS (BigInt/decimal-
string, never `JSON.parse` numbers), **or** de-authorize `canonicalJsonEncode`
(remove from the verifier's exported surface). At minimum make the JS
conformance test **fail** (not skip) on any vector it can't reproduce.

### M-2 — Non-federation build issues 1-of-1 "quorum" credentials (self-satisfaction by construction)
**File:** `src-tauri/src/api/credentials/quorum.rs:54-78`

In a `not(feature = "federation")` build the only reachable quorum is 1-of-1,
satisfied by the issuing node alone. Documented as "legitimate and unavoidable,"
but a `quorum: true` credential then carries no more trust than a single-issuer
one, while its naming invites over-trust. The federation build only `warn!`s
(not fail-closed) when `threshold == 1` over many pinned signers.

**Fix (policy):** Reject `quorum: true` with `threshold == 1` (or `N == 1`) as a
422 rather than silently issuing a single-signer "quorum"; consider per-
`credential_type` minimum thresholds (security policy, like the scope map).
Document that quorum is not consulted by `resolve_sbt_scopes`.

---

## Low

| ID | Area | File | Issue |
|----|------|------|-------|
| L-1 | ZK | `zk/vkey.rs:71-113` | Proof G1/G2 parser ignores the projective `z`; the offline **reference** verifier (`verifiers/rust/groth16.rs:99-119`) requires `z == "1"`. Not a soundness break (x,y still subgroup-checked) but a court-evidence cross-impl **conformance** gap. Mirror the reference: require 3 coords, `z == 1`. |
| L-2 | ZK | `api/zk/mod.rs:148-213` | Redaction trust-anchor reads `signals[4]/[5]` by fixed index, relying on ark-groth16's count check firing first. Add an explicit `signals.len() == 6` assert before indexing. |
| L-3 | ZK | `zk/zkey.rs:148-176` | `load_proving_key` (no manifest/blake3 check) is `pub`. Production routes through the manifest-checked entry, but tighten to `pub(crate)`/`#[cfg(test)]` so no future callsite bypasses CEREMONY_INTEGRITY #2. |
| L-4 | Crypto | `olympus-crypto/poseidon.rs:51-58` | `DOMAIN_LEAF == DOMAIN_NODE == 1` in the ZK Merkle layer — no domain separation. Not exploitable today (leaf vs node differ structurally) but must ride the pre-v1.0 ceremony as `NODE = 2` (new vkeys + SSMF vectors same commit). The BLAKE3 SMT layer **is** properly separated. |
| L-5 | Crypto | `olympus-crypto/lib.rs:238-255` | `node_hash` uses bare `\|`-separated inputs; collision-safety rests entirely on the 32-byte width `assert!`, not the separators. Keep the release assert; consider length-prefixing so it's robust to future callers. |
| L-6 | Crypto | `olympus-crypto/smt.rs:438-489` | `verify_(non)existence_proof` validate math only; trivially forgeable when `expected_root: None`. Documented usage hazard. Consider making `expected_root` mandatory or adding a `*_against_anchored_root` wrapper as the sole documented entry. |
| L-7 | DB | `src-tauri/src/db.rs:8-11,206` | Embedded-PG URI (incl. constant `olympus:olympus` creds) written plaintext to `olympus-pg-debug.log`. Loopback-only so low impact, but redact userinfo in `dbg_log` (pattern exists at `anchoring/mod.rs:229`); optionally randomize the PG password per-install. |
| L-8 | DB | `api/user_auth/recovery.rs:74-85` | `request_recovery` has no per-account cap and never invalidates prior tokens or prunes expired rows. IP-rate-limited so not a practical brute-force, but widens the valid-token window. Invalidate prior unused tokens on new request + periodic prune. |
| L-9 | Fed | `federation/equivocation.rs:21-34` | 3-way conflict miss: after an A/B pair is flagged, a third distinct root C at the same `(peer, ts)` finds no `flag = false` row, so C is stored unflagged and `check_and_flag` returns false. C is still persisted as evidence. Drop the `AND equivocation_detected = false` predicate (use `COUNT(DISTINCT ledger_root) > 1`) and flag the new row. |
| L-10 | Fed | `anchoring/tstinfo.rs:24-203` | RFC-3161 TSA **CMS signature + cert chain are not runtime-verified** (only structural messageImprint/nonce/OID bind), yet metadata reports `tst_info_verified: true`. Court reliance depends on the documented offline `openssl ts -verify`. Verify the CMS signature against a configured TSA anchor at submit time, or rename the flag to signal structural-only. |
| L-11 | Fed | `anchoring/own_checkpoint.rs:140-143` | BJJ-signed `checkpoint_timestamp` is unbounded `SystemTime::now()` (no NTP/monotonicity/sanity bound); verify path only rejects negative. External anchors are the real trusted-time source, but nothing compares TSA `genTime` to local time. Add a `genTime`-vs-local sanity window and surface the delta. |
| L-12 | Ingest | `zk/pdf_objects.rs:260-274` | Traditional-xref walk lacks the early entry cap the modern path has (`pdf_xref.rs:299,413`); `MAX_OBJECTS` only checked after the whole `/Prev` chain + spans are built. Bounded by the 100 MB file cap (~16M entries, few-hundred-MB transient) but runs inside the locked ingest txn. Add an early `TooManyObjects` bail once `entries.len()` crosses `MAX_OBJECTS * k`. |
| L-13 | Ingest | `zk/segment/pdf_xref.rs:174-195,521-564` | `object_body_span` is O(objects × filesize) with naive window-scan `find`; worst case ~1.6 TB of byte compares (entry_cap 16384 × 100 MB), single-core CPU DoS inside the locked txn (availability-only, chunk fallback). Search only within the next object's xref window, or tighten `entry_cap` toward `MAX_SEGMENTS`. |

### Additional Low / hygiene (no table row needed)
- **Cosign route has no rate limit** (`federation/cosign.rs:125-233`): unauthenticated Tor-facing; signature is verified before the trusted-peer lookup (correct order) but add the shared `RateLimit` extractor.
- **`redact` scope is unreachable** (`api/redaction/types.rs:113-125`): `require_redact_scope` accepts a `"redact"` scope absent from every `VALID_SCOPES`. Fail-closed (no escalation) — either add it canonically or drop the dead branch.
- **u32 arithmetic on attacker obj-ids/offsets** (`pdf_xref.rs:387,620`, `pdf_objects.rs:270`): wraps silently in release (harmless — leaves bind the id) but would panic under `overflow-checks`. Use `saturating_add`/`wrapping_add` to make intent explicit.

---

## Info / Positive controls verified

These were specifically attacked and found correctly defended — recorded so the
guarantees aren't lost:

- **Auth/authz:** All admin/approval secret comparisons use `subtle::ConstantTimeEq` over BLAKE3 digests (no length leak); empty/unset admin key fails closed. `derive_api_key_from_bjj` is domain-separated BLAKE3 over a CSPRNG key. SBT scope resolver fails closed on unknown `credential_type` and is H-7-hardened (issuer in trusted set + window + recomputed `commit_id` + verified EdDSA with subgroup checks). Credential issue/revoke require role=admin AND admin scope (closes M-3 self-bootstrap). Shard `authorize_write` is unconditional/fail-closed on the only caller-supplied-shard route. `X-Forwarded-For` distrusted by default (M-6); CORS locked to Tauri origins (loopback dev-only); non-loopback bind refused.
- **ZK:** H-2 empty-tree invariant enforced (HTTP + federation paths); ark-groth16 public-input-count binding; M-5 `CircomReduction` sealing (no `LibsnarkReduction` reachable); strict field-modulus parsing (rejects ≥ r before reduce); on-curve + prime-order-subgroup checks on vkey/proof/BJJ points; ceremony manifest blake3 + coordinator-signature contribution-chain, placeholder manifests fatal in prod; redaction & unified circuits bind all leaves / section hashes (no dead-witness or hide-non-redacted-content path).
- **Credentials/quorum:** Domain separation real and enforced — single-issuer (bare/`OLY:SBT:COMMIT:V1`), revocation (`OLY:SBT:REVOKE:V1`), quorum (`OLY:SBT:QUORUM:V2`) are disjoint; signer distinctness by canonical identity in a `BTreeSet` (no duplicate-counting); M=0 impossible, M>N rejected; EdDSA malleability bound (`S < l`). (Doc still says `QUORUM:V1` — stale; code is V2.)
- **Crypto/SMT:** `leaf_hash` binds all six fields, length-prefixed, value_hash/key 32-byte-asserted, shard↔key-prefix authority link enforced in both verifiers; lazy-SMT over-cap canopy logic correct and oracle-tested; H-4 write lock held across read-modify-write with in-lock cache refresh; Poseidon/BJJ constants pinned against circomlib reference vectors.
- **DB/secrets:** No SQL injection (all bound params; no dynamic ORDER BY/columns from user input); scrypt password hashing + ct_eq + timing-equalized login; recovery tokens 32-byte OsRng, hashed at rest, single-use, TTL'd; no API/BJJ/Ed25519/admin/recovery/blind secret logged (C-1 leaks removed); minted key material returned only on admin/dev-gated routes; pagination clamped; RNG is OS-seeded ChaCha CSPRNG; keys persisted (prod fails closed vs ephemeral).
- **Federation/anchoring:** Push & pull share one verify path (wire-version → pinned-pubkey BJJ sig → non-null Groth16 → single fixed vkey → public-signal binding → empty-tree → equivocation); gossip is non-amplifying; Tor HS proxies a separate listener mounting only read/verify + peer routes (no admin/prove/auth/write); anchor URLs only from env (no SSRF), `validate_anchor_url` defeats `localhost.evil.tld`, TLS never disabled; Rekor SET verified + prod fail-closed on missing pubkey (M-4); OTS upgrade-splice closed (OTS-1); RFC-3161 nonce replay closed (M-A1).
- **Ingest/redaction:** Deflate/zip bombs capped (cumulative `MAX_INFLATE`); `/N`,`/Columns`,`/W`,ObjStm offsets bounded/checked_add; `/Prev` cycle-guarded; redaction enforces recompute-root-equals-stored + monotonic/dense segment ids + non-canonical-leaf fail-closed + non-redacted byte-identity; blinding from the secret BJJ key (Pedersen-hiding leaves, no brute-force de-anon); no attacker-controlled filesystem write path.
- **Supply chain:** `deny.toml` bans GPL + wildcards with an empty advisory-ignore list; LGPL only via dynamic glib linking.

---

## Recommended remediation order

1. **H-1 / H-2** — anchor `/credentials/{id}/verify` to the trusted-issuer set
   (+ `covers()`) for issued and quorum signatures, add `issuer_trusted`, and
   couple `satisfied`/`issued_signature_valid` to `!is_revoked`. Closes the
   public-verifier-vs-privilege-path divergence in the safe direction.
2. **M-1** — align or de-authorize the JS `canonicalJsonEncode`; make the JS
   conformance test fail (not skip) on unreproducible vectors.
3. **M-2** — decide policy on N=1 / M=1 "quorum" credentials (fail-closed vs
   warn) and per-type minimum thresholds.
4. **L-1, L-2, L-3** — ZK conformance + defense-in-depth (court-evidence
   re-verifiability and ceremony-bypass hardening).
5. **L-9..L-13** — equivocation 3-way fix, TSA CMS-sig / clock sanity, ingest
   entry-cap + scan-cost bounds.
6. **L-4** — schedule `Poseidon NODE = 2` with the pre-v1.0 Phase-2 ceremony.
7. Remaining Low/hygiene (L-5..L-8, cosign rate-limit, `redact` scope, u32
   arithmetic) as cleanup.

_No finding requires emergency remediation. The system's core soundness
invariants — domain separation, fail-closed authorization, ZK verifier
soundness, ceremony integrity, SMT consistency — hold._
