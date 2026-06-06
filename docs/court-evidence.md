# Olympus Evidence Pack — Information for Court Proceedings

_Audience: lawyers, opposing counsel's expert witness, judges hearing
Daubert / Frye challenges, and journalists who need to cite a primary
technical reference._

This document explains, in plain language, **what an Olympus
verification bundle proves**, **why the cryptography is admissible**,
and **how to independently verify the proofs without trusting any
Olympus operator**. It is written so that a competent third-party
technologist can reproduce every check on their own equipment.

---

## 0. v0.9 court-readiness statement — read this first

Olympus v0.9 is **not** court-ready by the strictest possible reading
of this document. Two specific gaps must close before an Olympus
bundle is suitable for adversarial litigation:

1. **The trusted-setup ceremony shipped with v0.9 has one
   contributor, not three+.** §5 of this document describes the
   standard required for a production deployment; v0.9 ships with a
   single-contributor dev ceremony that the production startup gate
   refuses to run against (`OLYMPUS_ENV=production` exits with code 2
   on a single-contributor manifest — see PR #1164 / audit A-2). The
   binary will simply not boot in production mode until a real
   multi-contributor ceremony has run and its manifest replaces the
   dev one. **A v0.9 binary running in dev mode against a
   single-contributor ceremony is not suitable for adversarial
   proceedings.** v1.0 ships the production ceremony.

2. **Four red-team findings are in flight with open fix PRs:**

   | Finding | Severity | Fix PR | What it closes |
   |---|---|---|---|
   | OTS-1 | Critical | [#1182](https://github.com/OlympusLedgerOrg/Olympus/pull/1182) | Calendar substitution of upgraded OTS receipt for a different anchored hash |
   | OTS-2 | High | [#1184](https://github.com/OlympusLedgerOrg/Olympus/pull/1184) | Unbounded calendar / TSA / Rekor response → OOM |
   | GRV-1 | High | [#1186](https://github.com/OlympusLedgerOrg/Olympus/pull/1186) | Crafted vkey with huge `nPublic` → court verifier DoS |
   | CKPT-1 | High | [#1187](https://github.com/OlympusLedgerOrg/Olympus/pull/1187) | Missing UNIQUE on `own_checkpoints(ledger_root, tree_size)` |

   These are held for review and not auto-merged. Operators relying
   on the bundle in court should confirm each is merged into the
   binary they ran, OR perform the mitigation manually (independently
   re-walking the OTS upgrade, manually inspecting the bundle's
   `own_checkpoints` row by id, etc.).

Sections 1–9 describe the **post-fix** state. Where the in-flight PR
materially changes behaviour, that's called out inline with the PR
number. References to merged red-team work cite the merged PR.

---

## 1. The single sentence

> "On date `T`, an Olympus node produced a Merkle root `R` covering
> tree size `N`, signed it with key `K`, and registered the existence
> of that signed state with up to three independent third-party services
> (`RFC 3161`, `Sigstore Rekor`, `OpenTimestamps`)."

"Up to three" because the three anchor backends are independently
opt-in via env vars (see §1.1). A node with zero `OLYMPUS_ANCHOR_*`
URLs configured runs in **producer-only mode**: it still writes a
locally-signed `own_checkpoints` row each cron tick but issues no
external anchor receipts. That row is not court evidence by itself —
the court-evidence claim requires at least one of the three external
anchors to fire.

Everything below is a structured way of demonstrating the single
sentence and showing how each link in the chain resists tampering.

---

### 1.1 What the v0.9 binary actually enforces online

Anchoring infrastructure lands in stages. This callout pins which
checks the **running node** enforces in v0.9 versus which rely on
**offline tools** (`openssl ts -verify`, `rekor-cli`, `ots verify`).
If you are presenting a bundle in court, both layers matter — online
enforcement makes the receipt fresh and non-replayable; offline tools
re-verify the cryptography on the opposing party's own hardware.

> **Anchoring is conditional on operator configuration.** Each of the
> three backends fires only when its env var is set:
>
> | Backend | Enable via |
> |---|---|
> | RFC 3161 | `OLYMPUS_ANCHOR_RFC3161_URL` |
> | Sigstore Rekor | `OLYMPUS_ANCHOR_REKOR_URL` |
> | OpenTimestamps | `OLYMPUS_ANCHOR_OTS_CALENDARS` |
>
> If none are set, the anchor cron logs `anchor cron: no
> OLYMPUS_ANCHOR_* URLs configured; starting producer-only mode` and
> the `anchor_receipts` table stays empty. Confirm against your
> operator's deployment config before relying on the §3 receipts.

> **Version scope — read first.** The in-node checks in the left column
> land with PRs **#1058**, **#1061**, **#1160**, and **#1165** (the
> `own_checkpoints` unification that made the anchor cron actually run
> for the first time). A binary built *before* those merge performs
> **none** of the online checks: it submits each receipt and stores it
> verbatim — no nonce-echo comparison, no Rekor SET verification, no OTS
> upgrade cron — and on a pre-#1165 build the anchor cron is silently
> inert because it was reading a never-written BLAKE3 column. The
> `metadata.nonce_echo_verified`, `metadata.set_verified`, and
> `metadata.phase` fields referenced below will be **absent** from real
> rows on such a build, and `anchor_receipts` itself will be empty. On
> such a build the entire evidentiary weight rests on the **offline**
> tools in the right column. Confirm your node includes #1058 + #1061
> + #1165 before relying on the online column or the `metadata.*`
> checklist at the end of this section.

| Anchor | Online (in-node) check | Offline tool — required for full proof |
|---|---|---|
| **RFC 3161 TSA** | Submission, response sanity check, **nonce-echo verification** (audit M-A1 — refuses receipts that don't echo the request nonce, defeats TSR splicing). Response size capped at 10 MiB ([fix in flight at #1184](https://github.com/OlympusLedgerOrg/Olympus/pull/1184)). | `openssl ts -verify` against the TSA cert chain (TSA signature, message imprint, cert validity at `T`) |
| **Sigstore Rekor** | Submission, response shape parse, **signedEntryTimestamp ECDSA-P-256 verification** when `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set (audit M-A2 — refuses unsigned-by-log receipts). When unset, receipt is stored with `metadata.set_verified=false` and a startup warning is logged. Response size capped at 10 MiB ([fix in flight at #1184](https://github.com/OlympusLedgerOrg/Olympus/pull/1184)). | `rekor-cli get --uuid <UUID>` to confirm the entry is still in the log + verifiable inclusion proof |
| **OpenTimestamps** | Submission (pending receipt) + **periodic upgrade cron** (audit M-A3, default 6h) that re-fetches each pending receipt from its originating calendar and persists the Bitcoin-anchored form. `metadata.phase` transitions `pending → upgraded`. **OTS-1 commitment re-verification on upgrade is in flight** ([#1182](https://github.com/OlympusLedgerOrg/Olympus/pull/1182)); until merged, an honest operator should independently re-walk the upgraded blob's op chain (or run `ots verify` against the original `anchored_hash`) before publishing the bundle. Response size capped at 10 MiB ([#1184](https://github.com/OlympusLedgerOrg/Olympus/pull/1184)). | `ots verify <receipt>` — requires `metadata.phase == "upgraded"` (the cron has run and replaced the blob). Pending receipts fail `ots verify` because no Bitcoin commitment exists yet. |

**Operator checklist before relying on the bundle in court:**

- [ ] At least one `OLYMPUS_ANCHOR_*` URL is set. (Without any, the bundle is producer-only — no court evidence.)
- [ ] `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set to the Rekor instance's log public key. Without it, the SET is not verified at submission time and the bundle's freshness rests on the live `rekor-cli get` call alone.
- [ ] At least one anchor cron tick has elapsed since each receipt was submitted (otherwise the OTS row may still be pending).
- [ ] The receipt rows in `anchor_receipts` show `metadata.nonce_echo_verified=true` (RFC 3161), `metadata.set_verified=true` (Rekor), and `metadata.phase='upgraded'` (OTS). Anything else is a gap to flag to opposing counsel before they do.
- [ ] Each row in `anchor_receipts` has a non-NULL `checkpoint_id` joining back to an `own_checkpoints` row (PR #1165 closure). A NULL `checkpoint_id` is a pre-#1165 row whose audit trail cannot be reconstructed from the bundle alone.
- [ ] For OTS rows: until #1182 merges, run `ots verify <upgraded_receipt> -f <anchored_hash>` yourself — do not rely on the in-node walker to detect calendar substitution.

---

## 2. The five claims, layered

| # | Claim | What proves it |
|---|---|---|
| 1 | **The hash is well-formed** | BLAKE3 digest of a canonical (JCS/RFC 8785) representation of the source data. Same bytes on every machine. |
| 2 | **The hash is included in a Merkle tree at a specific index** | Groth16 zero-knowledge inclusion proof produced by the `document_existence` circuit (`proofs/circuits/document_existence.circom`). Verifiable against the published verification key in `proofs/keys/verification_keys/document_existence_vkey.json`. |
| 3 | **The Merkle root was signed by the Olympus node** | Two-layer signature: (a) **Baby Jubjub EdDSA-Poseidon** over the Poseidon snapshot root, the same form federation gossip verifies; (b) **Ed25519** (RFC 8032) over `anchor_hash = BLAKE3(OLY:CHECKPOINT_ANCHOR:V1 \| ledger_root \| tree_size \| timestamp \| authority_pubkey_hash \| BJJ_sig)`, pinned at emission time so a published bundle is byte-identical on every re-export. Verifiable with the node's published Ed25519 verifying key and BJJ authority pubkey (`(Ax, Ay)`). |
| 4 | **The signed checkpoint existed by the timestamp** | Three independent anchors, see §1.1 for which checks fire online vs. offline and the env-var preconditions for each: <ul><li>**RFC 3161 TSA** — accredited authority signs `SHA-256(checkpoint)` at time `T`. Olympus enforces nonce-echo at submission; full cert-chain verification with `openssl ts -verify -in <receipt> -queryfile <hash> -CAfile <tsa-cert-chain>`.</li><li>**Sigstore Rekor** — append-only public transparency log. SET ECDSA verification at submission when `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set; independently verifiable via `rekor-cli get --uuid <UUID>`.</li><li>**OpenTimestamps** — pending receipts are upgraded to Bitcoin-anchored form by a background cron (default 6h cadence). Once `metadata.phase == "upgraded"`, the receipt verifies against Bitcoin with `ots verify <receipt> -f <file>`. No trust in any private party required. **Until [#1182](https://github.com/OlympusLedgerOrg/Olympus/pull/1182) merges**, the upgraded blob is accepted without re-walking its commitment chain against the pending receipt — a court verifier should run `ots verify` themselves rather than relying on the row reaching `phase=upgraded`.</li></ul> |
| 5 | **The redaction was correct** _(when applicable)_ | Groth16 proof from the `redaction_validity` circuit: shows the redacted commitment is derived only by applying a permitted mask to the original tree's leaves; nothing else was modified. Independent of the document content. |

Each row is independently verifiable. Any single row holding makes
the corresponding claim true; **the full chain together is robust to
single-point compromise** of any one of: the Olympus node, the TSA,
the Rekor log, or the OTS calendar — subject to the v0.9 court-
readiness caveats in §0 (single-contributor ceremony + in-flight fixes).

---

## 3. Independent verification — minimal commands

The verifier should not run Olympus's own desktop binary, because that
would delegate trust back to Olympus. Use the cross-language verifiers
in [`verifiers/`](../verifiers/) instead — independent reference
implementations in Rust and JavaScript that re-derive the protocol's
primitives so the math is checkable without trusting any Olympus code.

> **Order of operations matters.** The JavaScript verifier in step 3
> runs three checks itself (anchor-hash reconstruction, Ed25519,
> BJJ-EdDSA-Poseidon) and *prints* the cargo invocation for the
> Groth16 step (step 2 / step 4 in `verify.js` output) without
> running it. The line "All JS-side checks passed" means **checks
> 1–3 of the JS verifier completed** — it does **not** mean the
> Groth16 proof has been verified. Run step 2 separately to complete
> the chain.

```bash
# 1. BLAKE3 canonical digest (matches Olympus's hash on any machine)
echo -n '<canonical_json_bytes>' | b3sum

# 2. Groth16 verification — Rust verifier
#    Until #1186 merges, the verifier accepts arbitrarily large `nPublic`
#    in the vkey JSON; a tampered vkey could DoS the verifier. Inspect
#    the vkey's `nPublic` field by hand first (real Olympus circuits
#    have <16 public inputs).
cd verifiers/rust
cargo run --release -- verify \
    --circuit document_existence \
    --vkey ../../proofs/keys/verification_keys/document_existence_vkey.json \
    --proof <proof.json> \
    --public-signals <signals.json>
# Output includes:  vkey blake3: <64 hex chars>
# Cross-check this digest against the published vkey fingerprint —
# the BLAKE3 ties the verification to the exact vkey bytes, not the
# `--circuit` label (which is cosmetic).

# 3a. JavaScript verifier — checks 1–3 (anchor hash, Ed25519,
#     BJJ-EdDSA-Poseidon). Exits 0 if all three accept.
cd verifiers/javascript
node verify.js verify-checkpoint --bundle <bundle.json>
# IMPORTANT: exit 0 from this command means checks 1–3 passed.
# It DOES NOT verify the Groth16 proof embedded in the bundle —
# the verifier prints the cargo invocation for step 2 above and
# expects the operator to run that separately. A "checks 1–3 passed
# + step 2 separately ran" outcome is the full court-grade JS-side
# verification result; without step 2, only the signatures and the
# anchor-hash domain reconstruction are confirmed.

# 4. RFC 3161 TSA receipt (no Olympus code involved)
openssl ts -verify -in <rfc3161_receipt.tsr> \
    -queryfile <(printf '%s' '<checkpoint_hash_hex>' | xxd -r -p) \
    -CAfile <tsa-ca-chain.pem>

# 5. Sigstore Rekor entry (no Olympus code involved at verify time;
#    if the bundle was produced with OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM
#    set, the metadata.set_verified=true field also asserts the SET
#    was verified at submission against the same log key).
rekor-cli get --uuid <rekor_uuid> --rekor_server https://rekor.sigstore.dev

# 6. OpenTimestamps + Bitcoin (no Olympus code involved, no Sigstore,
#    no TSA — just Bitcoin's public chain).
#    Requires metadata.phase == "upgraded" on the receipt row — the
#    upgrade cron (default every 6h, see OLYMPUS_ANCHOR_OTS_UPGRADE_-
#    INTERVAL_SECS) replaces the pending blob with the Bitcoin-anchored
#    form once the calendar's OP_RETURN transaction confirms. Verifying
#    a pending receipt with `ots verify` fails because no Bitcoin
#    commitment exists yet — that is the expected state for the first
#    few hours after submission.
#
#    Until #1182 merges: an honest operator should run this step
#    INDEPENDENTLY of the metadata.phase flag — the in-node cron does
#    not re-verify the upgraded blob's commitment chain matches the
#    pending receipt before marking phase=upgraded.
ots verify <receipt.ots> -f <(printf '%s' '<checkpoint_hash_hex>' | xxd -r -p)
```

A successful run of **every** step is the evidence package. Skipping
step 2 because step 3a printed "All JS-side checks passed" is a
common operator error and a real evidentiary gap. The Olympus node's
role in the chain ends after step 3a; steps 2 and 4–6 are checked
against parties Olympus has no control over (the published vkey, the
TSA, the Rekor log, the OTS calendar / Bitcoin chain).

---

## 4. Cryptographic primitives and why they are admissible

| Primitive | Standard | Peer review |
|---|---|---|
| BLAKE3 | BLAKE3 specification (O'Connor et al., 2020) | Wide adoption (cargo, GnuTLS, Wireguard tooling). No published attacks. |
| Ed25519 | RFC 8032 | Used by SSH, TLS 1.3, signal, GPG modern, US government in NIST FIPS-186-5. |
| Baby Jubjub EdDSA-Poseidon | iden3 reference impl (Belles-Muñoz, Whitehat et al.); permissive re-implementation at [`crates/babyjubjub-permissive`](../crates/babyjubjub-permissive). | Used by Polygon Hermez, Iden3, Privacy & Scaling Explorations zkSNARK stack. The permissive crate is byte-for-byte compatible with the iden3 reference (parity tests in [`crates/babyjubjub-permissive/`](../crates/babyjubjub-permissive)). |
| Poseidon (BN254) | Grassi, Khovratovich, Rechberger et al. 2019 (eprint 2019/458) | Standard ZK-friendly hash; deployed in Zcash, Polygon Hermez, Mina, dozens of zkSNARK projects. |
| Groth16 | Groth 2016 (eprint 2016/260) | The de-facto SNARK system since 2016; used in Zcash Sapling, Tornado Cash, every major Circom-based deployment. |
| RFC 3161 | IETF RFC 3161 (2001), updated by RFC 5816 | Accepted as evidence in US federal cases; **eIDAS-recognised in the EU** (Regulation 910/2014). |
| Sigstore Rekor | Sigstore project (Linux Foundation / OpenSSF) | Used by PyPI, npm, RubyGems, Kubernetes for package signing. Public, auditable. |
| OpenTimestamps | Todd 2016, currently maintained by the OTS project | Anchors via Bitcoin; Bitcoin transactions have themselves been admitted as evidence (e.g. *United States v. Costanzo*, 9th Cir. 2020). |

All primitives are open standards with public peer review. None rely
on novel or proprietary cryptography. Under the **Daubert** factors
(testability, peer review, error rates, general acceptance) every
component is in the well-accepted region of the digital-evidence
landscape.

---

## 5. Trusted setup and what it means

The Groth16 proving system requires a **trusted setup ceremony** —
parameters generated once, then used forever for that specific
circuit. Olympus uses a two-phase setup:

- **Phase 1 ("Powers of Tau")** — universal, multi-party. Olympus
  consumes the public Hermez/Polygon ceremony output
  (`powersOfTau28_hez_final_20.ptau`, BLAKE2b
  `89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c…`),
  which had ~140 independent contributors and is auditable at
  <https://github.com/iden3/snarkjs#7-prepare-phase-2>.
- **Phase 2** — per-circuit. For **v1.0** releases Olympus runs a
  multi-contributor ceremony orchestrated by
  [`proofs/phase2_ceremony.sh`](../proofs/phase2_ceremony.sh) with
  ≥ 3 independent parties. Each contributor's identity and
  `contributionHash` are recorded in
  [`proofs/keys/PROVENANCE.md`](../proofs/keys/PROVENANCE.md).
  The final zkey is committed publicly via a random-beacon step
  (`snarkjs zkey beacon`) so the final state is auditable post-hoc.

**Why this matters to a court:** even a malicious contributor cannot
forge proofs unless they collude with **every** other contributor.
Standard Groth16 security: an adversary needs to know the
trapdoor τ, which only exists if every Phase 1 contributor *and* every
Phase 2 contributor was malicious and shared their entropy.

### 5.1 v0.9 ceremony status — explicit honesty

**v0.9 ships with a single-contributor dev Phase 2 ceremony.** The
manifest in `proofs/keys/manifests/<circuit>_manifest.json` has
exactly one contribution, and `ceremony_id` starts with the literal
prefix `olympus-dev-`. Three runtime gates make this dev-mode-only
(PR [#1164](https://github.com/OlympusLedgerOrg/Olympus/pull/1164),
audit A-2/A-3/A-4):

- **A-2:** production startup (`OLYMPUS_ENV=production`) refuses any
  manifest with fewer than 3 contributors, exiting with code 2.
- **A-3:** production startup refuses any manifest whose coordinator
  pubkey equals the bootstrap pubkey (self-attestation).
- **A-4:** production startup refuses any manifest whose
  `ceremony_id` begins with `olympus-dev-`.

Dev mode (any `OLYMPUS_ENV` value other than `production`) logs each
as a warning and continues. **A v0.9 binary running in dev mode
against the shipped dev manifest is therefore explicitly not
court-ready**: the single dev contributor knows the trapdoor τ and
could forge proofs.

v1.0 ships with a real multi-contributor Phase 2 ceremony. Until
then, an operator who wants to run Olympus in a court-grade context
must:

1. Run [`proofs/phase2_ceremony.sh`](../proofs/phase2_ceremony.sh)
   with ≥ 3 independent contributors.
2. Replace the dev manifests in `proofs/keys/manifests/` with the
   new ones.
3. Add the coordinator pubkey to
   `OLYMPUS_BJJ_TRUSTED_ISSUERS_JSON`.
4. Boot the binary with `OLYMPUS_ENV=production` — startup will
   refuse if any of A-2/A-3/A-4 still fires.

For v0.9 binaries, the disclaimer at the top of
[`proofs/setup_circuits.sh`](../proofs/setup_circuits.sh) is the same
warning in code form — the single-contributor dev path is **not**
production-safe and should not be relied on in adversarial contexts.

---

## 6. Chain of custody — typical operator practice

A defensible operational pattern (recommended; not enforced by the
binary):

1. **Key persistence.** The Ed25519 signing key
   (`OLYMPUS_INGEST_SIGNING_KEY`) and the Baby Jubjub authority key
   (`OLYMPUS_BJJ_AUTHORITY_KEY`) are generated once on dedicated
   hardware, the public keys are registered with the parties who will
   verify (e.g. the agency's CA, a notary, the journalist's editor),
   and the private keys are stored in a hardware security module or
   sealed envelope. Ephemeral keys destroy the chain of custody for
   prior records.
2. **NTP-anchored timestamps.** The operating system clock is
   synchronised to a NIST or equivalent stratum-1 time source; logs
   record the NTP server in use at each checkpoint time.
3. **Append-only (with two documented mutation exceptions).**
   - No `UPDATE` or `DELETE` is performed on `peer_checkpoints`
     except the equivocation-detector's `equivocation_flag`.
   - `ingest_records` permits exactly two narrow UPDATEs: one-shot
     attach of `zk_bundle` (NULL → set) and a snapshot-column
     back-fill that fills in `(snapshot_root, snapshot_index,
     snapshot_size, snapshot_path)` for rows that pre-dated the
     persistence migration.
   - `anchor_receipts` is append-only for **identity** (id,
     anchor_kind, anchored_hash, checkpoint_id, target,
     submitted_at) — these fields never change — but the
     `receipt_blob` + `metadata` pair is mutated exactly once per
     OTS row when the upgrade cron transitions the row from
     `phase: pending` to `phase: upgraded` and substitutes the
     Bitcoin-anchored blob for the calendar's pending receipt.
     `verified_at` is bumped at the same moment. All three
     transitions are monotonic (pending → upgraded; NULL → set;
     never reverse) and never lose data — the original RFC 3161 /
     Rekor blobs are preserved verbatim.
   - `own_checkpoints` is strictly INSERT-only (PR
     [#1165](https://github.com/OlympusLedgerOrg/Olympus/pull/1165))
     plus, on the fix-PR landing, a `UNIQUE (ledger_root, tree_size)`
     constraint with `ON CONFLICT DO NOTHING` ([fix in flight at
     #1187](https://github.com/OlympusLedgerOrg/Olympus/pull/1187)).
     There is no UPDATE or DELETE path through application code.
4. **Bundled receipts.** Every published checkpoint can be exported
   via the admin endpoint `GET /api/admin/checkpoints/{id}/bundle`
   (added by PR
   [#1168](https://github.com/OlympusLedgerOrg/Olympus/pull/1168)).
   The bundle includes the four cryptographic layers (anchor hash,
   Ed25519, BJJ-EdDSA-Poseidon, Groth16) and the three external
   anchor receipts (via the existing `/anchors?checkpoint_id=<id>`
   endpoint). Bundle schema:
   [`docs/checkpoint-bundle-schema.md`](checkpoint-bundle-schema.md).
   For court-grade bundles, wait until the OTS rows have
   `metadata.phase == "upgraded"` before publishing — bundling a
   pending OTS receipt forces the verifier to either trust the
   calendar separately or wait for the cron, both of which weaken
   the "no trust in any private party" claim.
5. **Periodic public posting.** A digest of the latest checkpoint
   ID + ledger root is published at a fixed cadence (RSS,
   mailing-list, governmental gazette, etc.) so opposing counsel can
   cite a public record predating the dispute.

### 6.1 Bundle byte-identity and BJJ key rotation

The Ed25519 signature in the bundle is **pinned at checkpoint
emission time** in the `own_checkpoints` row (PR #1168 + migration
0042); the BJJ authority pubkey coordinates `(Ax, Ay)` are also
written into the bundle at export time from the *current* in-memory
key, with a Poseidon-hash check that they match the row's stored
`authority_pubkey_hash`. The bundle producer refuses to emit (409
Conflict) if the current in-memory BJJ key doesn't match the row's
stored hash.

Consequence for rotation:

- Re-exporting an unchanged checkpoint row produces a byte-identical
  bundle.
- After rotating the BJJ authority key, the bundle producer can no
  longer export old checkpoints — they bound to the *old* pubkey,
  whose Poseidon hash no longer matches the live key. To preserve
  audit access, operators must retain the old BJJ private key (e.g.
  in escrow) or export and archive all in-flight bundles before
  rotating.
- After rotating the Ed25519 ingest signing key, the embedded
  signature in the bundle is still verifiable against the
  `ed25519_pubkey_hex` field (which records the *issuing* pubkey).
  But there is **no in-band revocation mechanism for compromised old
  keys** — if an old Ed25519 private key is later stolen, old
  bundles still verify against the embedded pubkey. Operators must
  publish an out-of-band revocation notice (e.g. governmental
  gazette, public mailing-list) and downstream verifiers must
  cross-check the bundle's `ed25519_pubkey_hex` against the live
  revocation list. **An in-band PKI revocation mechanism is a v1.0
  roadmap item, not a v0.9 promise.**

The audit reports in
[`docs/SECURITY_AUDIT_REPORT_V3.md`](SECURITY_AUDIT_REPORT_V3.md)
describe the threat model the code is hardened against; the
2026-06-02 follow-up audit is summarised inline in §0 above.

---

## 7. What Olympus does NOT prove

- **Identity of the submitter.** A signature only proves a key
  signed; binding a key to a real person is an out-of-band procedure
  (notary, government ID, key-signing ceremony).
- **Truth of the content.** Inclusion of a document in the ledger
  does not assert the document is accurate; only that the document,
  byte-for-byte, was in this state when committed.
- **Continuity of the federation.** If every Olympus node is offline,
  no new checkpoints are produced. Existing receipts (especially OTS
  → Bitcoin) remain verifiable indefinitely.
- **Revocation of compromised signing keys.** See §6.1. v0.9 has no
  in-band mechanism for revoking a previously-published Ed25519 or
  BJJ pubkey; revocation is an out-of-band publishing concern.
- **Trustworthiness of the v0.9 ceremony.** See §0 and §5.1. v0.9
  ships with a single-contributor dev ceremony; production startup
  refuses to run against it.

---

## 8. Anchoring infrastructure — file-level pointers for the expert witness

| Concern | Source |
|---|---|
| `anchor_receipts` schema | [`migrations/0026_add_anchor_receipts.sql`](../migrations/0026_add_anchor_receipts.sql) |
| `own_checkpoints` schema (PR #1165) | [`migrations/0041_add_own_checkpoints.sql`](../migrations/0041_add_own_checkpoints.sql) + [`migrations/0042_own_checkpoints_ed25519_sig.sql`](../migrations/0042_own_checkpoints_ed25519_sig.sql) |
| Own-checkpoint producer | [`src-tauri/src/anchoring/own_checkpoint.rs`](../src-tauri/src/anchoring/own_checkpoint.rs) |
| Anchor cron | [`src-tauri/src/anchoring/cron.rs`](../src-tauri/src/anchoring/cron.rs) |
| RFC 3161 client implementation | [`src-tauri/src/anchoring/rfc3161.rs`](../src-tauri/src/anchoring/rfc3161.rs) |
| RFC 3161 TSTInfo binding verification (audit M-A1) | [`src-tauri/src/anchoring/tstinfo.rs`](../src-tauri/src/anchoring/tstinfo.rs) |
| Sigstore Rekor client | [`src-tauri/src/anchoring/rekor.rs`](../src-tauri/src/anchoring/rekor.rs) |
| OpenTimestamps client (submit + upgrade) | [`src-tauri/src/anchoring/ots.rs`](../src-tauri/src/anchoring/ots.rs) |
| OTS binary-format walker (audit M-A3 / PR #1166) | [`src-tauri/src/anchoring/ots_format.rs`](../src-tauri/src/anchoring/ots_format.rs) |
| OTS upgrade cron | [`src-tauri/src/anchoring/upgrade_cron.rs`](../src-tauri/src/anchoring/upgrade_cron.rs) |
| Domain-separated checkpoint digest | `checkpoint_anchor_hash` in [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) |
| Admin bundle export endpoint (PR #1168) | `GET /api/admin/checkpoints/{id}/bundle` in [`src-tauri/src/api/checkpoint_bundle.rs`](../src-tauri/src/api/checkpoint_bundle.rs) |
| Bundle schema specification | [`docs/checkpoint-bundle-schema.md`](checkpoint-bundle-schema.md) |
| Per-anchor receipt export | `GET /anchors/{id}/receipt` returns the raw receipt with the correct Content-Type for offline verification. |
| Cross-language verifiers | [`verifiers/{rust,javascript}/`](../verifiers/) |
| Standalone Groth16 verifier binary (PR #1167) | [`verifiers/rust/src/bin/verify.rs`](../verifiers/rust/src/bin/verify.rs) |
| JS `verify-checkpoint --bundle` (PR #1168) | [`verifiers/javascript/verify.js`](../verifiers/javascript/verify.js) |
| Trusted setup ceremony script | [`proofs/phase2_ceremony.sh`](../proofs/phase2_ceremony.sh) |
| Dev / single-contributor setup script | [`proofs/setup_circuits.sh`](../proofs/setup_circuits.sh) |
| Setup provenance manifest | [`proofs/keys/PROVENANCE.md`](../proofs/keys/PROVENANCE.md) |
| Ceremony manifest verification (audit A-2/A-3/A-4) | [`src-tauri/src/startup.rs`](../src-tauri/src/startup.rs) — `apply_extra_prod_gates`, `verify_ceremony_manifests` |
| Federation checkpoint binding (audit F-1 / F-RT-1) | [`src-tauri/src/federation/verify.rs`](../src-tauri/src/federation/verify.rs) — `verify_checkpoint_proof` |

---

## 9. Contact points for verification

- **General verification questions / sample bundle requests:** open an
  issue in the Olympus repository.
- **Disputed proof / counterexample:** file a Security report per
  [`SECURITY.md`](../SECURITY.md). Olympus operators are bound by the
  security disclosure policy described therein; a proof that
  contradicts the audit log is treated as a critical incident.
- **Expert testimony:** Olympus operators do not provide expert
  witnesses for or against individual proofs. The cross-language
  verifiers are designed so that an opposing party's own expert can
  do the verification on their own equipment without trusting any
  Olympus-controlled software.

---

_This document is updated alongside the codebase. Last refreshed at
the same git commit as the rest of v0.9 (see `git log -1` of this
file). Red-team reconciliation: 2026-06-02._
