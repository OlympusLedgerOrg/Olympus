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

## 1. The single sentence

> "On date `T`, an Olympus node produced a Merkle root `R` covering
> tree size `N`, signed it with key `K`, and registered the existence
> of that signed state with three independent third-party services
> (`RFC 3161`, `Sigstore Rekor`, `OpenTimestamps`)."

Everything below is a structured way of demonstrating that single
sentence and showing how each link in the chain resists tampering.

---

### 1.1 What the v0.9 binary actually enforces online

Anchoring infrastructure lands in stages. This callout pins which
checks the **running node** enforces in v0.9 versus which rely on
**offline tools** (`openssl ts -verify`, `rekor-cli`, `ots verify`).
If you are presenting a bundle in court, both layers matter — online
enforcement makes the receipt fresh and non-replayable; offline tools
re-verify the cryptography on the opposing party's own hardware.

> **Version scope — read first.** The in-node checks in the left column
> land with PRs **#1058** and **#1061**. A binary built *before* those merge
> performs **none** of them online: it submits each receipt and stores it
> verbatim — no nonce-echo comparison, no Rekor SET verification, no OTS
> upgrade cron — and the `metadata.nonce_echo_verified`, `metadata.set_verified`,
> and `metadata.phase` fields referenced below will be **absent** from real
> rows. On such a build the entire evidentiary weight rests on the **offline**
> tools in the right column. Confirm your node includes #1058 + #1061 before
> relying on the online column or the `metadata.*` checklist at the end of
> this section.

| Anchor | Online (in-node) check | Offline tool — required for full proof |
|---|---|---|
| **RFC 3161 TSA** | Submission, response sanity check, **nonce-echo verification** (audit M-A1 — refuses receipts that don't echo the request nonce, defeats TSR splicing) | `openssl ts -verify` against the TSA cert chain (TSA signature, message imprint, cert validity at `T`) |
| **Sigstore Rekor** | Submission, response shape parse, **signedEntryTimestamp ECDSA-P-256 verification** when `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set (audit M-A2 — refuses unsigned-by-log receipts). When unset, receipt is stored with `metadata.set_verified=false` and a startup warning is logged. | `rekor-cli get --uuid <UUID>` to confirm the entry is still in the log + verifiable inclusion proof |
| **OpenTimestamps** | Submission (pending receipt) + **periodic upgrade cron** (audit M-A3, default 6h) that re-fetches each pending receipt from its originating calendar and persists the Bitcoin-anchored form. `metadata.phase` transitions `pending → upgraded`. | `ots verify <receipt>` — requires `metadata.phase == "upgraded"` (the cron has run and replaced the blob). Pending receipts fail `ots verify` because no Bitcoin commitment exists yet. |

**Operator checklist before relying on the bundle in court:**

- [ ] `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set to the Rekor instance's log public key. Without it, the SET is not verified at submission time and the bundle's freshness rests on the live `rekor-cli get` call alone.
- [ ] At least one anchor cron tick has elapsed since each receipt was submitted (otherwise the OTS row may still be pending).
- [ ] The receipt rows in `anchor_receipts` show `metadata.nonce_echo_verified=true` (RFC 3161), `metadata.set_verified=true` (Rekor), and `metadata.phase='upgraded'` (OTS). Anything else is a gap to flag to opposing counsel before they do.

---

## 2. The five claims, layered

| # | Claim | What proves it |
|---|---|---|
| 1 | **The hash is well-formed** | BLAKE3 digest of a canonical (JCS/RFC 8785) representation of the source data. Same bytes on every machine. |
| 2 | **The hash is included in a Merkle tree at a specific index** | Groth16 zero-knowledge inclusion proof produced by the `document_existence` circuit (`proofs/circuits/document_existence.circom`). Verifiable against the published verification key in `proofs/keys/verification_keys/document_existence_vkey.json`. |
| 3 | **The Merkle root was signed by the Olympus node** | Ed25519 signature over `(OLY:CHECKPOINT_ANCHOR:V1 \| ledger_root \| tree_size \| timestamp \| authority_pubkey_hash \| BJJ_sig)`. Verifiable with the node's published Ed25519 verifying key. |
| 4 | **The signed checkpoint existed by the timestamp** | Three independent anchors, see §1.1 for which checks fire online vs. offline: <ul><li>**RFC 3161 TSA** — accredited authority signs `SHA-256(checkpoint)` at time `T`. Olympus enforces nonce-echo at submission; full cert-chain verification with `openssl ts -verify -in <receipt> -queryfile <hash> -CAfile <tsa-cert-chain>`.</li><li>**Sigstore Rekor** — append-only public transparency log. SET ECDSA verification at submission when `OLYMPUS_ANCHOR_REKOR_PUBKEY_PEM` is set; independently verifiable via `rekor-cli get --uuid <UUID>`.</li><li>**OpenTimestamps** — pending receipts are upgraded to Bitcoin-anchored form by a background cron (default 6h cadence). Once `metadata.phase == "upgraded"`, the receipt verifies against Bitcoin with `ots verify <receipt> -f <file>`. No trust in any private party required.</li></ul> |
| 5 | **The redaction was correct** _(when applicable)_ | Groth16 proof from the `redaction_validity` circuit: shows the redacted commitment is derived only by applying a permitted mask to the original tree's leaves; nothing else was modified. Independent of the document content. |

Each row is independently verifiable. Any single row holding makes
the corresponding claim true; **the full chain together is robust to
single-point compromise** of any one of: the Olympus node, the TSA,
the Rekor log, or the OTS calendar.

---

## 3. Independent verification — minimal commands

The verifier should not run Olympus's own binary, because that would
delegate trust back to Olympus. Use the cross-language verifiers in
[`verifiers/`](../verifiers/) instead — independent reference
implementations in Rust and JavaScript that re-derive the protocol's
primitives so the math is checkable without trusting any Olympus code.

```bash
# 1. BLAKE3 canonical digest (matches Olympus's hash on any machine)
echo -n '<canonical_json_bytes>' | b3sum

# 2. Groth16 verification — Rust verifier
cd verifiers/rust
cargo run --release -- verify \
    --circuit document_existence \
    --vkey ../../proofs/keys/verification_keys/document_existence_vkey.json \
    --proof <proof.json> \
    --public-signals <signals.json>

# 3. Ed25519 signature on the checkpoint commitment — JavaScript verifier
cd verifiers/javascript
node verify.js verify-checkpoint --bundle <bundle.json>

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
ots verify <receipt.ots> -f <(printf '%s' '<checkpoint_hash_hex>' | xxd -r -p)
```

A successful run of each step is the evidence package. The Olympus
node's role in the chain ends after step 3; steps 4–6 are checked
against parties Olympus has no control over.

---

## 4. Cryptographic primitives and why they are admissible

| Primitive | Standard | Peer review |
|---|---|---|
| BLAKE3 | BLAKE3 specification (O'Connor et al., 2020) | Wide adoption (cargo, GnuTLS, Wireguard tooling). No published attacks. |
| Ed25519 | RFC 8032 | Used by SSH, TLS 1.3, signal, GPG modern, US government in NIST FIPS-186-5. |
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
- **Phase 2** — per-circuit. For v1.0 releases Olympus runs a
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

For v0.9 binaries, see the disclaimer at the top of
`proofs/setup_circuits.sh` — the single-contributor dev path is
**not** production-safe and should not be relied on in adversarial
contexts.

---

## 6. Chain of custody — typical operator practice

A defensible operational pattern (recommended; not enforced by the
binary):

1. **Key persistence.** The Ed25519 signing key
   (`OLYMPUS_INGEST_SIGNING_KEY`) is generated once on dedicated
   hardware, the public key is registered with the parties who will
   verify (e.g. the agency's CA, a notary, the journalist's editor),
   and the private key is stored in a hardware security module or
   sealed envelope. Ephemeral keys destroy the chain of custody for
   prior records.
2. **NTP-anchored timestamps.** The operating system clock is
   synchronised to a NIST or equivalent stratum-1 time source; logs
   record the NTP server in use at each checkpoint time.
3. **Append-only (with one documented exception).** No `UPDATE` or
   `DELETE` is performed on `ingest_records` or `peer_checkpoints`.
   `anchor_receipts` is append-only for **identity** (id, anchor_kind,
   anchored_hash, checkpoint_id, target, submitted_at) — these fields
   never change — but the `receipt_blob` + `metadata` pair is mutated
   exactly once per OTS row when the upgrade cron transitions the
   row from `phase: pending` to `phase: upgraded` and substitutes
   the Bitcoin-anchored blob for the calendar's pending receipt.
   `verified_at` is bumped at the same moment. Both transitions are
   monotonic (pending → upgraded; null → set) and never lose data —
   the original RFC 3161 / Rekor blobs are preserved verbatim.
4. **Bundled receipts.** Every published checkpoint includes the
   three external anchor receipts (`/anchors?checkpoint_id=<id>`) in
   the published bundle, so third-party verification needs no further
   contact with the Olympus node. For court-grade bundles, wait until
   the OTS rows have `metadata.phase == "upgraded"` before publishing
   — bundling a pending OTS receipt forces the verifier to either
   trust the calendar separately or wait for the cron, both of which
   weaken the "no trust in any private party" claim.
5. **Periodic public posting.** A digest of the latest checkpoint
   ID + ledger root is published at a fixed cadence (RSS,
   mailing-list, governmental gazette, etc.) so opposing counsel can
   cite a public record predating the dispute.

The audit reports in [`docs/SECURITY_AUDIT_REPORT_V3.md`](SECURITY_AUDIT_REPORT_V3.md)
describe the threat model the code is hardened against.

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

---

## 8. Anchoring infrastructure — file-level pointers for the
   expert witness

| Concern | Source |
|---|---|
| `anchor_receipts` schema | [`migrations/0026_add_anchor_receipts.sql`](../migrations/0026_add_anchor_receipts.sql) |
| RFC 3161 client implementation | [`src-tauri/src/anchoring/rfc3161.rs`](../src-tauri/src/anchoring/rfc3161.rs) |
| Sigstore Rekor client | [`src-tauri/src/anchoring/rekor.rs`](../src-tauri/src/anchoring/rekor.rs) |
| OpenTimestamps client | [`src-tauri/src/anchoring/ots.rs`](../src-tauri/src/anchoring/ots.rs) |
| Domain-separated checkpoint digest | `checkpoint_anchor_hash` in [`src-tauri/src/anchoring/mod.rs`](../src-tauri/src/anchoring/mod.rs) |
| Bundle export endpoint | `GET /anchors/{id}/receipt` returns the raw receipt with the correct Content-Type for offline verification. |
| Cross-language verifiers | [`verifiers/{rust,javascript}/`](../verifiers/) |
| Trusted setup ceremony script | [`proofs/phase2_ceremony.sh`](../proofs/phase2_ceremony.sh) |
| Setup provenance manifest | [`proofs/keys/PROVENANCE.md`](../proofs/keys/PROVENANCE.md) |

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
file)._
