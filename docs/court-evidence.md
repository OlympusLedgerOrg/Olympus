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

## 2. The five claims, layered

| # | Claim | What proves it |
|---|---|---|
| 1 | **The hash is well-formed** | BLAKE3 digest of a canonical (JCS/RFC 8785) representation of the source data. Same bytes on every machine. |
| 2 | **The hash is included in a Merkle tree at a specific index** | Groth16 zero-knowledge inclusion proof produced by the `document_existence` circuit (`proofs/circuits/document_existence.circom`). Verifiable against the published verification key in `proofs/keys/verification_keys/document_existence_vkey.json`. |
| 3 | **The Merkle root was signed by the Olympus node** | Ed25519 signature over `(OLY:CHECKPOINT_ANCHOR:V1 \| ledger_root \| tree_size \| timestamp \| authority_pubkey_hash \| BJJ_sig)`. Verifiable with the node's published Ed25519 verifying key. |
| 4 | **The signed checkpoint existed by the timestamp** | Three independent anchors: <ul><li>**RFC 3161 TSA** — accredited authority signs `SHA-256(checkpoint)` at time `T`. Verifiable with `openssl ts -verify -in <receipt> -queryfile <hash> -CAfile <tsa-cert-chain>`.</li><li>**Sigstore Rekor** — append-only public transparency log. Verifiable by anyone via `rekor-cli get --uuid <UUID>`.</li><li>**OpenTimestamps** — once upgraded (~hours after submission), the receipt anchors to a specific Bitcoin block header. Verifiable with `ots verify <receipt> -f <file>`. No trust in any private party required.</li></ul> |
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

# 5. Sigstore Rekor entry (no Olympus code involved)
rekor-cli get --uuid <rekor_uuid> --rekor_server https://rekor.sigstore.dev

# 6. OpenTimestamps + Bitcoin (no Olympus code involved, no Sigstore,
#    no TSA — just Bitcoin's public chain)
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
3. **Append-only.** No `UPDATE` or `DELETE` is performed on
   `ingest_records`, `peer_checkpoints`, or `anchor_receipts` rows;
   the schema is enforced append-only at the application layer.
4. **Bundled receipts.** Every published checkpoint includes the
   three external anchor receipts (`/anchors?checkpoint_id=<id>`) in
   the published bundle, so third-party verification needs no further
   contact with the Olympus node.
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
