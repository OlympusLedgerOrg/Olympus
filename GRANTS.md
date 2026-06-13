# Olympus Grant Brief

## One-Sentence Pitch

Olympus is open-source, public-interest infrastructure for proving that a document existed at a point in time and has not been silently altered — without trusting the institution that published it.

## What This Is

Olympus turns a file into a portable cryptographic receipt. You commit only the file's fingerprint to an append-only ledger and export a proof bundle that anyone can re-check later. The institution that published the document does not have to be trusted, and the document's contents never have to be uploaded just to verify it.

This brief separates two things deliberately:

- **What works in the demo today** — the commit → verify → portable proof bundle loop, plus an independent offline verifier.
- **What is implemented in-tree but audit-/ceremony-gated** — the zero-knowledge proof system, multi-operator Tor federation, and external anchoring.

Keeping that line crisp is the point of this document. The demonstrated core is real and runnable now; the advanced layers are built but are the maturity-and-audit target of this grant.

## Problem

Public records, compliance documents, contracts, meeting minutes, audits, and institutional files are usually distributed as ordinary PDFs or database exports. Once published, a reader has no simple way to independently prove that a downloaded copy is the exact file that was originally committed — and no way to tell if it was quietly changed afterward.

Most systems still ask people to trust the institution, the website, or a dashboard. Olympus shifts that trust into cryptographic receipts that can be verified later, by anyone, including offline.

## What Works Today

These steps are demonstrated end-to-end in the working prototype (see [DEMO.md](./DEMO.md)):

- double-click startup (`start.bat` on Windows, `./start.sh` on macOS / Linux / WSL)
- local BLAKE3 file hashing in the browser, before anything is uploaded
- hash-only verification, so private files are never uploaded just to check whether they are committed
- authenticated file ingest into an append-only ledger
- duplicate / already-committed record rejection
- bad API key rejection
- successful ledger verification for committed files
- downloadable proof bundles
- proof bundle verification from JSON or a small proof package file
- **independent offline verification** of a proof bundle via the standalone verifiers in [`verifiers/`](./verifiers/) (Rust and JavaScript), with no running app required

This is the honest demonstrated surface. The demo does **not** exercise the ZK, federation, or anchoring layers below — those are covered by the automated test suite.

## Implemented In-Tree, Audit-/Ceremony-Gated

These are built and live in the repository, but are not part of the default demo build and are the work this grant would harden and validate:

- **Zero-knowledge proofs (Groth16).** Three circuits — document existence, non-existence, and redaction validity — are compiled into and callable from the desktop binary (the `prover` feature is on by default), exposed via the scope-gated `/zk/prove` and `/zk/verify` routes. **The current proving/verification keys are single-contributor development artifacts** (Hermez Phase 1 powers-of-tau, power 20, generated 2026-06-08). A multi-contributor Phase 2 ceremony is the remaining blocker before these proofs should be treated as production-grade. This is stated plainly because it is the most important caveat in the project.
- **Multi-operator federation over Tor.** Hidden-service transport, peer trust management, checkpoint gossip, and equivocation detection are implemented in-tree **behind the opt-in `federation` cargo feature** (`--features federation`). It is **off in the default build**, and when enabled it depends on the live Tor network.
- **External anchoring.** RFC 3161 (accredited timestamping authorities), Sigstore Rekor (public transparency log), and Bitcoin via OpenTimestamps are implemented and wired into the server, giving outside parties verification paths that do not require trusting the Olympus operators. Live-network validation against real TSAs, Rekor, and OTS calendars is part of the pilot work, not yet a demonstrated end-to-end claim.

## Why It Is Different

Olympus is not a document storage app. It is a proof layer.

- **Privacy-preserving:** verification can happen from a hash, so private files do not need to be uploaded just to check whether they are committed.
- **Portable:** proof bundles can move outside the UI and be verified independently — including offline today, via the standalone verifiers.
- **Tamper-evident:** committed records are bound into an append-only Merkle structure; dual BLAKE3 + Poseidon roots and Ed25519-signed shard headers anchor ledger integrity.
- **Practical:** the local prototype launches and runs on a normal desktop with no external services.
- **Sits beside, not over:** the workflow can run as a notary sidecar next to existing document portals instead of replacing them.

## Framing for Reviewers

The demonstrated core and the gated layers above are the same for every reviewer. Two grant audiences emphasize different parts of it.

### Press freedom & human rights

Olympus gives journalists, FOIA/open-records users, human-rights defenders, and civil-society organizations a way to prove that a leaked, published, or obtained document is the exact artifact it claims to be — and to do so without trusting, or even being online with, the institution that produced it. Offline and out-of-band verification, redaction proofs that show *what* was withheld without revealing it, and trust distributed across independent operators (federation/anchoring) are the layers that matter most for adversarial, repressive, or censored environments. These are precisely the audit-/ceremony-gated layers this grant would mature.

### Civic transparency & public records

The same machinery lets institutions publish cryptographic receipts that citizens, journalists, and auditors can verify independently. A municipal or county pilot could run Olympus as a notary sidecar beside an existing public-records portal — a clerk commits meeting minutes, budgets, agendas, or ordinances, and the public verifies the published file against the ledger. See [`docs/grants/watauga_county_pilot_2026.md`](./docs/grants/watauga_county_pilot_2026.md) for a concrete pilot concept note.

## Funding Would Unlock

- a multi-contributor Phase 2 trusted-setup ceremony (the remaining ZK blocker)
- third-party cryptographic / security review
- live-network anchoring validation against real TSAs, Rekor, and OTS calendars
- hardened proof bundle format and verifier tooling
- a hosted pilot deployment for a real public-records or document-integrity workflow
- public documentation and sample packages for non-technical reviewers
- reliability work for packaging, startup, local databases, and recovery

## Near-Term Proof Points

To hand a reviewer something concrete, package these together:

- [DEMO.md](./DEMO.md)
- demo release link or attached recording
- one sample PDF
- one proof bundle JSON generated from that PDF
- screenshots of commit, verify, duplicate rejection, and proof verification
- this grant brief

## Current Status

Olympus is an active prototype. The demonstrated path — startup, ingest, verify, bad-key rejection, duplicate rejection, proof-bundle export, and independent offline bundle verification — works locally today. The ZK proof system, Tor federation, and external anchoring are implemented in-tree and are the maturity-and-audit target of this grant; the single largest gate is the multi-contributor trusted-setup ceremony for the ZK keys.
