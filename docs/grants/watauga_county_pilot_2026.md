# Grant Concept: Olympus Public Records Pilot

**Working title:** Restoring institutional trust through cryptographically verifiable public records.

This document is a grant concept note, not a signed pilot agreement. It describes how the current Olympus prototype could be used in a county or municipal public-records setting once a partner and funding source are secured.

## 1. Executive Summary

Public records are often distributed as PDFs or database exports. Citizens, journalists, auditors, and public servants usually have no simple way to prove that a downloaded copy is exactly the same file that was originally published or approved.

Olympus is an open-source proof layer for files and public records. The current local prototype can start from the Windows launcher, hash files locally with BLAKE3, commit files through an authenticated ingest path, verify committed hashes, reject bad API keys, reject already committed records, and export proof bundles for later verification.

The grant goal is to harden this working prototype into a pilot-ready public-records verification workflow.

## 2. Statement of Need

Government and institutional records are increasingly digital, but the trust model is still mostly social and procedural:

- people trust that a portal serves the same file that was originally approved
- administrators trust that storage systems were not silently changed
- auditors often need logs, screenshots, or internal access instead of portable cryptographic evidence

Olympus addresses this gap by making the integrity of a record independently checkable from a cryptographic digest and proof bundle.

## 3. Current Prototype

The repository currently demonstrates:

- local startup with `start.bat` (Windows) or `./start.sh` (macOS / Linux / WSL)
- self-contained Tauri 2 desktop app: embedded Axum HTTP server + embedded PostgreSQL (pg_embed), no external services
- React + Vite public UI
- local BLAKE3 hashing in the browser before verification
- hash-only verification, so normal checks do not need to upload file contents
- authenticated ingest into the ledger
- duplicate/already committed record handling
- bad API key rejection
- public stats polling
- downloadable and re-checkable proof bundles

The current demo release is documented in the root-level `DEMO.md` and `GRANTS.md`.

## 4. Proposed Pilot Workflow

A municipal or county pilot could run Olympus as a notary sidecar beside an existing public-records portal:

1. A clerk or operator publishes a public document, such as meeting minutes, budgets, agendas, or ordinances.
2. Olympus hashes the document and commits the hash to the append-only ledger.
3. The public portal links to the document and its proof bundle.
4. A citizen, journalist, or auditor downloads the file and independently verifies that the hash and proof bundle match the committed ledger record.

The intent is to avoid replacing the existing portal. The pilot would add a verification layer around records the institution already publishes.

## 5. Candidate Pilot Partner

Watauga County, North Carolina is an example candidate for framing and outreach because county records such as budgets, agendas, and meeting minutes are concrete, public, and easy for reviewers to understand.

This document does not claim Watauga County has agreed to a pilot. A grant-funded next step would be partner outreach, workflow discovery, and a small shadow deployment using non-sensitive public documents.

## 6. Differentiation

Olympus should be evaluated as a proof layer, not a document management system:

- **Privacy-preserving verification:** users can verify from a hash without re-uploading private file contents.
- **Portable evidence:** proof bundles can be saved and checked outside the main UI.
- **Tamper-evident records:** committed entries are bound into an append-only Merkle structure.
- **Practical local demo:** the current workflow can be launched and demonstrated on a Windows development machine.
- **Open-source path:** protocol, API, UI, docs, and verifier code live in this repository.

## 7. Risks and Mitigations

- **Risk:** under-resourced public agencies may not have staff for complex infrastructure.
  **Mitigation:** keep the pilot scoped to a sidecar workflow around already-public documents, with simple operator steps and clear verifier docs.

- **Risk:** the current prototype is locally verified, not production certified.
  **Mitigation:** use grant funding for hosted CI, external security review, deployment hardening, and documented release packaging.

- **Risk:** reviewers may confuse proof-of-integrity with confidentiality.
  **Mitigation:** state clearly that Olympus proves file integrity and ledger inclusion; it does not make public documents secret.

## 8. Proposed Grant Milestones

1. **Pilot packaging:** produce a clean demo package with sample files, proof bundles, screenshots, and a short video.
2. **Security review:** obtain outside review of the ingest, hashing, proof bundle, and verification paths.
3. **Hosted pilot:** deploy a small hosted verifier for public sample records.
4. **Partner workflow:** document a clerk/operator workflow for publishing new records with proof bundles.
5. **Verifier tooling:** improve CLI and browser-based verification for non-technical reviewers.

## 9. Evaluation Metrics

Use achievable pilot metrics rather than production-scale claims:

- time for a reviewer to verify a known sample file
- successful verification of a small corpus of public PDFs
- successful duplicate and bad-key rejection during operator testing
- proof bundle portability across machines/browsers
- documented operator steps that do not require cryptography knowledge

## 10. Funding Use

Grant funding would support:

- engineering time for reliability, packaging, and verifier polish
- hosted infrastructure for a public demo/pilot
- third-party security review
- documentation and sample package production
- outreach to a public-records partner
