# Olympus Grant Brief

## One-Sentence Pitch

Olympus lets anyone prove that a file existed and has not changed by committing only its cryptographic fingerprint to an append-only ledger and exporting a portable Merkle proof bundle.

## Problem

Public records, compliance documents, contracts, meeting minutes, audits, and institutional files are usually distributed as ordinary PDFs or database exports. Once published, the public has no simple way to independently prove that a downloaded copy is the exact same file that was originally committed.

Most systems still ask people to trust the institution, the website, or a dashboard. Olympus shifts that trust into cryptographic receipts that can be verified later.

## Working Prototype

The current prototype already demonstrates the core grant-relevant workflow:

- double-click Windows startup
- local BLAKE3 file hashing
- hash-only verification for privacy-preserving checks
- authenticated file ingest into an append-only ledger
- duplicate/already committed record rejection
- bad API key rejection
- successful ledger verification for committed files
- downloadable proof bundles
- proof bundle verification from JSON or a small proof package file
- optional admin-controlled EVM SBT queue/flush endpoints for deployment mirrors

Demo guide and video link: [DEMO.md](./DEMO.md)

## Why It Is Different

Olympus is not a document storage app. It is a proof layer.

- **Privacy-preserving:** verification can happen from a hash, so private files do not need to be uploaded just to check whether they are committed.
- **Portable:** proof bundles can move outside the UI and still be verified.
- **Tamper-evident:** committed records are bound into an append-only Merkle structure.
- **Practical:** the local prototype can be launched and tested on a normal Windows machine.
- **Public-sector friendly:** the workflow can sit beside existing document portals instead of replacing them.

## Who Benefits

- municipal clerks publishing meeting minutes, budgets, ordinances, and agendas
- journalists checking whether a public file changed after publication
- auditors validating chain-of-custody for sensitive documents
- grant programs funding civic trust, open records, and transparency infrastructure
- organizations that need evidence without exposing private file contents

## Suggested Grant Framing

Olympus should be presented as civic trust infrastructure, not as a generic ledger project.

Strong framing:

> Olympus is a privacy-preserving proof layer for public documents. It lets institutions publish cryptographic receipts that citizens, journalists, and auditors can verify independently, even offline, without trusting the original website.

For today, phrase "offline" as a roadmap or verifier goal unless the reviewer is using one of the local verifier paths. The live demo is a local web app and API-backed workflow, with proof bundles designed to become portable verification artifacts.

Avoid leading with implementation details like Rust, Go, sparse trees, or API internals. Those matter after the reviewer understands the civic problem.

## Funding Would Unlock

- hosted pilot deployment for a real public-records workflow
- third-party cryptographic/security review
- hardened proof bundle format and verifier tooling
- public documentation and sample packages for non-technical reviewers
- integrations for existing document portals and clerk workflows
- reliability work for packaging, startup, local databases, and recovery

## Near-Term Proof Points

Before submitting this to a grant reviewer, package these together:

- [DEMO.md](./DEMO.md)
- demo release link or attached recording
- one sample PDF
- one proof bundle JSON generated from that PDF
- screenshots of commit, verify, duplicate rejection, and proof verification
- this grant brief

## Current Status

Olympus is an active prototype. The demo path is working locally: startup, ingest, verify, bad-key rejection, duplicate rejection, and proof-bundle verification. The next milestone is making that path easy for outside reviewers to experience without needing developer setup knowledge.
