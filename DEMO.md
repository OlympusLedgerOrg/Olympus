# Olympus Demo Guide

This demo shows the working Olympus proof loop without asking a reviewer to understand the full codebase first.

## Demo Video

There is currently no published screen recording. The former
`olympus-demo-2026-05-14-r2` release and the local `.mp4` it was cut from are
both gone, so this guide is deliberately self-contained: the reviewer
walkthrough below reproduces the whole loop from a fresh install, and it is the
authoritative demo path.

If you would rather run a prebuilt binary than build the desktop app, the
[Build Week judge-demo v3 release](https://github.com/OlympusLedgerOrg/Olympus/releases/tag/build-week-2026-demo-v3)
ships network-free binaries for Windows x64, Linux x64, and macOS Apple Silicon.
There is no Intel macOS asset; on that hardware, build from source. See
[`JUDGES.md`](./JUDGES.md) for the five-minute version of that path.

Either way, the story is the same: double-click start, ingest a file, verify it, reject a bad API key, reject an already committed record, download a proof bundle, and verify that proof bundle.

This walkthrough is a local verification path, not a production certification. Automated GitHub CI is not treated as the release gate for this demo package.

**Scope of this demo:** the walkthrough below exercises the commit / verify / proof-bundle loop only. The zero-knowledge proof system (`/zk/prove`, `/zk/verify`) and external anchoring (RFC 3161 / Sigstore Rekor / OpenTimestamps) are implemented in-tree and covered by the automated test suite, not by this desktop walkthrough. The separate [Build Week judge binary](./JUDGES.md) verifies a committed fixed-image canonicalization receipt but deliberately does not perform live proving. Federation is off by default and not part of this walkthrough.

## What Works Now

- Olympus starts from the double-click Windows launcher.
- Files are BLAKE3-hashed locally before verification.
- Normal verification sends only the hash.
- Committing a file writes it to the append-only ledger.
- Re-verifying a committed file returns the ledger receipt and proof status.
- Bad API keys are rejected before commit.
- Already committed records are rejected instead of silently overwriting state.
- Proof bundles can be downloaded and checked independently.

## Reviewer Walkthrough

1. Start Olympus with `start.bat` (Windows) or `./start.sh` (macOS / Linux / WSL).
2. Open the public UI and land on Verify.
3. Drop a small sample file.
4. Confirm the local BLAKE3 digest appears before any upload.
5. Verify the hash before commit and confirm Olympus reports `RECORD_NOT_FOUND`.
6. Commit the file with a valid API key.
7. Verify the same file again and confirm the ledger reports a valid record.
8. Download the proof bundle from the successful verification.
9. Open the Proof tab and load the proof bundle JSON.
10. Confirm Olympus independently validates the proof bundle.
11. Try an invalid API key and confirm the app rejects it.
12. Try committing the same record again and confirm Olympus rejects the duplicate.

## Why This Matters

Olympus is not asking reviewers to trust the interface. The demo shows that the file hash, ledger record, and proof bundle can be checked as separate artifacts. That is the grant-relevant point: public documents can become portable, tamper-evident facts without forcing users to re-upload private content just to verify them later.

## Good Sample Package

For outside review, include:

- one harmless sample PDF
- the downloaded proof bundle JSON for that PDF
- a screen recording of your own run, if you made one
- a short note with the API base URL and Olympus version used during the run
