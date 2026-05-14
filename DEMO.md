# Olympus Demo Guide

This demo shows the working Olympus proof loop without asking a reviewer to understand the full codebase first.

## Demo Video

- Local recording: [Recording 2026-05-14 081752.mp4](./Recording%202026-05-14%20081752.mp4)
- Public/share link: replace this line with the grant portal, Drive, YouTube, or release-asset URL before sending the package outside the project.

The recording should show the core story: double-click start, ingest a file, verify it, reject a bad API key, reject an already committed record, download a proof bundle, and verify that proof bundle.

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

1. Start Olympus with `Olympus-Start-Windows.cmd`.
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
- the demo video above, or a public URL to it
- a short note with the API base URL used during the recording
