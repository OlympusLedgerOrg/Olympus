# Olympus OTF IFF 2026-07 Reviewer Packet

## Project

**Olympus v1.0: Phase 2 Ceremony and Verification Pilot for Public-Interest Records**

## Short Version

Olympus is an open-source desktop system for creating and verifying portable
cryptographic receipts for public-interest documents. The current v0.10.0
release implements the core local workflow: desktop node, embedded ledger,
document commitment, proof-bundle export, and standalone verifier tooling. OTF
support would fund the remaining production-trust transition to a v1.0 release
candidate.

## Pre-v1 / As-Is Status

This repository is a pre-v1, as-is technical release intended for review,
demonstration, and continued hardening. It should not be treated as a
production-trust v1.0 release until the remaining trust gates are complete:

- multi-contributor Groth16 Phase 2 ceremony;
- public ceremony provenance and checksum verification;
- proof-bundle and offline verifier hardening;
- remediation or documented deferral of known internal-review findings;
- external security review preparation and OTF-facilitated audit;
- public-interest user pilot and documentation updates.

Pre-v1 development databases should be treated as disposable. A v1.0 release
may require wiping or reinitializing local dev databases and regenerating
development proof artifacts; records committed only to pre-v1 dev databases are
not represented as permanent public-interest records across the v1 boundary.
Durable reliance begins with the v1 release path, production ceremony artifacts,
documented migrations, and verifier-compatible proof bundles.

The remaining blocker is not basic functionality; it is production trust.

## AI-Assisted Development Disclosure

Olympus used AI-assisted development, testing, documentation, and adversarial
code-review workflows to accelerate implementation and examine the codebase. AI
assistance was used as a development and review aid, not as an authority.
Outputs were reviewed by the project lead before inclusion.

AI-assisted review is not represented as an independent security audit. The
current security review is internal/adversarial, and the project is
intentionally structured around external security review before v1.0.

## What Exists Now

- Rust/Tauri desktop app with embedded Axum HTTP server and embedded PostgreSQL.
- Document commitment workflow for public-interest records.
- Tamper-evident sparse Merkle ledger.
- Proof-bundle export.
- Offline verifier tooling in Rust and JavaScript.
- Groth16 proof integration and ceremony-manifest checks.
- Redaction verification via signed Merkle replay, not a redaction Groth16
  circuit.
- Feature-gated federation and external anchoring support, subject to operator
  configuration and live-network validation.
- Plain-English threat model and court-evidence runbook.
- Internal adversarial security review, clearly labeled as internal review
  rather than an independent third-party audit.

## What OTF Funding Would Do

OTF funding would move Olympus from v0.10.0 to a v1.0 release candidate by
completing the trust work that should happen before public-interest users rely
on it in adversarial settings:

1. Freeze the v0.10.0 baseline and reviewer documentation.
2. Prepare a multi-contributor Phase 2 ceremony.
3. Run the ceremony and publish provenance.
4. Integrate production ceremony artifacts.
5. Harden proof-bundle export and offline verification.
6. Prepare for external security review and remediate known internal-review
   findings.
7. Recruit and run a small public-interest user pilot.
8. Publish a v1.0 release candidate, pilot report, verifier documentation, and
   sustainability updates.

## Demo Workflow

1. Start the desktop app.
2. Add a sample public-interest document.
3. Commit the document fingerprint to the local ledger.
4. Verify the committed document.
5. Export a proof bundle.
6. Verify the proof bundle independently with the standalone verifier.
7. Demonstrate failure on a modified file or mismatched proof bundle.

## Documents for Reviewers

- [README.md](../../README.md) - high-level overview and developer entry point.
- [DEMO.md](../../DEMO.md) - local demo path.
- [ROADMAP.md](../../ROADMAP.md) - v0.10.x to v1.0 milestones.
- [GRANTS.md](../../GRANTS.md) - grant brief and reviewer framing.
- [proofs/README.md](../../proofs/README.md) - active circuits, ceremony
  process, and redaction note.
- [docs/threat-model.md](../threat-model.md) - plain-English threat model.
- [docs/court-evidence.md](../court-evidence.md) - evidence and verification
  runbook.
- [docs/SECURITY_AUDIT_REPORT_V5.md](../SECURITY_AUDIT_REPORT_V5.md) -
  internal adversarial security review.
- [proofs/phase2_ceremony.sh](../../proofs/phase2_ceremony.sh) -
  multi-contributor Phase 2 ceremony tooling.

## Important Non-Claims

- v0.10.0 is not being represented as production-trust v1.0.
- Pre-v1 development databases are not represented as permanent public-interest
  archives across the v1 release boundary.
- The current security review is internal/adversarial, not an independent
  external audit.
- AI-assisted review is not represented as an independent security audit.
- Redaction is no longer a Groth16 circuit; it is verified through signed
  Merkle replay.
- Federation is implemented in-tree but feature-gated.
- External anchoring depends on operator configuration and live-network
  validation.

## Requested Support

- Amount: $75,000
- Duration: 6 months
- OTF form duration selection: 6 months to 1 year
- Category: Technology Development
