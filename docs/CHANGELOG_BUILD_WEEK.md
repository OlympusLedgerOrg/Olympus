# OpenAI Build Week 2026 changelog

This changelog contains only work attributed to the qualifying Build Week
extensions. Olympus existed before the submission window; see
[`BUILD_WEEK.md`](BUILD_WEEK.md) for the eligibility boundary and comparison
with pre-existing functionality.

## July 15–16, 2026 — transactional database-agnostic SMT storage

Feature pull request: [#1398](https://github.com/OlympusLedgerOrg/Olympus/pull/1398)

Isolated commit range:
[`ad3e080d...6e3fbfad`](https://github.com/OlympusLedgerOrg/Olympus/compare/ad3e080dcfd758bff912b278da99710953608e4e...6e3fbfad397eb555690a1ba48d7241325e567426)

- Replaced independent persistent SMT operations with backend-owned stable
  read snapshots and atomic write transactions.
- Made PostgreSQL leaf and internal-node persistence one serialized
  transaction using a transaction-scoped advisory lock.
- Added a durable SQLite SMT backend, isolated SQLite migrations, strict schema
  constraints, and explicit locking and durability settings.
- Made the in-memory backend stage and publish complete transaction state.
- Bound cache reuse and proof generation to the root observed inside a stable
  snapshot.
- Added rollback, durability, concurrent-writer, stale-reader, write-once,
  proof-parity, and schema-constraint coverage.
- Added ADR-0039 documenting the security contract and honest SQLite scope.

## July 17, 2026 — judge and submission package

- Added a standalone, network-free SQLite demonstration of the qualifying
  storage path.
- Added cross-platform CI builds, smoke verification, checksums, and an
  operator-triggered public prerelease workflow.
- Added judge instructions, provenance documentation, Devpost copy, and a
  narrated sub-three-minute video script.
- Corrected the contributor MSRV documentation to Rust 1.94, matching the
  locked SQLx 0.9 dependency graph.

This second group makes the qualifying feature testable and legible to judges;
it does not replace PR #1398 as the claimed core extension.

## July 18–19, 2026 — fixed-image canonicalization receipts

Feature pull request: [#1409](https://github.com/OlympusLedgerOrg/Olympus/pull/1409)

Core implementation and hardening range:
[`357b1e51...c69c2f7d`](https://github.com/OlympusLedgerOrg/Olympus/compare/357b1e51c363c956a7e61d609b352e19b3a58821...c69c2f7d3c518454374f5fd416614dbbb08f07c0)

- Added a fixed-image RISC Zero guest that executes the shared Rust RFC 8785
  canonicalizer and journals a bounded, versioned claim.
- Bound a domain-separated commitment to the exact source bytes and the
  canonical digest to the existing structured section commitment, then composed
  that commitment with the Groth16 inclusion/root proof.
- Pinned the guest ELF, image ID, real succinct receipt fixture, deterministic
  build container, and adversarial cycle report.
- Added independent Rust and JavaScript claim verification and runtime tests
  that accept only the pinned guest and succinct receipt format.
- Bounded source/output sizes, receipt size, user cycles, and local proving
  concurrency; repaired Windows static-CRT linker scoping uncovered by the new
  dependency graph.
- Corrected protocol documentation so the raw historical `_sign` circuit is
  never described as proving canonicalization or signatures.

## July 19, 2026 — combined judge experience

- Extended the existing no-network judge binary rather than introducing a
  second setup path.
- Kept the transactional SQLite SMT flow as the primary product demonstration.
- Added verification of the committed succinct canonicalization receipt under
  the pinned guest image, exact fixture-source binding, and cryptographic
  rejection after journal tampering.
- Kept live proving out of the judge path so the complete demonstration remains
  practical on Windows, Linux, and macOS.
