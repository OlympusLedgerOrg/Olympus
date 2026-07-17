# OpenAI Build Week 2026 changelog

This changelog contains only work attributed to the qualifying Build Week
extension. Olympus existed before the submission window; see
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
