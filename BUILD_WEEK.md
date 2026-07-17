# OpenAI Build Week 2026 contribution

## Eligibility boundary

Olympus is a pre-existing project. The Build Week submission period began on
July 13, 2026 at 9:00 a.m. Pacific (12:00 p.m. Eastern / 16:00 UTC).

The last `main` commit before that boundary was
[`e239a414`](https://github.com/OlympusLedgerOrg/Olympus/commit/e239a41485cb5697190d0f35c359848f4a25f30e).
PRs #1376 and #1377 began before the submission period; although they merged
after the cutoff, Olympus does not claim them as the qualifying extension.

## Qualifying extension

The submission is centered on
[PR #1398, **Add transactional database-agnostic SMT
storage**](https://github.com/OlympusLedgerOrg/Olympus/pull/1398):

- opened July 15, 2026 at 21:05 UTC;
- merged July 16, 2026 at 09:33 UTC;
- three commits across ten files;
- 2,242 additions and 409 deletions; and
- isolated feature comparison:
  [`ad3e080d...6e3fbfad`](https://github.com/OlympusLedgerOrg/Olympus/compare/ad3e080dcfd758bff912b278da99710953608e4e...6e3fbfad397eb555690a1ba48d7241325e567426).

### What changed

1. `NodeBackend` now exposes backend-owned read and write transactions rather
   than unrelated read/write calls.
2. PostgreSQL takes a transaction-scoped advisory lock and commits leaf and
   internal-node changes atomically.
3. SQLite uses `BEGIN IMMEDIATE`, `synchronous=EXTRA`, a dedicated strict
   schema, and a bounded busy timeout.
4. Proof construction reads from a stable snapshot and validates a resident
   hot cache against that snapshot's root.
5. The in-memory backend stages and swaps one complete transaction state.
6. Tests cover rollback, durability, concurrent writers, stale handles,
   write-once conflicts, proof parity, and schema constraints.

The governing design is
[ADR-0039](docs/adr/ADR-0039-transactional-database-agnostic-smt-storage.md).

## Before versus during Build Week

| Area | Before the submission period | Build Week extension |
|---|---|---|
| Persistent writes | Leaf and node operations could use separate autocommit connections | One backend-owned transaction commits or rolls back the complete batch |
| PostgreSQL locking | Session-oriented writer locking | `pg_advisory_xact_lock` inside the atomic write transaction |
| SQLite | No persistent SQLite SMT backend | Durable SQLite backend and dedicated `migrations-sqlite/` schema |
| Proof reads | Resident cache could outlive another process's commit | Snapshot root validates cache reuse; stale readers reload inside the snapshot |
| Backend API | Independent storage operations | Transaction-bound `NodeReadTransaction` and `NodeWriteTransaction` contracts |
| Test surface | PostgreSQL and memory behavior | Cross-backend transaction, rollback, concurrency, durability, and parity coverage |

## Codex and GPT-5.6 collaboration

Codex with GPT-5.6 assisted with:

- tracing the original cross-connection atomicity failure;
- designing the transaction-bound Rust trait contract;
- implementing PostgreSQL, SQLite, and memory transaction types;
- selecting and documenting SQLite durability and locking settings;
- writing adversarial rollback, concurrency, stale-reader, and write-once tests;
- resolving review feedback while preserving the security boundary; and
- producing the judge demo and submission documentation.

Anthony Smith retained the key product and engineering decisions: keep the
desktop application's broader data model on PostgreSQL, make only the SMT
storage boundary database-agnostic, preserve the existing ledger hash/proof
format, require insert-only behavior, and avoid claiming SQLite as a wholesale
desktop-database replacement.

The Devpost submission supplies the `/feedback` Session ID from the Codex
thread where the majority of PR #1398's core implementation was built. The
Session ID is entered in Devpost rather than committed as repository metadata.

## Validation evidence

PR #1398 recorded the following validation before merge:

- 1,305 local Rust workspace tests passed;
- 80 serialized embedded-PostgreSQL tests passed;
- seven SQLite backend regression tests passed;
- four PostgreSQL backend regression tests passed; and
- the federation, quorum-circuit, ZK, formatting, lint, verifier, dependency,
  and repository-tooling matrices passed.

The standalone judge binary adds a focused runtime demonstration of both proof
types, explicit leaf/node rollback, stale-reader refresh, write-once batch
rollback, and durable SQLite reopen. See [`JUDGES.md`](JUDGES.md).

## Scope limits

- SQLite is an SMT storage implementation, not a replacement for every
  PostgreSQL-backed Olympus subsystem.
- The judge demo uses deterministic synthetic records and makes no claim about
  the truth of real documents.
- The change preserves existing ledger hashes and offline proof formats; it is
  a storage atomicity and portability improvement, not a new cryptographic
  primitive.
