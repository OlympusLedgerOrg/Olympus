# OpenAI Build Week 2026 contribution

## Eligibility boundary

Olympus is a pre-existing project. The Build Week submission period began on
July 13, 2026 at 9:00 a.m. Pacific (12:00 p.m. Eastern / 16:00 UTC).

The last `main` commit before that boundary was
[`e239a414`](https://github.com/OlympusLedgerOrg/Olympus/commit/e239a41485cb5697190d0f35c359848f4a25f30e).
PRs #1376 and #1377 began before the submission period; although they merged
after the cutoff, Olympus does not claim them as qualifying work.

## Qualifying extensions

### Runnable product foundation — PR #1398

The judge experience is centered on
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

### Cryptographic verification highlight — PR #1409

[PR #1409, **Prove canonicalization with zkVM
receipts**](https://github.com/OlympusLedgerOrg/Olympus/pull/1409) was opened
July 19, 2026 at 01:54 UTC. Its core implementation and hardening range is
[`357b1e51...c69c2f7d`](https://github.com/OlympusLedgerOrg/Olympus/compare/357b1e51c363c956a7e61d609b352e19b3a58821...c69c2f7d3c518454374f5fd416614dbbb08f07c0).

The pre-existing unified Groth16 circuit committed to caller-supplied section
hashes; by itself it did not prove those hashes came from canonicalizing the
source document. PR #1409 makes that boundary explicit and closes it with a
fixed-image RISC Zero receipt:

1. The guest executes Olympus's complete Rust RFC 8785/JCS canonicalizer.
2. Its fixed-width journal binds a domain-separated commitment to the exact
   private source bytes, canonical digest, protocol version, and bounded
   lengths.
3. Runtime and standalone verification accept only succinct receipts for the
   pinned guest image, then bind the derived section commitment to public
   signal zero of the existing Groth16 inclusion/root proof.
4. A digest-pinned Linux builder reproduces the guest ELF and image ID; CI
   byte-compares both and verifies the committed real receipt fixture.
5. Source/output sizes, receipt size, user cycles, and local proving
   concurrency are bounded and tested on adversarial one-MiB inputs.
6. Rust and JavaScript verification paths independently validate the claim
   encoding and canonicalization vectors.

No Circom source, R1CS, verification key, or ceremony manifest changed in this
extension. The Build Week binary verifies the committed succinct receipt and a
tampered-journal rejection; it deliberately does not make judges wait for live
proving.

## Before versus during Build Week

| Area | Before the submission period | Build Week extensions |
|---|---|---|
| Persistent writes | Leaf and node operations could use separate autocommit connections | One backend-owned transaction commits or rolls back the complete batch |
| PostgreSQL locking | Session-oriented writer locking | `pg_advisory_xact_lock` inside the atomic write transaction |
| SQLite | No persistent SQLite SMT backend | Durable SQLite backend and dedicated `migrations-sqlite/` schema |
| Proof reads | Resident cache could outlive another process's commit | Snapshot root validates cache reuse; stale readers reload inside the snapshot |
| Backend API | Independent storage operations | Transaction-bound `NodeReadTransaction` and `NodeWriteTransaction` contracts |
| Test surface | PostgreSQL and memory behavior | Cross-backend transaction, rollback, concurrency, durability, and parity coverage |
| Canonicalization claim | The raw Groth16 circuit accepted caller-supplied section hashes and did not prove canonicalizer execution | A pinned zkVM guest executes the shared canonicalizer and authenticates the source commitment and canonical digest |
| Judge verification | Transaction semantics were not available as a standalone test | One network-free binary demonstrates the SQLite transaction contract and verifies a real succinct receipt plus tamper rejection |

## Codex and GPT-5.6 collaboration

Codex with GPT-5.6 assisted with:

- tracing the original cross-connection atomicity failure;
- designing the transaction-bound Rust trait contract;
- implementing PostgreSQL, SQLite, and memory transaction types;
- selecting and documenting SQLite durability and locking settings;
- writing adversarial rollback, concurrency, stale-reader, and write-once tests;
- resolving review feedback while preserving the security boundary; and
- implementing and reviewing the fixed-image canonicalization guest, receipt
  composition, deterministic build/fixture gates, Windows CRT repair, and
  bounded proving policy; and
- producing the combined judge demo and submission documentation.

Anthony Smith retained the key product and engineering decisions: keep the
desktop application's broader data model on PostgreSQL, make only the SMT
storage boundary database-agnostic, preserve the existing ledger hash/proof
format, require insert-only behavior, avoid claiming SQLite as a wholesale
desktop-database replacement, replace the false unified-canonicalization claim
with explicit receipt composition, and keep development Groth16 keys out of
production-trust claims.

The Devpost submission supplies the `/feedback` Session ID from the Codex task
containing the majority of the combined qualifying implementation. The Session
ID is entered in Devpost rather than committed as repository metadata; both PR
histories preserve the supporting timestamp and review evidence.

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
rollback, durable SQLite reopen, fixed-image receipt verification, exact source
binding, and cryptographic rejection of a journal mutation. See
[`JUDGES.md`](JUDGES.md).

PR #1409's validated pre-demo-integration head recorded 49 successful GitHub
checks with no failures: reproducible guest rebuild, real receipt/cycle fixture,
Windows and macOS builds, Rust/JavaScript verifier conformance, fuzzing,
coverage, mutation testing, supply-chain audit, CodeQL, and the complete Rust
test matrix.

## Scope limits

- SQLite is an SMT storage implementation, not a replacement for every
  PostgreSQL-backed Olympus subsystem.
- The judge demo uses deterministic synthetic records and makes no claim about
  the truth of real documents.
- The SMT extension preserves existing ledger hashes and offline proof formats;
  it is a storage atomicity and portability improvement, not a new
  cryptographic primitive.
- The canonicalization fixture contains public sample JSON. Receipt
  verification demonstrates execution integrity and source binding, not source
  privacy for that public fixture.
- The judge demo verifies a pre-generated succinct receipt; it does not perform
  a live zkVM proof. Local proving requires supported Linux tooling and is
  intentionally bounded and serialized.
- The current Groth16 keys remain single-contributor development artifacts.
  A multi-contributor Phase 2 ceremony is still required before production
  trust claims.
