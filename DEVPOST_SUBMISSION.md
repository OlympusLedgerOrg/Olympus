# Devpost submission draft

## Project name

Olympus

## Category

Developer Tools

## One-sentence pitch

Olympus gives journalists, investigators, lawyers, and oversight organizations
offline-verifiable proof that sensitive records existed and have not been
silently altered, while keeping the source documents local.

## Inspiration

When a leaked or public-interest record is changed, denied, or selectively
published, screenshots and institutional assurances are not durable evidence.
Olympus was created to make document history independently verifiable without
requiring a reader to trust one company, database operator, or cloud service.

## What it does

Olympus is a native verifiable-records system. It canonicalizes and commits
records to a domain-separated Sparse Merkle Tree, produces existence and
non-existence proofs, supports redaction evidence and offline verification, and
can anchor checkpoints to external timestamp and transparency systems.

## OpenAI Build Week contribution

Olympus existed before Build Week. During the qualifying period we added a
transactional, database-agnostic persistent SMT storage contract with
PostgreSQL, SQLite, and in-memory implementations.

Previously, PostgreSQL leaf and internal-node writes could occur through
separate autocommit operations. A failure between them could leave durable
preimages and nodes describing different trees. The new type-level contract
forces the read-modify-write sequence through one backend-owned transaction,
publishes the hot cache only after commit, and constructs proofs from stable
read snapshots.

SQLite adds a low-maintenance local backend using `BEGIN IMMEDIATE`, strict
schema constraints, `synchronous=EXTRA`, trusted-schema lockdown, and explicit
rollback semantics. The change does not alter Olympus's ledger hashes or proof
formats.

Feature evidence:

- PR: https://github.com/OlympusLedgerOrg/Olympus/pull/1398
- Isolated diff: https://github.com/OlympusLedgerOrg/Olympus/compare/ad3e080dcfd758bff912b278da99710953608e4e...6e3fbfad397eb555690a1ba48d7241325e567426
- Provenance: https://github.com/OlympusLedgerOrg/Olympus/blob/main/BUILD_WEEK.md
- Judge instructions: https://github.com/OlympusLedgerOrg/Olympus/blob/main/JUDGES.md

## How Codex and GPT-5.6 were used

Codex with GPT-5.6 helped trace the atomicity failure across the async Rust and
SQLx paths, design the transaction-bound backend API, implement the three
backend transaction types, write adversarial concurrency and rollback tests,
debug review findings, and produce the judge demonstration and documentation.

I made the key scope and product decisions: retain PostgreSQL for the full
desktop application, make the SMT boundary independently portable, preserve
the existing hash/proof format, require insert-only behavior, and choose
fail-closed durability settings rather than advertise SQLite capabilities that
had not been qualified.

## How it works

1. A record is canonicalized and hashed locally.
2. Its shard-bound key and parser provenance form an insert-only SMT leaf.
3. The backend begins one serialized write transaction.
4. Olympus loads the working tree, validates write-once constraints, and
   computes the new root.
5. Leaf preimages and internal nodes commit or roll back together.
6. Proof readers establish a stable snapshot before reusing or refreshing the
   hot cache.
7. Offline verifiers validate proofs against the resulting checkpoint root.

## Challenges

The hardest part was preserving one semantic contract across PostgreSQL,
SQLite, and memory without reducing every backend to the least-capable SQL
dialect. SQLite also required careful choices around file URLs, VFS options,
locking, journal mode, synchronous durability, and migration isolation.

Another challenge was proving that the optimization layer remained correct
when a second process committed after a reader's cache was populated. The
solution binds cache reuse to the root observed inside the reader's stable
snapshot.

## Accomplishments

- Atomic persistent SMT batches across all supported backends.
- A durable, strict SQLite SMT implementation.
- Snapshot-consistent proof generation across stale handles.
- Whole-batch rollback on write-once conflicts.
- Byte-identical roots and proofs across storage implementations.
- A standalone, network-free judge binary requiring no rebuild or database
  installation.

## What we learned

Database abstraction is not just a query portability problem. For an
authenticated data structure, transaction ownership, lock timing, snapshot
semantics, cache publication, and durability settings are part of the security
contract.

## What's next

Next steps are a generation-tagged migration workflow for moving non-empty SMT
deployments between backends, additional crash/fault-injection qualification,
and completion of Olympus's multi-contributor production ceremony and external
security review.

## Repository and testing

- Repository: https://github.com/OlympusLedgerOrg/Olympus
- License: Apache-2.0
- Supported judge-demo platforms: Windows x64, Linux x64, macOS Apple Silicon
- Test build: https://github.com/OlympusLedgerOrg/Olympus/releases/tag/build-week-2026-demo

## Before final submission

- Paste the public YouTube demonstration URL into Devpost.
- Paste the `/feedback` Session ID from the principal PR #1398 implementation
  thread into the dedicated Devpost field.
- Replace any branch-based documentation URLs with the final `main` URLs if
  the submission package has not yet merged.
- Confirm the final repository commit matches the binary's `build_commit` and
  the commit shown in the video.
