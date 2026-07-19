# Devpost submission draft

## Project name

Olympus

## Category

Developer Tools

## One-sentence pitch

Olympus gives journalists, investigators, lawyers, and oversight organizations
offline-verifiable proof that pinned code canonicalized a record and that the
record is covered by a committed checkpoint root and unchanged relative to it,
while keeping source documents local; this establishes integrity under the
[documented threat model](docs/threat-model.md), not truth, authorship, or
uncommitted history.

## Inspiration

When a leaked or public-interest record is changed, denied, or selectively
published, screenshots and institutional assurances are not durable evidence.
Olympus was created to make document history independently verifiable without
requiring a reader to trust one company, database operator, or cloud service.

## What it does

Olympus is a native verifiable-records system. It canonicalizes and commits
records to a domain-separated Sparse Merkle Tree, produces existence and
non-existence proofs, supports redaction evidence and offline verification, and
can anchor checkpoints to external timestamp and transparency systems. A
fixed-image zkVM receipt proves the canonicalizer execution that produced the
digest composed with an inclusion/root proof. Each verifier proves only the
integrity claim covered by the selected checkpoint root and its threat-model
assumptions—not truth, authorship, or changes never committed to a checkpoint.

## OpenAI Build Week contribution

Olympus existed before Build Week. During the qualifying period we added a
pair of complementary extensions: a transactional, database-agnostic
persistent SMT storage contract with PostgreSQL, SQLite, and in-memory
implementations, plus fixed-image zkVM receipts that prove Olympus's RFC 8785
canonicalizer actually produced the digest bound into an inclusion proof.

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

Before PR #1409, the raw unified Groth16 circuit accepted structured section
hashes but did not prove they came from canonicalizing the source. The new RISC
Zero guest executes the complete shared Rust canonicalizer and authenticates a
fixed-width claim binding a domain-separated commitment to the exact source
bytes, canonical digest, protocol version, and bounded lengths. Olympus accepts
only succinct receipts for the pinned guest image, derives the section
commitment from the authenticated journal, and requires it to equal the
existing Groth16 public signal.

The same standalone judge binary demonstrates both layers. It runs the real
SQLite transaction backend, verifies a committed real succinct receipt, checks
that receipt against a fresh claim for the public fixture source, and proves a
validly encoded journal mutation is cryptographically rejected. No network,
database installation, ZK tooling, or live proof generation is required.

Feature evidence:

- PR: https://github.com/OlympusLedgerOrg/Olympus/pull/1398
- Isolated diff: https://github.com/OlympusLedgerOrg/Olympus/compare/ad3e080dcfd758bff912b278da99710953608e4e...6e3fbfad397eb555690a1ba48d7241325e567426
- zkVM PR: https://github.com/OlympusLedgerOrg/Olympus/pull/1409
- zkVM core diff: https://github.com/OlympusLedgerOrg/Olympus/compare/357b1e51c363c956a7e61d609b352e19b3a58821...c69c2f7d3c518454374f5fd416614dbbb08f07c0
- Provenance: https://github.com/OlympusLedgerOrg/Olympus/blob/main/BUILD_WEEK.md
- Judge instructions: https://github.com/OlympusLedgerOrg/Olympus/blob/main/JUDGES.md

## How Codex and GPT-5.6 were used

Codex with GPT-5.6 helped trace the atomicity failure across the async Rust and
SQLx paths, design the transaction-bound backend API, implement the three
backend transaction types, write adversarial concurrency and rollback tests,
design and review the fixed-image zkVM claim, integrate receipt verification
with the existing Groth16 boundary, build reproducibility and adversarial-cycle
gates, repair the Windows CRT issue exposed by the dependency graph, debug
review findings, and produce the combined judge demonstration and
documentation.

I made the key scope and product decisions: retain PostgreSQL for the full
desktop application, make the SMT boundary independently portable, preserve
the existing hash/proof format, require insert-only behavior, and choose
fail-closed durability settings rather than advertise SQLite capabilities that
had not been qualified. I also chose to retire the misleading historical
canonicalization/signature claim, bind a commitment to the exact source bytes
in the zkVM journal, keep live proving out of the judge path, and state plainly
that the current Groth16 keys are development artifacts pending a
multi-contributor ceremony.

## How it works

1. A record is canonicalized and hashed locally.
2. Its shard-bound key and parser provenance form an insert-only SMT leaf.
3. The backend begins one serialized write transaction.
4. Olympus loads the working tree, validates write-once constraints, and
   computes the new root.
5. Leaf preimages and internal nodes commit or roll back together.
6. Proof readers establish a stable snapshot before reusing or refreshing the
   hot cache.
7. A fixed-image zkVM guest executes the canonicalizer and journals the source
   commitment plus canonical digest.
8. The verifier authenticates that receipt before deriving the section
   commitment bound to the Groth16 inclusion/root proof.
9. Offline verifiers validate the composed claim against the resulting
   checkpoint root.

## Challenges

The hardest part was preserving one semantic contract across PostgreSQL,
SQLite, and memory without reducing every backend to the least-capable SQL
dialect. SQLite also required careful choices around file URLs, VFS options,
locking, journal mode, synchronous durability, and migration isolation.

Another challenge was proving that the optimization layer remained correct
when a second process committed after a reader's cache was populated. The
solution binds cache reuse to the root observed inside the reader's stable
snapshot.

The zkVM challenge was separating what the historical circuit actually proved
from what its name implied. The solution keeps the raw section-commitment
circuit explicit, authenticates canonicalizer execution with a pinned guest,
and composes the two claims at verification time without changing the Circom
artifacts or ceremony state. Reproducible guest builds, real succinct fixtures,
bounded adversarial inputs, and cross-language verification make that claim
auditable.

## Accomplishments

- Atomic persistent SMT batches across all supported backends.
- A durable, strict SQLite SMT implementation.
- Snapshot-consistent proof generation across stale handles.
- Whole-batch rollback on write-once conflicts.
- Byte-identical roots and proofs across storage implementations.
- Complete RFC 8785 canonicalization proven by a pinned zkVM guest and bound to
  the existing inclusion/root proof.
- Reproducible guest artifacts, a real succinct receipt, adversarial cycle
  measurements, and independent Rust/JavaScript verification.
- A standalone, network-free judge binary requiring no rebuild, database
  installation, ZK toolchain, or live proving.

## What we learned

Database abstraction is not just a query portability problem. For an
authenticated data structure, transaction ownership, lock timing, snapshot
semantics, cache publication, and durability settings are part of the security
contract. Likewise, naming a circuit after a security property does not prove
that property: the verifier must make every composition boundary explicit and
authenticate the computation that produces each public commitment.

## What's next

Next steps are a generation-tagged migration workflow for moving non-empty SMT
deployments between backends, additional crash/fault-injection qualification,
and completion of Olympus's multi-contributor production ceremony and external
security review. The canonicalization receipt path itself requires no new
Groth16 ceremony because it composes with the existing circuit; production
trust still requires replacing the current development keys.

## Repository and testing

- Repository: https://github.com/OlympusLedgerOrg/Olympus
- License: Apache-2.0
- Supported judge-demo platforms: Windows x64, Linux x64, macOS Apple Silicon
- Test build: https://github.com/OlympusLedgerOrg/Olympus/releases/tag/build-week-2026-demo-v2

## Before final submission

- Paste the public YouTube demonstration URL into Devpost.
- Paste the `/feedback` Session ID from the principal implementation thread
  into the dedicated Devpost field. If #1398 and #1409 were developed in
  separate tasks, use the task containing the majority of the combined core
  implementation and preserve both PR histories as supporting evidence.
- Replace any branch-based documentation URLs with the final `main` URLs if
  the submission package has not yet merged.
- Confirm the final repository commit matches the binary's `build_commit` and
  the commit shown in the video.
