# Olympus Build Week demo script

Target duration: 2 minutes 45 seconds. Use spoken narration and show the real
binary and repository. Do not add music.

## 0:00–0:20 — Problem and audience

**On screen:** Olympus README, then a sample record/proof screen.

> When an important document is leaked, altered, or denied, a screenshot is
> not durable evidence. Olympus helps journalists, lawyers, investigators, and
> oversight organizations prove that a record existed and has not been
> silently changed, without uploading the source document to a company.

## 0:20–0:50 — What Olympus does

**On screen:** Briefly show the desktop workflow or existing Olympus demo.

> Olympus commits records to an insert-only Sparse Merkle Tree. It produces
> offline-verifiable existence and non-existence proofs and can anchor signed
> checkpoints to independent timestamp systems. Olympus existed before Build
> Week, so this submission is specifically about what changed after July 13.

## 0:50–1:45 — Run the Build Week feature

**On screen:** Download the judge binary, verify its SHA-256, then run:

```powershell
.\olympus-smt-demo-windows-x64.exe --database olympus-demo.sqlite --reset
```

Scroll slowly through the JSON `checks` object.

> During Build Week I added transactional, database-agnostic SMT storage. This
> binary is exercising the real SQLite backend with no server, network, Tauri,
> PostgreSQL, or rebuild. It inserts deterministic records, verifies existence
> and non-existence proofs, rolls back staged leaf and node rows together,
> proves that a stale reader refreshes against a stable snapshot, rejects a
> conflicting insert-only batch, and reopens the database to verify the same
> durable root. Every check is true, so the demo exits with PASS.

## 1:45–2:10 — Honest technical boundary

**On screen:** ADR-0039 scope section and PR #1398 files.

> This does not claim that the whole desktop app switched to SQLite. Olympus
> still uses embedded PostgreSQL for its broader application state. The new
> boundary makes the authenticated tree portable while keeping PostgreSQL's
> production behavior and preserving identical ledger hashes and proofs.

## 2:10–2:35 — Codex and GPT-5.6

**On screen:** Build Week provenance document, commit comparison, and a brief
view of the principal Codex session without exposing private data.

> Codex with GPT-5.6 helped trace the original cross-connection failure, design
> the Rust transaction contract, implement the PostgreSQL, SQLite, and memory
> backends, write adversarial rollback and concurrency tests, and debug review
> findings. I made the product and security decisions about scope, durability,
> insert-only behavior, and what Olympus would and would not claim.

## 2:35–2:45 — Close

**On screen:** `JUDGES.md`, public repository, and release assets.

> The code, exact Build Week diff, prebuilt test binaries, checksums, and a
> five-minute judge walkthrough are public. Olympus turns trust in an operator
> into evidence anyone can verify.
