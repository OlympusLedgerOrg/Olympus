# Olympus Build Week demo script

Target duration: 2 minutes 55 seconds. Use spoken narration and show the real
binary and repository. Do not add music.

## 0:00–0:18 — Problem and audience

**On screen:** Olympus README, then a sample record/proof screen.

> When an important document is leaked, altered, or denied, a screenshot is
> not durable evidence. Olympus helps journalists, lawyers, investigators, and
> oversight organizations prove that a record is covered by a committed root
> and is unchanged relative to that checkpoint, without uploading the source
> document to a company.

## 0:18–0:38 — Honest Build Week boundary

**On screen:** `BUILD_WEEK.md`, with PRs #1398 and #1409 visible.

> Olympus existed before Build Week. After July 13, I added two complementary
> extensions with Codex and GPT-5.6: transactional, portable Merkle storage as
> the runnable product foundation, and fixed-image zkVM receipts as the
> cryptographic verification highlight.

## 0:38–1:33 — Run the product foundation

**On screen:** Download the v2 judge binary, verify its SHA-256, then run:

```powershell
.\olympus-smt-demo-windows-x64.exe --database olympus-demo.sqlite --reset
```

Pause on the first six entries in the JSON `checks` object.

> This is the real SQLite SMT backend with no server, network, Tauri,
> PostgreSQL, or rebuild. It inserts deterministic records, verifies existence
> and non-existence proofs, rolls back leaf and node rows together, refreshes a
> stale reader against a stable snapshot, rejects a conflicting insert-only
> batch, and reopens the database at the same durable root.

## 1:33–2:08 — Show the zkVM verification highlight

**On screen:** Pause on the three `canonicalization_*` checks and the
`canonicalization` report object.

> The same binary now verifies a real succinct RISC Zero receipt. The pinned
> guest executed Olympus's complete RFC 8785 canonicalizer, binding a commitment
> to the exact source bytes and the canonical digest later composed with the
> inclusion proof.
> The binary independently rebuilds the fixture claim and confirms the binding.
> It then changes one journal byte, keeps the receipt validly encoded, and shows
> that cryptographic verification rejects it. This is verification, not a slow
> live proof, so judges get the security claim without waiting.

## 2:08–2:30 — Honest technical boundary

**On screen:** ADR-0039 scope, then ADR-0040 security/limitations.

> The desktop still uses PostgreSQL for broader application state, and SQLite
> is scoped to the authenticated tree. The receipt proves canonicalizer
> execution and source binding—not truth or authorship. The existing Groth16
> keys are development artifacts pending a multi-contributor ceremony, and the
> demo makes no production-trust claim.

## 2:30–2:48 — Codex and GPT-5.6

**On screen:** Commit comparisons and a brief view of the principal Codex task
without exposing private data.

> Codex with GPT-5.6 helped trace the transaction bug, design and implement the
> Rust backends, build adversarial tests, integrate and harden the zkVM guest,
> repair cross-platform CI, and review every security claim. I directed the
> product boundaries, threat model, durability policy, and final claims.

## 2:48–2:55 — Close

**On screen:** `JUDGES.md`, public repository, and v2 release assets.

> The code, exact diffs, prebuilt binaries, checksums, and judge walkthrough are
> public. Olympus turns trust in an operator into evidence anyone can verify.
