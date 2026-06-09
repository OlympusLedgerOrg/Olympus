# Maintainers & Contributor Ladder

This file is the operational record of **who maintains Olympus, what each role
can do, and how someone moves up the ladder**. It is the companion to
[`docs/governance.md`](docs/governance.md) (the decision process) and
[`CONTRIBUTING.md`](CONTRIBUTING.md) (how to submit changes).

> **Current state (honest disclosure).** Olympus is in its
> maintainer-bootstrapping phase. The reference implementation has been driven
> primarily by a small core team, and the project is **actively recruiting
> additional maintainers** to reduce bus factor. This document defines the
> ladder and authority model now so that growth is governed by a written
> process rather than ad hoc decisions. If you are interested in a maintainer
> role, see [Becoming a maintainer](#becoming-a-maintainer).

## Roles

Olympus uses a three-rung ladder. Each rung is additive.

| Role | Can do | Granted by |
|------|--------|-----------|
| **Contributor** | Open issues, submit pull requests, comment on reviews, propose RFCs. | Anyone — no approval needed. |
| **Reviewer** | Everything a contributor can, plus: their approval counts toward merge requirements for a defined area; triages incoming issues; mentors contributors. | Nomination by a maintainer + lazy consensus of maintainers (see governance). |
| **Maintainer** | Everything a reviewer can, plus: merge rights, release authority, manage `CODEOWNERS`/labels/branch protection, vote on governance matters, participate in security response, approve new reviewers/maintainers. | Nomination + maintainer vote (see [Becoming a maintainer](#becoming-a-maintainer)). |

A **Security Response Contact** is a maintainer (or delegate) who additionally
owns coordinated disclosure under [`SECURITY.md`](SECURITY.md). The security
response group is a subset of maintainers, listed below.

## Current Maintainers

Maintainers are listed by GitHub handle. The GitHub organization
[`@OlympusLedgerOrg`](https://github.com/OlympusLedgerOrg) and the
[`.github/CODEOWNERS`](.github/CODEOWNERS) entries are the machine-enforced
source of truth for review/merge rights; this table is the human-readable
roster.

| GitHub handle | Role | Areas of focus | Security response |
|---------------|------|----------------|:-----------------:|
| `@OlympusLedgerOrg` (core team) | Maintainer | All areas (crypto, ZK, Tauri/Axum, storage, federation, docs) | ✅ |

<!--
When adding a maintainer, append a row here in the same PR that updates
.github/CODEOWNERS, and record the vote/lazy-consensus thread in the PR
description. Use the contributor's real GitHub handle. Example rows:

| `@alice`  | Maintainer | ZK circuits, prover (`proofs/`, `src-tauri/src/zk/`) | ✅ |
| `@bob`    | Reviewer   | Frontend (`app/public-ui/`)                          |    |
-->

### Emeritus

Maintainers who step back retain credit and may return through a lightweight
re-confirmation rather than the full nomination process.

| GitHub handle | Former role | Notes |
|---------------|-------------|-------|
| _none yet_ | | |

## Area Ownership

Day-to-day review ownership follows [`.github/CODEOWNERS`](.github/CODEOWNERS).
The conceptual map:

| Area | Paths | Notes |
|------|-------|-------|
| Shared crypto | `crates/olympus-crypto/`, `crates/light-poseidon/`, `crates/babyjubjub-permissive/` | Hash/SMT/Poseidon invariants — changes are migration-class (see `CLAUDE.md` → Critical Invariants). |
| ZK / circuits | `proofs/`, `src-tauri/src/zk/` | Circuit + ceremony changes require an ADR and a manifest regeneration. |
| Backend / API | `src-tauri/src/` | Axum routes, auth, anchoring, federation, embedded DB. |
| Frontend | `app/public-ui/` | React + TypeScript UI. |
| Verifiers | `verifiers/` | Cross-language conformance; golden vectors. |
| Docs & governance | `docs/`, root `*.md` | ADRs, threat model, this file. |

## Becoming a Maintainer

The ladder is meant to be climbed. We would rather over-invest in growing the
maintainer pool than concentrate authority.

**Contributor → Reviewer**
1. Make sustained, quality contributions to an area (code, reviews, docs, or
   triage) over time.
2. A maintainer nominates you in a GitHub issue tagged `governance`.
3. Maintainers approve by lazy consensus (no objection within the review
   window defined in `docs/governance.md`).
4. You are added to the relevant `CODEOWNERS` paths and the roster above.

**Reviewer → Maintainer**
1. Demonstrate good judgment as a reviewer — sound merges, respect for the
   [Critical Invariants](CLAUDE.md), and constructive collaboration.
2. A maintainer nominates you in a `governance` issue.
3. Requires an affirmative maintainer vote per the voting rule in
   `docs/governance.md` (supermajority of active maintainers).
4. On approval: granted merge rights, added to this roster and `CODEOWNERS`,
   and offered (not obligated) a seat in the security response group.

Self-nomination is welcome — open a `governance` issue describing your
contributions and the area you want to own.

## Maintainer Guide (responsibilities)

Being a maintainer is a duty, not just a permission set:

- **Review fairly and promptly.** Aim to give a first response to PRs and
  issues within the review window. Respect the DCO sign-off requirement and the
  Critical Invariants when merging.
- **Protect the protocol.** Any change to leaf/node hashing, SMT shape, ZK
  circuits, or ceremony artifacts requires an ADR and the regeneration steps in
  `CLAUDE.md`. Do not merge invariant-breaking changes without one.
- **Keep CI green.** Do not merge with failing required checks. Use the
  security-hardening gates described in `SECURITY.md`.
- **Share the load.** Mentor contributors and actively look for reviewer
  candidates. A healthy bus factor is an explicit project goal.
- **Honor security SLAs.** If you are in the security response group, meet the
  acknowledgment/triage/patch timelines in `SECURITY.md`.
- **Step back gracefully.** If you can no longer participate, say so; you move
  to Emeritus and we follow the succession steps in `docs/governance.md`.

## Releases

Release authority and the release process are defined in
[`docs/governance.md`](docs/governance.md#releases). In short: any maintainer
may cut a release; tags are signed; `CHANGELOG.md` enumerates protocol-impacting
changes; and protocol/ceremony changes additionally require an ADR.

## Decisions & Disputes

Decision-making, voting thresholds, the RFC process, and dispute resolution are
defined in [`docs/governance.md`](docs/governance.md). Conduct concerns are
handled under [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
