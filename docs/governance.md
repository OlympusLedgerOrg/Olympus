# Olympus Governance

This document defines **how decisions are made in Olympus**: who decides, by
what process, and how disputes and successions are handled. It is operational —
the rules below are the ones we follow today — paired with an honest note about
the project's current maturity.

Companion documents:
- [`MAINTAINERS.md`](../MAINTAINERS.md) — roster, roles, and the contributor ladder.
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — how to submit changes (DCO sign-off).
- [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) — expected behavior and enforcement.
- [`docs/rfcs/README.md`](rfcs/README.md) — proposing substantial changes.
- [`SECURITY.md`](../SECURITY.md) — coordinated disclosure.
- [`ROADMAP.md`](../ROADMAP.md) — direction and milestones.

> **Current maturity (honest disclosure).** Olympus is in a
> maintainer-bootstrapping phase: the reference implementation has been driven
> primarily by a small core team, and growing the maintainer pool is an
> explicit, tracked goal (see [`ROADMAP.md`](../ROADMAP.md)). The process below
> is written so that authority is exercised by rule rather than by habit, and
> so the transition to multi-maintainer steady state is mechanical rather than
> improvised. Where a rule assumes several maintainers, it degrades gracefully
> while the pool is small (see [Bootstrapping clause](#bootstrapping-clause)).

## Principles

- **Protocol-first.** Ledger and proof semantics are stable, versioned, and
  documented (see [`docs/adr/`](adr/)).
- **Transparency.** Decisions and releases are recorded via ADRs, RFCs, and
  signed tags. Discussion happens in the open on issues and pull requests.
- **Fail-closed on the protocol.** Changes to the Critical Invariants in
  [`CLAUDE.md`](../../CLAUDE.md) are migration-class events and never land
  without an ADR.
- **Grow the bus factor.** We prefer to widen the maintainer pool over
  concentrating authority.

## Roles

Roles and the contributor ladder are defined in
[`MAINTAINERS.md`](../MAINTAINERS.md): **Contributor → Reviewer → Maintainer**,
plus a **Security Response** group drawn from maintainers. In governance terms:

- **Maintainers** hold merge rights, release authority, and votes.
- **Reviewers** can approve changes in their area toward merge requirements but
  do not vote on governance matters.
- **Contributors** propose changes and RFCs.

## Decision Process

We decide by **lazy consensus** wherever possible and fall back to a **vote**
only when consensus cannot be reached.

### Lazy consensus

Most decisions (merging a reviewed PR, accepting a small RFC, adding a reviewer)
proceed by lazy consensus: a maintainer proposes, and if no other maintainer
objects within the **review window** below, it is approved.

| Change class | Minimum review window | Minimum approvals |
|--------------|-----------------------|-------------------|
| Routine PR (bug fix, docs, tests, additive non-breaking) | none beyond normal review | 1 maintainer/area reviewer + green CI |
| Breaking change / new feature with external surface | 72 hours | 2 maintainers (or per `CODEOWNERS`) |
| Protocol / hashing / SMT / ZK circuit / ceremony change | 5 business days + ADR + RFC | 2 maintainers, incl. a crypto/ZK area owner |
| Governance change (this doc, ladder, release authority) | 7 days + RFC | vote (below) |

All PRs require DCO sign-off (`CONTRIBUTING.md`) and passing required CI before
merge. The Critical Invariants gate overrides everything: no invariant-breaking
merge without the ADR and regeneration steps in `CLAUDE.md`.

### Voting

When lazy consensus fails, or for governance changes and maintainer promotions,
maintainers vote:

- Each **active maintainer** has one vote. "Active" = merged or reviewed
  activity in the last 6 months.
- Votes run for at least the change class's review window, in the open
  (governance-tagged issue or the PR).
- **Ordinary matters** pass by simple majority of votes cast.
- **Sensitive matters** — governance changes, protocol/ceremony changes,
  maintainer promotion, or maintainer removal — require a **two-thirds
  supermajority** of active maintainers.
- Abstentions do not count toward the total. Ties fail (status quo holds).

## Proposing substantial changes (RFCs)

Substantial or hard-to-reverse changes go through the
[RFC process](rfcs/README.md) before implementation. RFCs that change
architecture produce an ADR when they land. See the RFC README for which
changes require one.

## Maintainer Election, Promotion & Removal

**Promotion** (Contributor → Reviewer → Maintainer) follows the ladder in
[`MAINTAINERS.md`](../MAINTAINERS.md#becoming-a-maintainer): nomination in a
`governance`-tagged issue, then lazy consensus (reviewer) or supermajority vote
(maintainer). The same PR updates the roster and `.github/CODEOWNERS`.

**Voluntary departure.** A maintainer may step down at any time and moves to
**Emeritus**; they may return via a lightweight re-confirmation.

**Removal for inactivity.** A maintainer inactive for 12 months may be moved to
Emeritus by lazy consensus, with notice to the person. They can return as above.

**Removal for cause.** Removal for serious Code of Conduct violations or loss
of trust requires a supermajority vote (the affected maintainer does not vote)
and is recorded. Conduct matters are handled per
[`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md).

## Releases

**Release authority:** any maintainer may cut a release.

Process:
1. Ensure `main` is green and `CHANGELOG.md` enumerates all protocol-impacting
   changes since the last release.
2. Versioning during 0.x hardening is `0.<minor>.<patch>`; breaking protocol
   changes bump `<minor>` and require a migration note + ADR.
3. Tag the release; **tags are signed**. ZK keys and ceremony transcripts are
   versioned under `proofs/` (and `ceremony/` for production ceremonies).
4. Before tagging **v1.0**, the production multi-contributor Phase-2 ceremony
   (`proofs/phase2_ceremony.sh`) must be complete with published, signed
   manifests — see `ROADMAP.md` and `proofs/CEREMONY_INTEGRITY.md`.

## Security Response

Vulnerability handling is owned by the **Security Response** group (a subset of
maintainers) and governed by [`SECURITY.md`](../SECURITY.md):

- Reports arrive privately via GitHub Private Security Advisory (preferred) or
  email to `olympusledgerorg@gmail.com` — **never** a public issue.
- SLAs: acknowledge ≤ 2 business days; triage ≤ 5 business days; patch ≤ 30
  days (critical) / ≤ 90 days (other); coordinated disclosure with a default
  90-day window.
- Fixes land as normal PRs after disclosure so they remain publicly reviewable;
  a public advisory is published once patched.
- Security work preempts roadmap/feature work.

## Dispute Resolution

1. **Discuss** on the issue/PR and seek lazy consensus.
2. If unresolved, **escalate** to a `governance`-tagged issue summarizing the
   options and trade-offs.
3. If still unresolved, **vote** per the rules above; the outcome is recorded.
4. Conduct-related disputes are routed to the Code of Conduct process instead.

## Escalation & Succession

If a maintainer becomes unavailable (especially a sole or last maintainer), the
remaining maintainers or designated stewards will:
1. Rotate signing keys used for releases and shard/checkpoint headers, and
   publish a signed notice + ADR documenting the change.
2. Invite additional maintainers from active contributors to restore
   redundancy.
3. Update [`MAINTAINERS.md`](../MAINTAINERS.md) and `.github/CODEOWNERS`.

The persistence requirements for signing keys (Ed25519 and Baby Jubjub) in
`CLAUDE.md` exist precisely so that historical signed roots remain verifiable
across a succession.

## Bootstrapping clause

While there is only one active maintainer, "supermajority of maintainers" and
"two maintainer approvals" reduce to that maintainer's decision **plus** a
mandatory open review window (per the change-class table) during which any
contributor may object, and **plus** the ADR/RFC paper trail. This keeps the
process transparent and reversible even before the pool grows. Reaching two to
three active maintainers — at which point these rules apply in full — is a
tracked v1.0 milestone in [`ROADMAP.md`](../ROADMAP.md).

## Licensing & Sustainability

Olympus is licensed under **Apache License 2.0** for all components: strong
patent protection for cryptographic implementations, enterprise-friendly terms,
and full auditability. Contributions are accepted under the Developer
Certificate of Origin (see [`CONTRIBUTING.md`](../CONTRIBUTING.md)) rather than a
CLA. The open-source model enables independent verification of every primitive,
community security review, and no vendor lock-in.

## Amending This Document

Changes to this governance document follow the **governance change** class
above: an RFC, a 7-day window, and a two-thirds supermajority vote (subject to
the bootstrapping clause).
