# Olympus RFC Process

An **RFC** (Request for Comments) is how Olympus proposes and reviews
substantial changes before implementation. It complements two existing
mechanisms:

- **ADRs** ([`docs/adr/`](../adr/)) record a decision *that has been made* and
  the architectural rationale behind it.
- **RFCs** (this directory) propose a change and gather feedback *before* the
  decision. An accepted RFC that changes architecture typically results in a
  new ADR when it lands.

Most pull requests do **not** need an RFC. Open one only when a change is
hard to reverse, affects many contributors, or touches the trust model.

## When an RFC is required

Open an RFC for any of:

- Changes to **protocol semantics** — leaf/node hashing, SMT shape,
  canonicalization, domain separation (see the Critical Invariants in
  [`CLAUDE.md`](../../CLAUDE.md)).
- Changes to **ZK circuits**, the proving/verifying surface, or the ceremony.
- Changes to the **threat model** or security boundaries.
- Changes to **governance**, the contributor ladder, or release authority.
- New cross-language **verifier** contracts or wire/bundle formats.

For these, an RFC is required in addition to (not instead of) the normal PR +
review + ADR requirements in [`docs/governance.md`](../governance.md).

## When an RFC is *not* required

Bug fixes, performance work, refactors with no external behavior change,
documentation, tests, and additive non-breaking features can go straight to a
pull request. If you are unsure, open a `governance`-tagged issue and ask.

## Lifecycle

1. **Draft.** Copy [`0000-template.md`](0000-template.md) to
   `docs/rfcs/0000-my-short-title.md` (keep `0000` until numbered) and open a
   pull request. Discussion happens on the PR.
2. **Review.** Maintainers and reviewers comment. The author iterates. The
   minimum comment window and quorum follow the decision rules in
   [`docs/governance.md`](../governance.md).
3. **Disposition.** The RFC is **Accepted**, **Rejected**, or **Postponed** by
   maintainer (lazy) consensus, or by vote if consensus cannot be reached.
   Rejected/postponed RFCs are kept for the historical record.
4. **Numbering & merge.** On acceptance, the RFC is assigned the next number,
   its `Status` is updated, and the PR is merged.
5. **Implementation.** Tracked via a linked issue. Protocol/architecture RFCs
   should produce an ADR when the implementation lands.

## Index

| RFC | Title | Status |
|-----|-------|--------|
| — | _none yet_ | |
