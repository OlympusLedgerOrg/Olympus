# RFC-0000: <Title>

| Field      | Value                                          |
|------------|------------------------------------------------|
| Status     | **Draft** \| Accepted \| Rejected \| Postponed |
| Author(s)  | <your GitHub handle>                           |
| Date       | <YYYY-MM-DD>                                    |
| Tracking   | <issue/PR link, if any>                         |
| Supersedes | <prior RFC/ADR, if any>                         |

## Summary

One paragraph: what is being proposed and why, in plain language.

## Motivation

What problem does this solve? Who is affected? What happens if we do nothing?
If this touches the threat model or Critical Invariants, say so explicitly.

## Detailed design

The concrete proposal. Be specific enough that someone other than the author
could implement it. Cover:

- Affected components/paths (e.g. `crates/olympus-crypto/`, `src-tauri/src/zk/`).
- Protocol/hashing/circuit/ceremony impact, if any, and the migration plan.
- Public API, wire-format, or verifier-contract changes.
- Backward/forward compatibility and data migration.

## Security & invariant impact

Call out any effect on the Critical Invariants in `CLAUDE.md`, the threat model
([`docs/threat-model.md`](../threat-model.md)), or the ceremony integrity
checks. State the new assumptions a verifier or auditor must trust.

## Alternatives considered

What else was evaluated, and why this option was chosen.

## Drawbacks & risks

Honest accounting of costs, risks, and what could go wrong.

## Unresolved questions

Open issues to settle during review or defer to implementation.
