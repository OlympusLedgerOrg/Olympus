# CODEX.md

This file provides guidance to OpenAI Codex when working with code in this
repository.

**The single source of truth for agent guidance is [`AGENTS.md`](AGENTS.md)** —
read it in full. This file used to carry a near-duplicate copy; the two drifted
in opposite directions (each was newer in different sections), which is exactly
the failure mode a duplicate invites, so the copy was retired in favor of this
pointer.

Two hard rules worth restating even here:

- **Absolute upstream boundary**: never write to any repository outside
  `OlympusLedgerOrg` — see the policy section at the top of `AGENTS.md`.
- **Critical invariants** (leaf-hash layout, canonical JSON divergences,
  insert-only ledger, ceremony-manifest atomicity) are listed in `AGENTS.md`
  and `CLAUDE.md`; treat them as security policy, not documentation.
