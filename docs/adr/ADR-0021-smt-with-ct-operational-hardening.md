# ADR-0021: CD-HS-ST with CT-style operational hardening

- **Status:** Proposed (scaffold)
- **Date:** 2026-05-10
- **Reference discussion:** Olympus architecture chat, 2026-05-10

## Context

Olympus needs keyed inclusion and non-inclusion proofs for press-freedom records while also making operational equivocation (split-view behavior) publicly detectable. The existing CD-HS-ST (single global sparse Merkle tree keyed by `H(GLOBAL_KEY_PREFIX || shard_id || record_key)`) is the cryptographic source of truth.

The missing deployment hardening is CT-grade operational practice around signed roots: witness cosigning, gossip comparisons, monitor APIs, and a maximum merge delay (MMD) policy.

## Decision

Keep the **SMT (CD-HS-ST)** as the only ledger commitment tree and add **RFC-6962-inspired operational controls** around signed roots.

### Why SMT over an RFC-6962 history tree

- **Non-inclusion proofs are first-class** (critical for proving keyed absence vs hidden records).
- **Keyed lookups are native** (`shard_id + record_key`), unlike index-based history trees.
- **Mutable-but-tamper-evident state** maps directly to keyed sparse tree updates.
- **Proof size remains fixed-depth** for a 256-level sparse tree.

### Why adopt CT operational practices anyway

- **Witness cosigning:** independent parties co-sign roots to reduce single-operator trust.
- **Gossip:** independent monitors compare envelopes and detect split-view evidence.
- **Maximum Merge Delay (MMD):** submitters can prove delayed inclusion breaches.
- **Monitor API:** public read-only surfaces for root/proof/evidence verification.

## Explicit non-goals (this scaffold)

- ❌ No parallel RFC-6962 history tree.
- ❌ No RFC-6962 `consistency_proof` endpoint.
- ❌ No production witness onboarding ceremony in this PR.
- ❌ No production gossip transport implementation (interfaces + in-memory doubles only).

## SMT-native equivalent of CT consistency checks

Olympus does **not** implement RFC-6962 prefix consistency proofs. The SMT-native equivalent is:

1. Retrieve two signed roots (`old_root`, `new_root`).
2. Re-check inclusion/non-inclusion proofs against each root as needed.
3. Detect contradiction/equivocation via signed conflicting root envelopes.

## Threat model coverage

| Mechanism | Defends against | Notes |
|---|---|---|
| Signed roots | Silent state rewrites without detectable root change | Base cryptographic checkpointing |
| Witness cosigning | Single-operator unilateral root claims | Threshold policy (scaffold default: 2-of-3) |
| Gossip comparison | Split-view/equivocation across auditors | Detects same-height conflicting signed roots |
| MMD evidence | Hidden records / delayed publication after receipt | Submitter can present timing evidence |
| Inclusion/non-inclusion proofs | Hidden records and denial of committed records | Anchored to signed roots |

## Consequences

- We preserve one global CD-HS-ST data structure and avoid dual-tree operational complexity.
- Operational trust posture aligns with CT deployment lessons without forcing RFC-6962 semantics onto an SMT.
- This ADR enables incremental implementation: scaffold interfaces now, production network and witness governance later.
