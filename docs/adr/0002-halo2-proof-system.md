# ADR 0002: Zero-Knowledge Proof System Selection — Prefer Halo2

## Context
- Olympus needs a production-grade ZK proving system for redaction proofs.
- Goals: no trusted setup, battle-tested security, and ecosystem support.

## Decision
- Prefer Halo2 for future circuits (no trusted setup, production-proven in Zcash/Scroll).
- Continue to support existing circom circuits short term; treat Halo2 as the recommended target.
- Version all circuits and parameters; pin proving/verifying keys when generated.

## Alternatives Considered
- circom/Groth16 only: requires trusted setup ceremonies per circuit and increases operational burden.
- STARK-based systems: no setup but higher proof sizes and limited existing circuit parity with current designs.

## Consequences
- No ceremony required, reducing operational risk.
- Python-facing integration via `py-halo2` is less mature; Rust toolchain remains primary.
- Transition plan: maintain circom compatibility until Halo2 circuits are fully validated and reproducible.
