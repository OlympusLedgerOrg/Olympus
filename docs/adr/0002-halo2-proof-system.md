# ADR 0002: Zero-Knowledge Proof System Selection — Groth16 Primary, Halo2 Optional

## Context
- Olympus needs a production-grade ZK proving system for redaction proofs.
- Goals: high throughput/low latency for the core ledger, mitigation of trusted
  setup risk, and a path to higher-assurance proofs when needed.

## Decision
- **Groth16 remains the primary proving system** for current operations to meet
  performance and latency targets.
- Trusted setup risk is mitigated via a transparent, multi-party Phase 2
  ceremony with public transcripts.
- **Halo2 is introduced as an optional secondary proving system** for
  high-assurance contexts (e.g., superseding signatures or “final appeal”
  proofs) where maximal trustlessness is required.
- Maintain a clear boundary between the proving system and the protocol so
  Halo2 can be slotted in without disrupting the Groth16 pipeline.
- Version all circuits and parameters; pin proving/verifying keys when
  generated.

## Alternatives Considered
- Halo2-only: removes trusted setup but would regress throughput/latency goals
  for current workloads.
- circom/Groth16 only: requires trusted setup ceremonies per circuit and
  increases operational burden without providing a high-trustless option.
- STARK-based systems: no setup but higher proof sizes and limited existing
  circuit parity with current designs.

## Consequences
- Default proving stays on Groth16, preserving current performance.
- Production deployments must publish a multi-party Groth16 ceremony transcript.
- Halo2 hooks can be added behind the proving-system boundary for the most
  sensitive verifications without destabilizing the core path.
- Python-facing Halo2 integration (`py-halo2`) remains less mature; Rust
  toolchain is primary for those optional circuits.
