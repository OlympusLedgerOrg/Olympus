# Architecture Decision Records

Index of all ADRs in this directory. Numbering has gaps (some numbers were
reserved by design discussions that never produced a committed record), and
file naming switched from `NNNN-` to `ADR-NNNN-` at ADR-0009 — both prefixes
are valid history; new ADRs use the `ADR-NNNN-` form.

| ADR | Title | Status |
|-----|-------|--------|
| [ADR-0001](0001-incremental-tree-reconstruction.md) | Incremental / paginated tree reconstruction | Superseded |
| [ADR-0002](0002-mutation-testing-and-differential-fuzzing.md) | Mutation testing + cross-implementation differential fuzzing | Superseded |
| [ADR-0003](0003-parser-version-leaf-domain-separator.md) | Parser-version binding in the leaf hash domain separator | Accepted |
| [ADR-0004](0004-model-hash-leaf-domain-separator.md) | Model-hash binding in the leaf hash domain separator | Accepted |
| [ADR-0005](0005-structured-leaf-prefix-shard-binding.md) | Structured leaf prefix + shard-ID binding | Accepted |
| [ADR-0009](ADR-0009-poseidon-hash-suite.md) | Poseidon hash suite contract (poseidon-bn254-v1) | Accepted |
| [ADR-0021](ADR-0021-smt-with-ct-operational-hardening.md) | CD-HS-ST with CT-style operational hardening | Proposed (scaffold) |
| [ADR-0022](ADR-0022-smt-lazy-deep-node-storage.md) | Lazy deep-node storage for the persistent SMT | Accepted, implemented |
| [ADR-0023](ADR-0023-rasterized-tile-redaction.md) | In-house rasterized tile redaction | **Rejected** (2026-06-07) |
| [ADR-0024](ADR-0024-zk-tile-redaction.md) | Hybrid rasterized ZK tile redaction | **Rejected** (2026-06-08) |
| [ADR-0025](ADR-0025-pdf-object-level-redaction.md) | PDF object-level redaction commitment | Accepted (2026-06-08) |
| [ADR-0026](ADR-0026-multiformat-object-redaction-producer.md) | Multi-format object-level redaction producer | Proposed (2026-06-09) |
| [ADR-0027](ADR-0027-dataset-manifest-commitments.md) | Dataset-manifest commitments + client CLI/SDK | Accepted (2026-06-12) |
| [ADR-0031](ADR-0031-transition-attestations-insert-only-ledger.md) | Transition attestations + enforced insert-only ledger | Proposed (2026-06-16) |
| [ADR-0032](ADR-0032-retire-witness-over-root-cosignature.md) | Retire the witness-over-root cosignature scaffold | Accepted (2026-06-16) |

When adding an ADR: pick the next unused number, use the `ADR-NNNN-slug.md`
naming form, include a Status line near the top, and add a row here in the
same commit.
