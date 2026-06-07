# Olympus Security Audit Report - V3 Re-Audit and Diff

> ⚠️ **OUTDATED — SUPERSEDED BY V4.** This report (V3) is retained for
> historical reference only. The current security audit is
> [`SECURITY_AUDIT_REPORT_V4.md`](../../SECURITY_AUDIT_REPORT_V4.md) (June 2026),
> which consolidates V1–V3 and the `docs/audits/` component audits. Do not
> rely on the finding statuses below — consult V4 for current state.

**Version:** 3.0
**Audit Date:** May 9, 2026
**Prior Audit:** V2 - April 3, 2026
**Classification:** Public
**Scope:** Code and documentation changes since the May 4, 2026 runtime exam, plus re-verification of prior V2 findings.

---

## Executive Summary

This re-audit reviewed the current `main` history through May 9, 2026, including the May 4-9 remediation series for canonical JSON hardening, SMT replay integrity, shared Rust crypto, sequencer networking, ingest verification access control, and public-statistics metadata propagation.

The earlier V2 high- and medium-severity findings remain closed. Since May 4, the repository added or strengthened:

- canonical JSON NFC normalization and depth limits,
- Sparse Merkle Tree replay integrity checks keyed by sequence windows,
- shared Rust hash/key primitives used by Python and the Rust sidecar,
- single-statement job claiming to reduce worker TOCTOU exposure,
- BLAKE3 WASM initialization hardening,
- sequencer URL/environment handling for Docker and local deployments,
- public verification endpoint access while keeping ingest auth-gated,
- 24-hour fuzzing framework and cross-platform fuzz runner coverage.

The current open items are no longer V2 high/medium blockers. They are operational or rollout gaps that should remain visible before broad production scaling.

## Validation Snapshot

| Check | Result | Notes |
|---|---|---|
| `pytest --collect-only -q` | Pass | 3,980 tests collected on May 9, 2026 |
| `ruff check .` | Pass | All Ruff lint checks passed after cleanup |
| `ruff format --check .` | Pass | 410 files already formatted |
| `python -m mypy protocol/ storage/ api/` | Pass | No issues found in 129 source files |
| `python -m bandit -r protocol/ storage/ api/ -f txt` | Pass | No issues identified |
| Full test suite | Not rerun during this documentation refresh | Existing working tree contains unrelated in-progress code changes |

## Diff Since May 4 Runtime Exam

| Area | May 4 status | May 9 status |
|---|---|---|
| Canonical JSON | Needed stronger Unicode/depth hardening | NFC-normalize-then-sort behavior and depth-cap regressions added |
| SMT replay integrity | Replay checks had scope/window risks | Sequence-based replay and orphan checks added across storage helpers |
| Worker job claim | TOCTOU window in claim flow | Single-statement `UPDATE` claim implemented |
| BLAKE3 WASM verifier path | Initialization and zero-output hardening needed | Retry, all-zero guard, and cross-library tests added |
| Shared Rust crypto | PyO3 and sidecar drift risk | `crates/olympus-crypto/` now centralizes protocol byte layouts |
| Sequencer Docker path | Networking and env alias drift | Docker-first stack and `OLYMPUS_SEQUENCER_URL` handling repaired |
| Verification API | Verify/ingest auth posture needed clarity | Verify endpoint public, ingest remains auth-gated |
| Fuzzing | Framework not yet part of routine evidence | 24-hour reliability fuzzing framework and seed controls added |

## Current Open Items

| ID | Severity | Status | Description |
|---|---|---|---|
| V3-O1 | Low | Open | ADR-0003 is **Accepted** and the operational leaf-hash now binds `parser_id` and `canonical_parser_version` (`crates/olympus-crypto/`, `src/crypto.rs`, `src/smt.rs`). Remaining gap is verifier/vector rollout: published verifier vectors at `verifiers/test_vectors/vectors.json` still encode the pre-binding `OLY:LEAF:V1` shape and external verifier releases need a regenerated parity corpus. |
| V3-O2 | Medium | Open | Multi-worker production deployments require a non-memory rate-limit backend. Keep `WEB_CONCURRENCY=1` with the default memory backend. |
| V3-O3 | Low | Open | Ingest parser determinism has API/schema tests but no committed parser-output vector corpus comparable to verifier vectors. |
| V3-O4 | Low | Open | External audit consumers would benefit from a machine-readable verifier parity results artifact. |
| V3-O5 | Low | Open | Groth16 production Phase 2 ceremony remains an external coordination task; development keys are not production keys. |

## Re-Verification of V2 Findings

| V2 category | Status as of May 9, 2026 |
|---|---|
| High findings RT-H1 through RT-H5 | Verified closed |
| Medium findings RT-M1 through RT-M4 | Verified closed or superseded by later hardening |
| Documentation drift | Updated by V3 docs to point auditors at the current architecture and startup paths |

## Auditor Notes

- `api.main:app` is the canonical FastAPI entrypoint. `api.app` remains only as a backward-compatibility shim.
- The Python API path is still the primary write path. The Go sequencer and Rust CD-HS-ST service are Phase 1 services being hardened alongside it.
- The shared Rust crypto crate reduces cross-language drift risk, but verifier vectors and conformance tests remain the source of truth for protocol byte layouts.
- With the default in-memory rate limiter, production should run a single worker. Multiple workers require a shared backend such as Redis.

## Recommended Follow-On Work

1. Regenerate and publish verifier vectors (`verifiers/test_vectors/vectors.json`) for the ADR-0003 leaf-hash binding and ship a verifier release that consumes them.
2. Add committed ingest parser determinism vectors.
3. Publish verifier parity results as a checked-in artifact or release artifact.
4. Keep production deployment examples pinned to `api.main:app`.
5. Run a clean full-suite audit after the unrelated May 9 working-tree code changes land or are isolated.
