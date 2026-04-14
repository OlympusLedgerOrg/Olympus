# ADR-0002: Mutation Testing and Cross-Implementation Differential Fuzzing

- **Status:** Accepted
- **Date:** 2026-04-14
- **Deciders:** Olympus maintainers

## Context

The Olympus test suite includes 150+ test files, property-based testing via
Hypothesis, adversarial tests, and chaos tests.  However, two gaps remained:

1. **No mutation testing** — high code coverage does not guarantee that every
   line of crypto code is actually *tested*.  A mutation in a hash domain
   separator, Merkle tree construction, or canonicalization function could
   survive undetected if tests only exercise the happy path.

2. **Limited cross-implementation differential fuzzing** — the existing
   `test_cross_language_determinism.py` harness uses a fixed seed
   (`0xC0FFEE`) with deterministic random records.  This misses edge cases
   that property-based fuzzers (Hypothesis) are designed to find: empty
   inputs, boundary lengths, non-UTF-8 byte sequences, etc.

Both gaps directly affect the trustworthiness of the cryptographic core.

## Decision

### Mutation Testing

We adopt **mutmut** as the mutation testing framework for the protocol crypto
modules (`protocol/hashes.py`, `protocol/merkle.py`, `protocol/ssmf.py`,
`protocol/canonical.py`).

- **Configuration** lives in `[tool.mutmut]` in `pyproject.toml`.
- **Runner** targets the focused set of crypto unit tests to keep mutation
  test runs under 30 minutes.
- **CI** runs nightly via `.github/workflows/mutation-testing.yml` on a
  cron schedule.  Surviving mutants are reported as warnings; the workflow
  does not block merges (informational mode) while we work toward a 100%
  kill rate.
- **Makefile** targets `mutation-test` and `mutation-test-report` are
  available for local developer use.

### Cross-Implementation Differential Fuzzing

We extend the verifier batch hash tools (`hash_batch` in Go, Rust, and
JavaScript) to support three operations via an `op` field:

| Operation | Description |
|-----------|-------------|
| `blake3` | Raw BLAKE3 hash (backward compatible default) |
| `merkle_leaf_hash` | Domain-separated leaf hash (`OLY:LEAF:V1`) |
| `merkle_root` | Full Merkle tree root via CT-style promotion |

A new `tests/test_differential_fuzz.py` module uses Hypothesis to generate
random inputs and feeds them to all four implementations (Python, Go, Rust,
JavaScript), asserting byte-for-byte identical outputs.

- **Python-only property tests** always run and verify determinism, output
  length, and domain separation invariants.
- **Cross-implementation tests** are gated behind the `differential` pytest
  marker and skip gracefully when toolchains are unavailable.
- Inputs are **batched** to minimize subprocess overhead.

## Consequences

### Positive

- Every line of crypto code that matters is provably covered by a test that
  catches a mutation.
- Edge-case divergences between implementations are caught early by
  Hypothesis-generated inputs.
- Developers can run `make mutation-test` locally to check crypto coverage.

### Negative

- Mutation testing adds ~10-30 minutes to nightly CI (not on every PR).
- Cross-implementation differential tests require Go, Rust, and Node.js
  toolchains and are slower than pure-Python tests.

### Risks

- mutmut may produce false positives for lines that are defensive/redundant
  by design.  These should be triaged and documented, not suppressed.

## Related

- ADR-0001: Incremental tree reconstruction
- `verifiers/cli/test_cross_language_determinism.py` (predecessor)
- `.github/workflows/verifier-conformance.yml` (conformance CI)
