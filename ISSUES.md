# Open Issues

## 14 - 1.0 Readiness

## Epic: Olympus v1.0 Readiness

### Problem

Olympus v1.0 requires coordinated completion of multiple critical and high-priority workstreams (correctness, compatibility, replication, testing, schema hardening, and documentation).  
Without a single aggregation point, blockers risk being missed or partially completed before release.

### Why this blocks 1.0

A v1.0 release implies:
- Cryptographic correctness
- Deterministic behavior across environments
- Verifiable replication and proofs
- Complete operator and auditor documentation

Absent centralized tracking, there is no reliable way to assert that **all release-blocking conditions have been satisfied**.

### Acceptance Criteria (objective, testable)

- All linked sub-issues are **closed**
- All sub-issues are assigned to either the `1.0` or `Phase 0.5` milestone
- No open issues with labels `critical` or `high-priority` remain
- `1.0` milestone review passes with:
  - Test suite green
  - No unresolved schema or replication concerns
  - Documentation sufficient for third-party verification
- This epic accurately represents the full Olympus v1.0 release scope (no known blockers tracked elsewhere)

---

## 15 - Fix Python 3.12 Deprecation Warnings (datetime.utcnow)

### Problem

Code and tests use deprecated `datetime.utcnow()` (8 instances), which will break in future Python versions.

### Why this blocks 1.0

Forthcoming Python releases will remove `datetime.utcnow()`. Shipping deprecated APIs causes near-term breakage and undermines platform longevity for v1.0.

### Acceptance criteria (objective, testable)

- All calls to `datetime.utcnow()` replaced with `datetime.now(timezone.utc)`
- Tests pass on Python 3.12+
- No deprecation warnings in test or CI output

---

## 16 - Resolve Type Safety Issues (mypy errors)

### Problem

There are 8 mypy errors: missing return type annotations and generic type parameter issues.

### Why this blocks 1.0

Lax type safety allows preventable bugs to ship, reducing maintainability. v1.0 must conform to strict mypy type checking for user and contributor trust.

### Acceptance criteria (objective, testable)

- All mypy errors are resolved
- All functions have return type annotations where expected
- mypy strict mode produces no errors in CI

---

## 17 - Clarify or Implement Guardian Replication

### Problem

Guardian Replication is documented in the specs as a finality requirement but is not implemented.

### Why this blocks 1.0

A spec-implementation gap invites confusion for integrators and risks functional incompleteness. Release 1.0 must clearly indicate if Guardian Replication is supported, or document as "Phase 1+ feature."

### Acceptance criteria (objective, testable)

- Guardian Replication is either implemented as described in the spec, or
- All documentation and user-facing references are clearly annotated as "Phase 1+ (not included in v1.0)"
- There is no ambiguity about Guardian Replication status in code, CLI, or docs

---

## 18 - Improve Test Coverage for Edge Cases and CLI

### Problem

Critical APIs and flows lack direct unit testing:
- `canonical_json_encode()` (only tested indirectly)
- `canonicalize_document()` (not tested directly)
- `Ledger` class (unit tests missing; only e2e present)
- CLI tools (untested)

### Why this blocks 1.0

Uncovered edge cases and untested interfaces risk regression. 1.0 needs end-to-end as well as direct and CLI-specific tests for confidence.

### Acceptance criteria (objective, testable)

- Direct unit tests exist for `canonical_json_encode()` and `canonicalize_document()`
- `Ledger` has unit tests in addition to e2e
- CLI tools are covered by automated tests
- Coverage metrics improve (or are justified as maximized) for all above

---

## 19 - Align JSON Schemas and Implementation

### Problem

JSON schemas in `schemas/` are not referenced by the API, which uses Pydantic models; schemas are orphaned, no runtime input validation is integrated.

### Why this blocks 1.0

Schema-implementation disconnect risks malformed inputs and interoperability bugs. v1.0 should reliably use schemas—or document their non-use conclusively.

### Acceptance criteria (objective, testable)

- Schemas are either linked to API validation or
- Documentation clearly states why schemas are not used in validation
- No unused or misleading schema artifacts
- CI verifies schema-implementation alignment or documented exceptions

---

## 20 - Clarify and Unify Database Strategy

### Problem

E2E tests assume Postgres while API tests use SQLite. The rationale for supporting both, or requirements for v1.0, are not documented.

### Why this blocks 1.0

Disagreement on supported database backends or test coverage can cause false confidence or spurious bugs in production.

### Acceptance criteria (objective, testable)

- Database support strategy is documented (test + prod)
- Rationale for test database choice is clear
- CI validates expected backend(s) consistently
- Contributors know which DB(s) to use in each context
