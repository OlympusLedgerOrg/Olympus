# Federation + Ingest + Verifiers Audit

**Date:** 2026-04-19  
**Scope:** federation quorum logic, ingest parser determinism evidence, and cross-language verifier parity  
**Classification:** Public

---

## 1. Scope and audited claims

This audit consolidates three evidence tracks into one deliverable:

1. **Federation quorum logic end-to-end**
   - Claim: federation signatures are bound to the correct node identity, header commitment, validator set, and epoch; duplicate or malformed signatures do not count toward quorum; quorum certificates are verifiable and replay-resistant.
2. **Ingest parser determinism + ADR-0003 status**
   - Claim: the ingest parser service exposes a deterministic contract with explicit provenance fields and stable schema validation.
   - Non-claim: ADR-0003 parser-version binding is **not** currently enforced in the leaf hash. The ADR remains proposed/doc-only.
3. **Cross-language verifier parity**
   - Claim: Python, Go, Rust, and JavaScript verifiers consume the same fixed vectors and agree on randomized hash outputs under the existing `OLY:LEAF:V1` / `OLY:NODE:V1` contract.

---

## 2. Evidence matrix

| Section | Claim | Code | Tests / vectors | Manual review / notes |
|---|---|---|---|---|
| Federation | Vote signatures are bound to node identity, event, shard root, epoch, and validator set | `/home/runner/work/Olympus/Olympus/protocol/federation/quorum.py` | `/home/runner/work/Olympus/Olympus/tests/test_federation.py` | Review canonical vote payload construction, registry key lookup, and `event_id` derivation |
| Federation | Duplicate, invalid, or inactive-node signatures do not count toward quorum | `/home/runner/work/Olympus/Olympus/protocol/federation/quorum.py` | `/home/runner/work/Olympus/Olympus/tests/test_federation.py`, `/home/runner/work/Olympus/Olympus/tests/test_federation_multinode_integration.py` | Review `seen_nodes`, active-node filtering, and header-hash commitment checks |
| Federation | Quorum threshold and certificate verification are end-to-end verifiable | `/home/runner/work/Olympus/Olympus/protocol/federation/quorum.py`, `/home/runner/work/Olympus/Olympus/protocol/federation/__init__.py` | `/home/runner/work/Olympus/Olympus/tests/test_federation.py`, `/home/runner/work/Olympus/Olympus/tests/test_federation_multinode_integration.py` | Review signer bitmap, canonical node-id ordering, membership hash, epoch snapshot, and certificate hash binding |
| Ingest | Service exposes deterministic parse/health contract with provenance | `/home/runner/work/Olympus/Olympus/services/ingest-parser/src/ingest_parser/main.py` | `/home/runner/work/Olympus/Olympus/services/ingest-parser/tests/test_api.py` | Review lifespan initialization, CPU-only setup, hash verification, and provenance fields returned by `/parse` and `/health` |
| Ingest | Schema validation enforces stable provenance/version structure and numeric rounding | `/home/runner/work/Olympus/Olympus/services/ingest-parser/src/ingest_parser/schemas.py`, `/home/runner/work/Olympus/Olympus/services/ingest-parser/src/ingest_parser/parser.py` | `/home/runner/work/Olympus/Olympus/services/ingest-parser/tests/test_schemas.py` | Review `canonical_parser_version` pattern, BLAKE3/SHA-256 prefixes, and 4-decimal rounding rules |
| Ingest | ADR-0003 is only proposed; parser version is not yet bound into leaf hashing | `/home/runner/work/Olympus/Olympus/docs/adr/0003-parser-version-leaf-domain-separator.md`, `/home/runner/work/Olympus/Olympus/protocol/hashes.py`, `/home/runner/work/Olympus/Olympus/services/cdhs-smf-rust/src/crypto.rs` | Existing verifier vectors remain V1-based: `/home/runner/work/Olympus/Olympus/verifiers/test_vectors/vectors.json` | Manual review confirms `OLY:LEAF:V1` is still active; no accepted migration or parser-id wire-format change exists |
| Verifiers | All language verifiers consume the same fixed vector source of truth | `/home/runner/work/Olympus/Olympus/verifiers/README.md` | `/home/runner/work/Olympus/Olympus/verifiers/test_vectors/vectors.json`, `/home/runner/work/Olympus/Olympus/verifiers/cli/test_conformance.py`, `/home/runner/work/Olympus/Olympus/verifiers/go/conformance_test.go`, `/home/runner/work/Olympus/Olympus/verifiers/javascript/test_conformance.js`, `/home/runner/work/Olympus/Olympus/verifiers/rust/src/lib.rs` | Review domain-separation constants and vector coverage categories |
| Verifiers | Randomized parity harness detects cross-language drift | `/home/runner/work/Olympus/Olympus/verifiers/cli/test_cross_language_determinism.py` | Randomized harness plus `.github/workflows/verifier-conformance.yml` | Review deterministic seed, batch execution, and CI coverage across Python/Go/Rust/JS |

---

## 3. Federation review results

### Automated evidence

- `/home/runner/work/Olympus/Olympus/tests/test_federation.py`
- `/home/runner/work/Olympus/Olympus/tests/test_federation_multinode_integration.py`

These tests cover:

- quorum threshold calculation for 3-node and 4-node registries
- duplicate-signature rejection
- wrong-header and event-id replay rejection
- validator-set, membership-hash, and epoch mismatch rejection
- canonical signature ordering and signer bitmap validation
- registry-based key lookup and node-identity binding
- multi-node certificate creation and verification

### Manual-review / red-team checklist

- [x] **Replay resistance:** verify `event_id` binds shard, header hash, timestamp, epoch, and membership hash
- [x] **Identity binding:** verify public keys are derived from the registry, not caller input
- [x] **Duplicate-signature handling:** verify duplicate node IDs are dropped before quorum counting
- [x] **Inactive-node rejection:** verify inactive nodes are skipped during validation
- [x] **Quorum threshold correctness:** verify threshold is based on active membership and not raw signature count
- [x] **Certificate verification:** verify signer bitmap, canonical order, certificate hash, epoch snapshot, and membership commitments are checked

### Result

**Pass, with good evidence coverage.** The existing federation test suite already exercises the core red-team scenarios requested by this audit.

---

## 4. Ingest parser review results

### Current deterministic contract

The ingest parser service returns provenance from `/parse` and `/health` using:

- `raw_file_blake3`
- `parser_name`
- `parser_version`
- `canonical_parser_version`
- `model_hash`
- `environment_digest`

Schema validation in `/home/runner/work/Olympus/Olympus/services/ingest-parser/src/ingest_parser/schemas.py` also enforces:

- exact `blake3_` / `sha256_` prefix formats
- `canonical_parser_version` pattern `v<major>.<minor>`
- 4-decimal rounding for bounding boxes, confidence, and page dimensions

### ADR-0003 status

ADR-0003 (`/home/runner/work/Olympus/Olympus/docs/adr/0003-parser-version-leaf-domain-separator.md`) is still **Proposed** and explicitly states that implementation is deferred. Current code still uses:

- `/home/runner/work/Olympus/Olympus/protocol/hashes.py` → `LEAF_PREFIX = b"OLY:LEAF:V1"`
- `/home/runner/work/Olympus/Olympus/services/cdhs-smf-rust/src/crypto.rs` → `const LEAF_HASH_PREFIX: &[u8] = b"OLY:LEAF:V1";`

### Result

**Partial pass.** Deterministic service/schema evidence exists and is now exercised by the ingest-parser API tests, but ADR-0003 parser-version binding is not live and must not be claimed as enforced.

---

## 5. Cross-language verifier parity results

### Fixed-vector evidence

The verifier contract is documented in `/home/runner/work/Olympus/Olympus/verifiers/README.md` and fixed vectors live in `/home/runner/work/Olympus/Olympus/verifiers/test_vectors/vectors.json`.

Coverage includes:

- raw BLAKE3 hashes
- Merkle leaf and parent hashing
- Merkle roots with odd-leaf promotion
- Merkle proof verification
- canonicalizer regression vectors
- ledger-entry hashing
- verification-bundle vectors

### Randomized parity evidence

`/home/runner/work/Olympus/Olympus/verifiers/cli/test_cross_language_determinism.py` generates deterministic random records using a fixed seed and compares Python, Go, Rust, and JavaScript outputs batch-for-batch. CI executes the same parity workflow in `/home/runner/work/Olympus/Olympus/.github/workflows/verifier-conformance.yml`.

### Result

**Pass under the current V1 hash contract.** The verifier system has both fixed-vector conformance and randomized parity coverage.

---

## 6. Observed gaps / blockers

1. **ADR-0003 enforcement gap**
   - Parser version is not yet part of the leaf-hash domain separator.
   - This remains a protocol decision and implementation gap, not a test gap.

2. **Parser determinism vectors are still missing as first-class audit artifacts**
   - The ingest parser has deterministic API/schema tests, but no committed parser-output vector corpus comparable to `verifiers/test_vectors/vectors.json`.

3. **Ingest test suite setup required correction**
   - The ingest-parser API tests needed lifespan-aware `TestClient` setup so startup initialization runs and the service contract is exercised correctly.

4. **No standalone parity results artifact**
   - Verifier parity is enforced by tests and CI, but there is no committed results snapshot/report outside the test harness itself.

---

## 7. Final status

| Section | Status | Notes |
|---|---|---|
| Federation quorum logic | **Pass** | Existing tests plus manual review cover the requested red-team scenarios |
| Ingest parser determinism | **Partial pass** | Deterministic contract and schema evidence exist; ADR-0003 remains proposed and unenforced |
| Cross-language verifier parity | **Pass** | Fixed vectors, randomized harness, and CI workflow all exist under the current V1 hash contract |

## 8. Recommended follow-on work

1. Add committed ingest parser determinism vectors.
2. Preserve the strengthened ingest-parser API tests as regression coverage for provenance fields.
3. If maintainers accept ADR-0003, implement the parser-id wire-format change and regenerate all verifier vectors.
4. Optionally publish a machine-readable parity-results artifact for audit consumers who do not run CI locally.
