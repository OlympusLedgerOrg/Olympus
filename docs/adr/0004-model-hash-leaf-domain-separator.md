# ADR-0004: Model-Hash Binding in the Leaf Hash Domain Separator

| Field      | Value                                  |
|------------|----------------------------------------|
| Status     | Accepted                               |
| Date       | 2026-05-28                             |
| Extends    | ADR-0003 (Parser-Version Binding)      |

## Context

ADR-0003 bound `parser_id` and `canonical_parser_version` into the leaf hash so
the ledger captures *which parser* produced a committed value. It explicitly
named a third provenance field — `model_hash` — that is surfaced by the
ingest-parser response but was *not* bound into the leaf hash.

That leaves a gap: two documents produced by the same parser binary
(`parser_id`) and the same operator-declared `canonical_parser_version`, but by
*different model weights* (e.g. a docling release that swaps an OCR/layout
model without bumping its package version), produce identical leaf hashes. The
cryptographic ledger therefore gives no guarantee about which model artifact
generated the committed content.

## Decision

Bind `model_hash` as a third length-prefixed provenance field, appended after
`canonical_parser_version`. Leaf hash becomes:

    BLAKE3(
        OLY:LEAF:V1 || SEP ||
        key || SEP ||
        value_hash || SEP ||
        len(parser_id)[4B BE] || parser_id || SEP ||
        len(canonical_parser_version)[4B BE] || canonical_parser_version || SEP ||
        len(model_hash)[4B BE] || model_hash
    )

### Decision details

1. **Migration policy:** None. As with ADR-0003, no pre-launch ledger exists,
   so there are no committed leaves to migrate. There is no dual-format window.
2. **model_hash semantics:** An opaque, non-empty UTF-8 string identifying the
   parser's model artifact — typically a content hash of the model weights
   (e.g. `"blake3:<hex>"`). The runtime treats it as an opaque tag; only
   non-emptiness is enforced.
3. **Wire placement:** A single new length-prefixed field appended after
   `canonical_parser_version`, not encoded into the `OLY:LEAF:V1` prefix
   string. `OLY:LEAF:V1` remains a fixed static protocol marker. Reusing the
   ADR-0003 length-prefix discipline keeps the new field collision-safe against
   its neighbours (`(cpv="ab", model="c")` ≠ `(cpv="a", model="bc")`).
4. **Operator configuration:** The ingest path resolves the provenance triple
   from environment, mirroring ADR-0003's `INGEST_PARSER_CANONICAL_VERSION`:
   - `OLYMPUS_INGEST_PARSER_ID` (default `"fallback@1.0.0"`)
   - `INGEST_PARSER_CANONICAL_VERSION` (default `"v1"`)
   - `OLYMPUS_INGEST_MODEL_HASH` (default `"none"`)
   Blank values fall back to the defaults; the resolved triple is always
   non-empty so it can never produce an unverifiable leaf.
5. **Test vectors:** The SSMF (SMT) conformance vectors were regenerated. The
   generator is `crates/olympus-crypto/examples/gen_ssmf_vectors.rs`; the offline
   verifiers (`verifiers/rust`, `verifiers/javascript`) now load the SMT vectors
   directly from `verifiers/test_vectors/vectors.json` rather than from
   copy-pasted constants, so a single regeneration keeps every implementation in
   sync.

## Consequences

- The canonical Rust signature is now
  `olympus_crypto::leaf_hash(key, value_hash, parser_id,
  canonical_parser_version, model_hash)`, consumed by `src-tauri` and both
  verifiers. The in-memory and persistent SMTs (`olympus_crypto::smt`,
  `src-tauri::smt`) carry `model_hash` on each leaf record and proof.
- `smt_leaves` gains a `model_hash TEXT NOT NULL` column (migration 0036).
- Every cross-language verifier accepts a third required provenance input when
  computing leaf hashes; an empty `model_hash` is rejected, exactly like
  `parser_id` / `canonical_parser_version`.
- All SMT golden vectors regenerated in the same change; the global fixture
  root moved accordingly.

## Rejected alternatives

- Encoding `model_hash` into the prefix string: rejected for the same reason as
  ADR-0003 — prefix strings are static protocol markers, not variable data.
- A separate `leaf_hash_v2`: rejected because v1 has no committed callers; just
  extend v1 (consistent with ADR-0003's reasoning).
- Binding `model_hash` into the Poseidon snapshot tree / ZK circuit instead:
  out of scope. That tree is constrained by the
  `unified_canonicalization_inclusion_root_sign` circuit and changing it would
  require a new trusted-setup ceremony. ADR-0004 concerns the BLAKE3 SMT leaf
  domain only.
