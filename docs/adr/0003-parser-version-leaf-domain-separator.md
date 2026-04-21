# ADR-0003: Parser-Version Binding in the Leaf Hash Domain Separator

| Field      | Value                                  |
|------------|----------------------------------------|
| Status     | Accepted                               |
| Date       | 2026-04-20                             |
| Supersedes | ADR-0003 (Proposed, 2026-04-18)        |

## Context

The current leaf hash is `BLAKE3(OLY:LEAF:V1 || | || key || | || value_hash)`.
Parser provenance (`canonical_parser_version`, `parser_id`, `model_hash`) is
captured in the ingest-parser response but never enters the leaf hash.
Two documents parsed with different docling versions produce identical
leaf hashes — the cryptographic ledger gives no guarantee about which
parser produced the committed content.

## Decision

Leaf hash becomes:

    BLAKE3(
        OLY:LEAF:V1 || SEP ||
        key || SEP ||
        value_hash || SEP ||
        len(parser_id)[4B BE] || parser_id || SEP ||
        len(canonical_parser_version)[4B BE] || canonical_parser_version
    )

### Decision details

1. **Migration policy:** None. Pre-launch, no ledger active, no committed leaves.
2. **parser_id format:** `"<name>@<version>"` (e.g. `"docling@2.3.1"`).
   Fallback parser uses `"fallback@1.0.0"`. Empty string rejected.
3. **canonical_parser_version:** Opaque string, set by operator via
   `INGEST_PARSER_CANONICAL_VERSION`. Default `"v1"`. Empty string rejected.
4. **Wire placement:** Two new length-prefixed fields appended after
   `value_hash`, not encoded into the `OLY:LEAF:V1` prefix string.
   `OLY:LEAF:V1` remains a fixed static protocol marker.
5. **Test vectors:** All golden vectors regenerated. No dual-format support.

## Consequences

- Every cross-language verifier (Go/Rust/Python/JS) must accept two new
  required inputs when computing leaf hashes.
- The PyO3 `leaf_hash` signature changes: adds `parser_id: str` and
  `canonical_parser_version: str` parameters.
- The Rust standalone crate `cdhs-smf-rust/src/crypto.rs::hash_leaf` signature
  changes identically.
- Tests and golden vectors regenerated in the same PR.

## Rejected alternatives

- Encoding parser fields into the prefix string (e.g. `OLY:LEAF:V1:parser=X`):
  rejected because prefix strings should be static protocol markers, not
  variable data, and because length-prefixed fields give automatic
  collision safety.
- Dual-format compat window: rejected because no ledger exists to migrate.
- Using a separate `leaf_hash_v2` function: rejected because v1 has no
  committed callers; just change v1.
