# Accepted/Ratified ADR Code Re-verification - 2026-06-30

Scope: every ADR in `docs/adr` whose status is Accepted/Accepted implemented, plus ADR-0030 because it contains ratified decisions even though the file status remains Proposed.

Method: static trace from ADR invariants to the current Rust/Tauri, verifier, migration, circuit, and frontend code; targeted tests for the highest-risk cryptographic surfaces.

## Executive summary

Most implemented invariants match the current code. The main problems are documentation/status drift, not failed tests:

1. ADR-0009 is stale against current Poseidon domain tags and proof-bundle metadata.
2. ADR-0025/0026/0028 still describe the Groth16 redaction era in places; live code has moved to ADR-0030 V3 signed-Merkle redaction.
3. ADR-0030's ratified V3 decisions are largely implemented, but the file still says Proposed and manifest lookup/storage remains keyed by `content_hash`.
4. ADR-0033 is stale: accepted ADR says checkpoint-quorum V1/root-only, while live code and vectors are V2 with `chain_id` and `epoch`.
5. `docs/adr/README.md` is stale for at least ADR-0026 (listed Proposed despite accepted file status) and omits ADR-0028.

## Verification matrix

| ADR | Current code verdict | Evidence |
|---|---|---|
| ADR-0003 parser-version leaf binding | PASS | `olympus_crypto::leaf_hash` binds parser fields; ingest resolves non-empty defaults; SMT/verifiers carry parser metadata. |
| ADR-0004 model-hash leaf binding | PASS | `leaf_hash` takes `model_hash`; migration `0036` adds `smt_leaves.model_hash`; ingest default is `none`; verifiers/vectors include `model_hash`. |
| ADR-0005 structured leaf prefix + shard binding | PASS | `LEAF_BODY_FIELD_COUNT = 0x05`; `leaf_hash` uses structured prefix and length prefixes; SMT write/verify rejects shard/key-prefix mismatch. |
| ADR-0009 Poseidon hash suite | DRIFT | ADR says leaf/node domain tags are `0`/`1` and bundles include `hash_suite`; current code uses `DOMAIN_LEAF = 1`, `DOMAIN_NODE = 2`, and no `hash_suite` field was found. |
| ADR-0022 lazy deep-node SMT storage | PASS | `LAZY_DEPTH = 72`, `CANOPY_RECOMPUTE_CAP = 1024`, write-lock section and over-cap persistence are implemented; migration `0044` preserves over-cap deep rows. |
| ADR-0025 PDF object-level redaction | SUPERSEDED/DRIFT | Core PDF object commitment survives, but the ADR still describes `redaction_validity`, fixed 1024/depth-10, and ceremony work. Live code uses ADR-0030 variable-depth V3 signed bundles and removed the redaction circuit. |
| ADR-0026 multi-format segment producer | PASS WITH AMENDMENTS | Segment abstraction, PDF/text/OOXML, hiding leaves, and manifest persistence exist. Stale parts still mention unchanged Groth16 circuit and 1024-leaf witness. |
| ADR-0027 dataset manifest commitments | PASS | `crates/olympus-manifest`, `clients/cli`, Python verifier package, path-compressed SMT builder, diff domain, and parity tests are present. |
| ADR-0028 modern-PDF xref-stream redaction | PASS WITH AMENDMENTS | `pdf_xref` segmenter implements xref-stream/ObjStm parsing and rebuild-to-traditional redaction. Stale "no circuit/verifier/ceremony change" text should now be read through ADR-0030. |
| ADR-0030 signed-Merkle redaction ratified decisions | MOSTLY PASS | V3 bundle domains, nullifier, canonical text signing, variable-depth fold, max segment cap, circuit removal, verifiers, vectors, and frontend verifier are present. Remaining drift: file status still Proposed; manifest DB/API lookup still uses `content_hash`. |
| ADR-0032 retire witness-over-root scaffold | PASS | No live `verify_witness` / `witness_cosignature` implementation found; checkpoint/quorum path owns the co-signature surface. |
| ADR-0033 checkpoint-quorum co-signatures | DRIFT AHEAD | Live code implements `OLY:CHECKPOINT:QUORUM:V2` with `chain_id` and `epoch`; ADR title/body still describe V1/root-only Phase 1 with Phase 2 future. |
| ADR-0034 fixed-width redaction tokens | PASS | Text uses `[REDACTED]\n`; traditional PDF rebuilds with `null`; OOXML empties parts; verifiers check canonical destroyed forms. |

## Specific findings

### ADR-0009 stale Poseidon contract

ADR-0009 states:
- Merkle leaf tag `0`
- Merkle internal-node tag `1`
- every proof bundle includes `{"hash_suite":"poseidon-bn254-v1"}`

Current code states and uses:
- `DOMAIN_LEAF = 1`
- `DOMAIN_NODE = 2`
- no `hash_suite` or `poseidon-bn254-v1` occurrence in `src-tauri`, `app`, `verifiers`, `proofs`, or `crates`.

This appears to be an ADR update gap after the later NODE=2 split. The code has tests pinning current Poseidon parity, so the fix is likely documentation and, if still desired, adding explicit hash-suite metadata to proof bundles.

### Redaction ADR status drift

ADR-0025 and parts of ADR-0026/0028 are now historical. Current redaction is ADR-0030 V3:

- `proofs/setup_circuits.sh` release circuits include only `document_existence` and `non_existence`.
- `proofs/CEREMONY_INTEGRITY.md` records that `redaction_validity` was removed.
- `src-tauri/src/zk/segment.rs` implements variable-depth folding with `MAX_REDACTION_SEGMENTS = 1 << 20`.
- `src-tauri/src/api/redaction/bundle_v3.rs` implements the V3 signed table, nullifier, canonical-form checks, and Ed25519 signature.
- `verifiers/rust/src/redaction.rs`, `verifiers/javascript/test_redaction.js`, and `app/public-ui/src/lib/redactionBinding.ts` mirror the V3 verifier.

Recommended doc cleanup: mark ADR-0025 as superseded/amended by ADR-0026 and ADR-0030, mark ADR-0030 Accepted/Ratified or split the ratified portion into an accepted ADR, and update stale migration/API comments that still describe `redaction_validity` or fixed 1024-leaf witnesses.

### ADR-0030 content-hash lookup drift

The ratified SR-DEC-1 removed `content_hash` from V3 bundles. The bundle code honors that. However, producer and manifest APIs still resolve manifests by `content_hash`:

- `redaction_segment_manifests` primary key is `(content_hash, shard_id)`.
- `GET /redaction/manifest/{content_hash}` remains the operator listing endpoint.
- `/redaction/redact` computes `content_hash = BLAKE3(original bytes)` and calls `load_object_manifest(&state, &content_hash)`.

This does not reintroduce `content_hash` into the recipient bundle, but it does not fully match ADR-0030's "re-key the ledger lookup on original_root" implementation note.

### ADR-0033 live code is V2

ADR-0033 says V1 root-only and leaves `chain_id`/epoch binding for Phase 2. Current code already implemented Phase 2 as V2:

- `CHECKPOINT_QUORUM_PREFIX = b"OLY:CHECKPOINT:QUORUM:V2"`
- message binds `chain_id`, `epoch`, `root`, threshold, and signer set
- golden vectors are committed as V2

This is a good security direction; the accepted ADR should be amended or superseded so auditors do not treat V1/root-only as live.

### ADR index drift

`docs/adr/README.md` is not an accurate accepted-ADR index:

- ADR-0026 file status is Accepted, but the index says Proposed.
- ADR-0028 file status is Accepted, but the index does not list it in the table.
- ADR-0030 contains ratified decisions but remains Proposed in status.
- ADR-0033 title/status still says V1 while code is V2.

## Tests run

All targeted checks passed:

```text
cargo test -p olympus-crypto --features smt,poseidon
57 passed

cargo test -p olympus-manifest
27 passed

cargo test -p olympus-desktop redaction::bundle_v3
12 lib tests + 12 main tests passed

cargo test -p olympus-desktop quorum::checkpoint
10 lib tests + 10 main tests passed
```

Note: an initial parallel Cargo batch wedged on Cargo locks and was stopped; the checks above were rerun sequentially and completed successfully.

## Recommended follow-up patch set

1. Update ADR-0009 to reflect current domain tags (`LEAF=1`, `NODE=2`) or create a superseding ADR for the NODE=2 split; decide whether proof bundles should now gain `hash_suite`.
2. Update ADR-0025/0026/0028 statuses and language to mark fixed-1024/Groth16 redaction as superseded by ADR-0030.
3. Flip or supersede ADR-0030 so the ratified V3 design is not hidden inside a Proposed ADR.
4. Decide whether to migrate manifest lookup to `original_root` per ADR-0030 SR-DEC-1, or explicitly document that `content_hash` remains an issuer-side lookup key but is not shipped in bundles.
5. Update ADR-0033 to V2, including `chain_id`/epoch binding and the committed vector schema.
6. Refresh `docs/adr/README.md` to match actual ADR file statuses.
