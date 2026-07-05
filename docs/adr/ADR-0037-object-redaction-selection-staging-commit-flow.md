# ADR-0037: Object-Based Redaction Selection, Staging, and Commit Flow

## Status

Accepted.

This ADR was supplied as `ADR-0031`, but the repository already uses ADR-0031 for
transition attestations and insert-only ledger enforcement. It is therefore
recorded as ADR-0037, the next unused ADR number.

## Context

Olympus supports object-based document redaction on top of the object/segment
redaction scheme established in ADR-0025, ADR-0026, ADR-0028, ADR-0030, and
ADR-0034. Users interact with a rendered document view and select
backend-derived objects or segments for redaction.

Object selection in the UI is security-sensitive input, not a security decision.
Object IDs, bounding boxes, page coordinates, and selection state that originate
in the frontend can be spoofed, stale, or wrong, and must never be treated as
authoritative. The Rust backend owns the canonical `SegmentManifest`, performs
all validation, stages proposed redactions, emits structured warnings for
dangerous object relationships, commits length-preserving redaction mutations,
updates the manifest when a durable publish path exists, and produces the live
redaction proof artifact.

Live v0.10.x redaction is ADR-0030 V3 signed-Merkle redaction, not the retired
Groth16 `redaction_validity` circuit. Any `proof_id` in this ADR therefore
refers to the live proof artifact or bundle handle for the active redaction
scheme. This ADR does not reintroduce a redaction SNARK or alter ZK ceremony
requirements.

Prior redaction bugs RD-01 (stream-keyword substring matching) and RD-02 (object
identity bound only to `obj_id`, not generation) showed that PDF object identity
and stream relationships are easy to mishandle. Any new redaction surface must
assume the same class of bug is possible again and design against it rather than
relying on careful frontend code.

## Decision

Adopt a three-step redaction flow backed by the canonical manifest:

1. `get_page_objects`
2. `stage_redaction`
3. `commit_redaction`

The frontend may display page images, object bounds, drag selections, click
selections, previews, and warnings, and may propose `object_id`s for staging. It
is never the source of truth for redaction validity. All final validation happens
in Rust against the live canonical manifest at commit time.

## Staging Rules

For V1, a staging entry is page-scoped: all `object_id`s in a single
`stage_redaction` call must belong to the same document, page, and manifest
version. Cross-page staging is rejected with `InvalidObjectSelection`.
Multi-page redaction sets are a future extension.

Rust re-resolves every `object_id` against the live manifest before staging. If
the supplied `manifest_version` does not match the live version, staging fails
with `ManifestVersionMismatch` rather than silently staging against a stale
snapshot.

`stage_redaction` deduplicates and canonicalizes `object_id`s before creating a
staging entry. The canonical staging set is sorted by manifest order, not
frontend selection order, so warnings, previews, and proof inputs are
deterministic regardless of click or drag order in the UI.

Warnings are structured and severity-bearing. If a condition makes safe,
precise redaction impossible, it must be represented as `Blocking` severity, and
`commit_redaction` must refuse to proceed with `BlockingRedactionWarning`.

| Condition | Severity |
|---|---|
| Shared stream, but the selected byte range is safely isolable | `Warning` |
| Shared stream where zero-fill would affect unselected visible content | `Blocking` |
| Annotation has an appearance stream not automatically included in selection | `Blocking` |
| Ambiguous text span surfaced from a UI click | `Info` |

## Commit Rules

Commit re-validates the staging entry:

- `staging.doc_id == doc_id`
- the staging record exists, is pending, and is not expired
- the live manifest version still matches the staged `manifest_version`
- stored and recomputed warnings have the same digest
- neither the stored nor recomputed warning set contains `Blocking` severity

Commit follows a candidate-artifact pattern rather than mutating in place:

1. Load and validate the staging entry.
2. Recompute warnings from the live manifest and verify `warning_digest`.
3. Build candidate redacted bytes off to the side.
4. Build a candidate manifest/root/proof artifact for the live redaction scheme.
5. Re-acquire the document write lock and re-check `manifest_version`.
6. Atomically publish the candidate durable state when the repository has a
   durable artifact storage path for this flow.
7. Transition the staging record from `Pending` to `Consumed`, retaining the
   tombstone until the original `expires_at`.

If proof generation or the final version re-check fails, no candidate state is
published.

## Staging Lifecycle

```rust
enum StagingRecord {
    Pending(RedactionStagingEntry),
    Consumed {
        doc_id: String,
        consumed_at: DateTime<Utc>,
        resulting_manifest_version: u64,
    },
}

struct RedactionStagingEntry {
    doc_id: String,
    page_num: u32,
    manifest_version: u64,
    object_ids: Vec<String>,
    warnings: Vec<RedactionWarning>,
    warning_digest: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}
```

- Default TTL: 15 minutes.
- Staging entries live in `AppState`, protected by document-scoped write-lock
  discipline, and must not be persisted to Postgres.
- A staged redaction is valid only against the exact manifest version from which
  it was created.
- Warning validation at commit is not digest-only: Rust checks the structured
  warning severities explicitly.
- A `staging_id` is single-use and backed by a short-lived consumed tombstone.

## Error Model

```rust
enum RedactionError {
    ObjectNotFound { object_id: String },
    AlreadyRedacted { object_id: String },
    ManifestVersionMismatch { expected: u64, actual: u64 },
    StagingNotFound,
    StagingExpired,
    StagingStale,
    StagingAlreadyConsumed,
    BlockingRedactionWarning { code: RedactionWarningCode },
    ProofGenerationFailed,
    ManifestUpdateConflict,
    InvalidObjectSelection,
    InvalidObjectGeometry { object_id: String },
}
```

All failures are fail-closed: no partial redaction state is ever persisted.

## Coordinate Contract

`get_page_objects` returns object bounds in canonical page-space units, not
rendered pixel-space. The backend normalizes page rotation before emitting
bounds, so the frontend receives one stable orientation per page.

This ADR chooses bottom-left, rotation-normalized page-space:

- `x`: distance from the left edge of the normalized page.
- `y`: distance from the bottom edge of the normalized page.
- `w`, `h`: width/height in page-space units.
- `page_width`, `page_height`: normalized page dimensions in page-space units.

`page_num` is zero-based across all commands. Human-facing page labels are a UI
display concern only.

The backend guarantees emitted bounding boxes are finite, non-NaN,
non-negative, and clipped to the normalized page extent. Objects with invalid or
unavailable geometry are omitted from selectable page-object results rather than
being guessed.

## Non-Goals

- This ADR does not change the on-disk redaction format or proof circuit.
- This ADR does not define a durable, cross-session draft redaction set feature.
- This ADR does not require the TypeScript frontend to perform
  security-sensitive crypto or manifest validation.

## Consequences

- Adds an ephemeral in-memory staging table to `AppState`.
- Requires warning-detection logic for shared streams, shared XObjects,
  ambiguous text spans, and annotation appearance streams.
- Requires any future durable `commit_redaction` implementation to use the
  candidate-artifact pattern rather than in-place mutation with rollback.
- Requires UI-facing page geometry to remain presentation-only and
  backend-derived.
