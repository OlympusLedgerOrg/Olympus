# ADR-0034: Width-preserving redaction fill (space, not NUL)

- **Status:** **Accepted — 2026-06-23** (implemented in the same change).
- **Date proposed:** 2026-06-23
- **Builds on:** **ADR-0026** (multi-format object-level redaction producer +
  the `Segmenter`/`SegmentManifest` generalisation), **ADR-0028** (modern-PDF
  cross-reference-stream / ObjStm redaction by container rebuild), and
  **ADR-0030** (redaction is a signed Merkle fold, not a SNARK; the V3
  signed-Merkle bundle).
- **Related invariants:** the redaction binding holds only when every *revealed*
  segment is byte-identical to the original at the same offset (the
  recompute-the-revealed-leaves rule both offline verifiers enforce). This ADR
  does **not** touch that rule, any leaf/root/signature, or any golden vector.

## Context

Redaction destroys a selected segment's content while keeping every other
segment byte-identical, so the non-redacted leaves recompute and the bundle
binds. For the two **in-place** formats — traditional-xref PDF
(`zk::pdf_objects`) and text/Markdown (`zk::segment::text`) — "destroy" was
implemented as a **NUL (`0x00`) fill** of the redacted byte span: same length,
same offsets, every other byte untouched.

NUL fill preserves *byte-width* but is hostile to anything that consumes the
artifact as text:

- A redacted text line becomes a run of NUL bytes, not a blank line. NUL
  truncates C-style string reads, trips "binary file" heuristics in editors,
  greppers, and diff tools, and renders as replacement glyphs / nothing.
- The redacted region no longer reads as the *whitespace* a reader expects
  where text was removed; the document's visual layout collapses into garbage at
  the redaction site even though the bytes are technically present.

The OOXML segmenter (`zk::segment::ooxml`) went further and **emptied** the
redacted part's payload (length → 0), which is not width-preserving at all: the
part's byte-length is lost.

We want redaction output that preserves width *and* reads cleanly: a redacted
unit should look like blank space of the right size.

## Decision

Introduce a single shared fill constant and use it across the in-place / canonical
segmenters:

```rust
// crates… no — src-tauri/src/zk/segment.rs
pub const REDACTION_FILL_BYTE: u8 = b' '; // ASCII space, 0x20
```

- **Traditional PDF** (`pdf_objects::apply_redaction`) and **text/Markdown**
  (`text::apply_redaction`): overwrite the redacted span in place with
  `REDACTION_FILL_BYTE` instead of `0x00`. Length, offsets, xref, and every
  non-redacted segment stay byte-identical, exactly as before — only the fill
  byte changes.
- **OOXML** (`ooxml::redacted_parts`): overwrite the redacted part's payload with
  `REDACTION_FILL_BYTE` **to its original length** rather than clearing it, so the
  part keeps its byte-width in the canonical Stored-ZIP repackage. The part name
  still survives; the content is destroyed.
- **Modern PDF** (`pdf_xref`, ADR-0028): **unchanged.** This path is a structural
  *rebuild* — it reassigns every object offset and emits a fresh xref — so there
  is no original byte-width to preserve. The redacted object body remains the
  valid PDF `null` token, not a same-length space run. (Forcing a space fill here
  would produce an invalid object body and buy nothing, since the rebuild already
  changes all offsets.)

The fill is a **producer-only presentation choice**. A redacted segment's true
leaf is carried in the bundle (`leaf_hex`) and is *never* recomputed from artifact
bytes; only revealed segments are recomputed. So the fill byte enters no leaf,
root, signature, nullifier, or golden vector — the change is crypto-transparent.

## Security & invariant analysis

- **Binding is untouched.** Revealed segments are still byte-identical to the
  original; redacted segments are still authoritative via `leaf_hex`. The
  recompute-the-revealed-leaves check both verifiers run is unaffected, so issued
  bundles continue to verify and no vectors regenerate.
- **Content hiding is unchanged.** Redacted plaintext is overwritten in place
  (the existing "plaintext must be ABSENT from the artifact" security tests still
  hold — spaces do not reproduce the secret). The redacted leaf stays a hiding
  Pedersen→Poseidon commitment (ADR-0026); nothing about brute-force resistance
  changes.
- **Size disclosure (the one real tradeoff).** Width-preservation inherently
  reveals the *byte-length* of redacted content: the span keeps its size. For the
  in-place formats this was already true (the file length and per-segment
  offsets/lengths are public). For **OOXML** this is a *new* disclosure — the
  previous empty-payload behaviour leaked length 0; the new behaviour publishes
  the redacted part's original byte-length. This is accepted and intended: it is
  the defining property of width-preserving redaction. **Width-preserving
  redaction hides content, not size.** An operator who must also hide size should
  not redact in place — that is a different primitive (e.g. removing the unit
  entirely and re-folding), out of scope here.
- **No new attack surface.** No new parser, renderer, or native dependency; the
  byte-fill loop and the OOXML repackage are the same code paths as before with a
  different fill value / length.

## Consequences

- Redacted text/PDF artifacts read as clean whitespace of the correct width;
  redacted OOXML parts keep their byte-width.
- One shared `REDACTION_FILL_BYTE` constant is the single source of truth for the
  fill across all in-place / canonical segmenters.
- Modern-PDF redaction stays a `null`-token rebuild (documented as deliberate).
- The legacy chunk fallback (`zk::redact`, retained only for pre-segment sealed
  records and un-segmentable inputs) is unchanged; it already takes a caller-
  supplied fill byte and is not a live segment producer.

## Alternatives considered

- **Keep NUL.** Rejected — byte-width is preserved but the artifact is hostile to
  text tooling and does not read as blank space, defeating the point of an
  in-place redaction a human inspects.
- **A visible marker (`X` / `█`).** Rejected as the default — a marker is not
  byte-width-equal for multi-byte glyphs and editorialises the artifact; ASCII
  space is the neutral, width-exact choice. A marker remains a trivial future
  knob (the constant is one byte) if a product surface wants it.
- **Force a space fill into the modern-PDF rebuild.** Rejected — the rebuild has
  no original byte-width to preserve and a whitespace object body is invalid PDF;
  `null` is the correct destroyed-object token.
