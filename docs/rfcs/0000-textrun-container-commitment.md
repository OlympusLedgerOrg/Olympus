# RFC-0000: Commit the container for `pdf-textrun`

| Field      | Value                                                        |
|------------|--------------------------------------------------------------|
| Status     | **Draft**                                                     |
| Author(s)  | OlympusLedgerOrg                                              |
| Date       | 2026-08-01                                                    |
| Tracking   | PR #1530 (the analysis this proposal answers)                 |
| Supersedes | Amends ADR-0029 Phase B (does not supersede it)               |

## Summary

`pdf-textrun` commits one hiding leaf per **word**. Everything else in the
document — whole images and fonts, and every operator, number, and inter-word
byte inside a content stream — is committed by nothing. Both offline verifiers
therefore refuse the format, and no amount of verifier-side container validation
can fix that: a verifier cannot constrain bytes the commitment never covered.

This RFC proposes extending the `pdf-textrun` leaf set from "words" to a
**partition of the artifact**, so that every byte is covered by exactly one leaf,
and making hex-string show operands word sources so text cannot be re-shown
through an uncommitted channel. With those two changes the format can be
promoted and the verifiers re-admit it.

## Motivation

ADR-0029 Phase B states that `pdf-textrun` "needs no new circuit / ceremony" and
reuses "the same offline verifiers — all reused." The first half is true; **the
second half is not**, and that is the gap this RFC closes.

Three concrete problems, verified against `main` and recorded in both verifiers'
`REJECTED_FORMATS` notes:

1. **Non-content objects are uncommitted.**
   `PdfTextRunSegmenter::apply_redaction_with_spans` starts from
   `new_bodies = bodies.clone()` and replaces only content objects. Images,
   fonts, and any other object survive into the artifact verbatim while no leaf
   covers them.

2. **A content stream's non-word bytes are uncommitted.** Only the words *inside*
   show-string operands are segments. The operators, coordinates, whitespace, and
   dictionary bytes around them are not.

3. **Hex-string show operands are an uncommitted text channel.**
   `show_string_ranges` sources words only from literal `( … )` operands; a
   hex-string operand (`<48656c6c6f> Tj`) is skipped entirely. A producer can
   re-show "redacted" text through a hex string that no leaf covers and no span
   inspects. The producer module documents this as "passed through verbatim (not
   word-sources) — documented, fail-soft"; measured against a *redaction* claim it
   is not fail-soft, it is a bypass.

Why the other formats do not have this problem: in `pdf-object`,
`pdf-xref-stream`, `text-line`, and `ooxml-part`, a segment **is** a container
unit. The verifier recovers them all with `artifact_spans`, pins the count with
`spans.len() == segments.len()`, and `validate_canonical_pdf_container` accounts
for every remaining byte. `pdf-textrun` is the first format whose segments are
*sub-units*, and the commitment was never extended to match.

**If we do nothing:** the format stays permanently rejected. Phase B's whole
premise — "prove the rest of the page is authentic; exactly these words were
removed" — cannot be delivered, because the bundle does not say anything about
the rest of the page.

## Detailed design

### The leaf set becomes a partition

For a `pdf-textrun` commitment, every logical object of the source PDF
contributes leaves, and every byte of every object is covered by exactly one
leaf:

| leaf kind | covers | count |
|---|---|---|
| **word** | one word inside a text-show operand of a content object | one per word |
| **skeleton** | a content object's bytes with every word span elided | one per content object |
| **object** | a non-content object's whole logical body | one per non-content object |

Bytes *outside* objects (the `%PDF-` header, the xref table, the trailer) need no
leaf: `validate_canonical_pdf_container` already pins them byte-exactly, and both
verifiers run it today for the other PDF formats.

### Skeleton leaves

A **skeleton** is the content object's decoded stream with each word's bytes
replaced by a single canonical elision byte (`0x00`), chosen so the skeleton is
*invariant under redaction*: redacting a word changes the word's bytes but not
the skeleton's. That invariance is what lets one leaf, committed at ingest over
the original, still reproduce from the redacted artifact.

```
content:  BT /F1 12 Tf (Hello SECRET) Tj ET
words:              ^^^^^ ^^^^^^
skeleton: BT /F1 12 Tf (\0 \0) Tj ET          ← committed
```

The verifier reconstructs the skeleton from the artifact by eliding exactly the
word spans it independently re-derived, and checks the leaf. Any edit to an
operator, a coordinate, or the whitespace between words now breaks that leaf.

> A skeleton elides *word extents*, not word *lengths* — one byte per word
> regardless of length — so it leaks nothing about redacted content and stays
> stable when `REDACTED_WORD_TOKEN` changes a word's length.

### Object leaves

Non-content objects are committed exactly as `pdf-xref-stream` commits them
today: one leaf over the trimmed logical body. This is deliberately the *same*
primitive and framing, so the verifier's existing `pdf-xref-stream` span recovery
is reused rather than reimplemented.

### Hex-string operands become word sources

`show_string_ranges` gains hex-string (`< … >`) operands. A hex string has no
internal whitespace structure, so **the whole string's content is one word**.

Its destruction token cannot be `REDACTED_WORD_TOKEN` — that is not valid hex.
Redacting a hex-string word replaces its content with a run of ASCII `0` of the
**same length**, which is valid hex, length-preserving (no reflow), and
unambiguously destroyed.

### Segment ordering and keying

One deterministic global sequence, so `extract` and `apply_redaction` agree and
the frontend can map a selection to ids:

1. objects in **obj-id ascending** order (as today);
2. within a content object: its **skeleton leaf first**, then its **words in
   stream order**;
3. a non-content object contributes its single **object leaf**.

`segment_id` remains a dense `0..N-1` index over that sequence, keyed
`segment_id.to_be_bytes()` — unchanged framing, so ADR-0005 length-prefixing and
the existing `redaction_leaf_for_segment` primitive are untouched.

### Skeleton and object leaves are not redactable

They exist to bind the container, not to be hidden. `apply_redaction` must reject
a request selecting one, the same way the structural-object guard already rejects
a `/Page` / `/Pages` / `/Catalog` selection (`SegmentError::StructuralObject`).
The manifest row carries the kind so the producer UI never offers them.

### Verifier contract

Both verifiers gain a `pdf-textrun` arm that:

- runs the existing canonical-container validation (reused from the
  `pdf-xref-stream` path — the artifact is the same rebuilt traditional-xref
  shape);
- **independently re-derives** every span: object spans from the xref, then within
  each content object the word spans from its own port of the tokenizer, and the
  skeleton span as the object's content extent;
- rejects when the bundle's declared `artifact_offset`/`artifact_length` disagrees
  with the re-derived span, as every format already does;
- checks a redacted word's span holds exactly the destruction token for its kind
  (`REDACTED_WORD_TOKEN` for literal, the `0`-run for hex);
- rejects any content object in the artifact that still carries a `/Filter` — the
  producer re-emits content objects uncompressed, so a filtered one means the
  artifact did not come from this producer. This lets the verifier avoid
  depending on an inflate implementation entirely.

### Compatibility and migration

**None required.** `pdf-textrun` has never shipped: `textrun-segmenter` is not a
default feature and is not wired into ingest dispatch, and both verifiers refuse
the tag. There is no persisted commitment in this format, so the leaf set can be
redefined outright rather than versioned. This is the last moment that is true.

Per ADR-0005 discipline, the schema, both offline verifiers, and the
cross-language vectors move in the **same commit** as the leaf-set change.

### Affected paths

- `src-tauri/src/zk/segment/pdf_textrun.rs` — leaf set, tokenizer, re-emit, guard
- `src-tauri/src/zk/segment.rs` — manifest row gains the segment kind
- `verifiers/rust/src/redaction.rs`, `verifiers/javascript/test_redaction.js` —
  the new arm; remove from `REJECTED_FORMATS`
- `verifiers/test_vectors/vectors.json` — positive + negative vectors
- `docs/adr/ADR-0029-*.md` — correct the "no verifier change" claim

## Security & invariant impact

- **Critical Invariants:** no change to `leaf_hash`, the SMT, node/leaf domain
  prefixes, or canonicalization. The hiding-leaf primitive
  (`redaction_leaf_for_segment`, `OLY:REDACTION:OBJ:V1`) and its
  `segment_id.to_be_bytes()` keying are reused verbatim. What changes is *which
  byte ranges become segments*, which is per-format policy, not protocol framing.
- **Circuits / vkeys / ceremony:** untouched. The fold treats leaves as opaque
  field elements; more leaves of more kinds is still a flat fold.
- **New guarantee.** A `pdf-textrun` bundle currently asserts "these words hash to
  these leaves." After this RFC it asserts "**this artifact** is the committed
  document with exactly these words destroyed" — the claim Phase B always
  intended and a court reader would assume.
- **Corrects a false statement in ADR-0029.** Phase B's "same offline verifiers —
  all reused" is wrong today and stays wrong until this lands; the ADR should say
  so.
- **New assumption for auditors:** that the skeleton elision is invariant under
  redaction. If a future re-emit changed bytes outside word spans, skeleton leaves
  would stop reproducing — loudly, as a verification failure, which is the correct
  direction to fail.

## Alternatives considered

- **Residue leaf** — one leaf over "everything that is not a word". Rejected: the
  residue is *not* invariant under redaction. Content objects are re-emitted
  uncompressed with a new `/Length`, so the artifact's residue never matches the
  residue committed at ingest.
- **Narrow the claim instead** — keep words-only and document that the bundle
  covers words alone. Rejected: these bundles are court evidence. A "redaction
  bundle" that is silent about the rest of the document invites exactly the
  misreading the verifiers' rejection note describes.
- **Make every object a segment, drop word granularity** — that is `pdf-object`,
  and it discards the sub-page redaction Phase B exists to provide.
- **Rasterize the page and commit pixels** — already rejected by ADR-0023/0024;
  a renderer must never become the commitment source.

## Drawbacks & risks

- **Leaf count grows.** Skeleton + object leaves add roughly one leaf per object
  on top of the word leaves. The §6a prototype measured ~4k word leaves for a
  28-page document against the `MAX_REDACTION_SEGMENTS` (2¹⁶) cap, so headroom
  remains, but the cap interacts with B-4's run-block grouping and should be
  re-measured on a dense document.
- **Skeleton leaves make the format brittle to producer changes.** Any alteration
  to content-stream re-emission invalidates previously committed skeletons and
  forces re-ingest. That is the intended trade — it is the same property that
  makes the container tamper-evident.
- **Hex-string words are coarse.** A whole hex string is one segment, so a user
  cannot redact one word of hex-encoded text without hiding the whole run.
- **Two more verifier ports.** The word tokenizer must be re-implemented
  byte-exactly in Rust and JavaScript and pinned by vectors. That is the standard
  verifier pattern here, but it is real work and a real drift risk.

## Unresolved questions

- **Hex-string granularity.** Whole-string is the conservative start. Splitting on
  decoded glyph runs would need font `/Encoding` awareness in the segmenter —
  worth it, or leave coarse?
- **Elision byte.** Is a bare `0x00` sufficient, or should the skeleton be
  domain-separated (e.g. length-prefixed word count) to remove any chance of a
  skeleton colliding with a legitimate content stream containing NULs?
- **Ordering contract with the frontend.** B-3 requires pdf.js's text-layer order
  to match the backend's. Inserting skeleton leaves into the id sequence changes
  the mapping; should skeleton/object leaves instead occupy a reserved id range
  above the words, so word ids stay `0..W-1` and the frontend mapping is unchanged?
- **Does `text-line` have the same gap?** Its segments are line-blocks covering
  the whole file, so probably not — but it should be checked with the same lens
  before this RFC is accepted.
