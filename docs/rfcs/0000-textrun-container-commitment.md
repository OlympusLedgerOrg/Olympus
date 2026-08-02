# RFC-0000: Commit the container for `pdf-textrun`

| Field      | Value                                                        |
|------------|--------------------------------------------------------------|
| Status     | **Accepted** (2026-08-02)                                     |
| Author(s)  | OlympusLedgerOrg                                              |
| Date       | 2026-08-01 (revised and accepted 2026-08-02)                  |
| Tracking   | PR #1530 (the analysis this proposal answers)                 |
| Supersedes | Amends ADR-0029 Phase B (does not supersede it)               |

> **2026-08-02.** All four questions this RFC opened are resolved and folded into
> the design — see *Resolved questions*. Q1–Q3 were accepted by the owner; Q4 was
> an audit question, answered with evidence: **no**, `text-line` does not share the
> gap, and neither does `ooxml-part`.
>
> Implementation is ADR-0029 **B-2**. Per ADR-0005 discipline the leaf-set change,
> both offline verifiers, and the cross-language vectors move in one commit.

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
`spans.len() == segments.len()`, and accounts for every remaining byte — via
`validate_canonical_pdf_container` for the PDF formats, gap-free span tiling for
`text-line`, and a field-by-field central-directory check for `ooxml-part`. Each
of those was re-checked against `main` for this RFC rather than assumed; see
*Resolved questions* Q4.

`pdf-textrun` is the first — and so far only — format whose segments are
*sub-units* of a container, and the commitment was never extended to match. That
is the distinguishing property, not anything specific to text or to PDFs.

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
| **skeleton** | a content object's whole logical body, minus the word spans and minus the `/Length` value | one per content object |
| **object** | a non-content object's whole logical body | one per non-content object |

Bytes *outside* objects (the `%PDF-` header, the xref table, the trailer) need no
leaf: `validate_canonical_pdf_container` already pins them byte-exactly, and both
verifiers run it today for the other PDF formats.

**Two exclusions, and only two.** The skeleton spans the content object's *whole*
logical body — dictionary, `stream` keyword, payload, `endstream` — not merely the
stream payload. Anything narrower would leave the object's dictionary
uncommitted, and a dictionary is not inert: `/Type`, `/Subtype` and additional
entries all change how a reader treats the object.

That forces the second exclusion. `/Length`'s value is not invariant under
redaction — a destruction token of a different length changes the payload size and
therefore `/Length`. This is the same non-invariance that kills the residue leaf
in *Alternatives considered*, and it would kill the skeleton too if the value were
inside it. So the `/Length` **value** is elided (its key and surrounding syntax are
not), and the verifier instead **recomputes** it from the artifact and rejects a
content object whose `/Length` disagrees with its actual payload extent.

Eliding a derived value costs nothing: a recomputed check is strictly stronger
than a committed one, because it cannot be satisfied by a stale-but-signed value.

### Skeleton leaves

A **skeleton** commits everything in a content object that is *not* a word, in a
form that is **invariant under redaction**: redacting a word changes the word's
bytes but leaves the skeleton identical. That invariance is what lets one leaf,
committed at ingest over the original, still reproduce from the redacted
artifact.

The skeleton is **not** a byte string with in-band elision markers. It is the
length-prefixed sequence of the **runs between the elided spans**:

```
skeleton_preimage = lp(run_0) || lp(run_1) || … || lp(run_K)
```

The elided spans are the object's `W` word spans plus its single `/Length` value
span, taken together in ascending offset order, so `K = W + 1` and there are
always exactly `K + 1 = W + 2` runs. `run_0` spans the object body's start to the
first elision, `run_i` spans elision `i-1`'s end to elision `i`'s start, and
`run_K` spans the last elision's end to the body's end.

```
body:  12 0 obj << /Length 31 >> stream BT (Hello SECRET) Tj ET endstream endobj
elided:                       ^^                (elided: /Length value)
                                                 ^^^^^ ^^^^^^  (elided: words)
runs:  [12 0 obj << /Length ][ >> stream BT (][ ][) Tj ET endstream endobj]
                                                          ← committed, length-prefixed
```

The verifier reconstructs the runs from the artifact by removing exactly the spans
it independently re-derived — the word spans from its own port of the tokenizer,
the `/Length` value span from the dictionary — and checks the leaf. Any edit to an
operator, a coordinate, a dictionary entry, or the whitespace between words now
breaks it.

Three properties follow from the framing, and the first two are why it was chosen
over an in-band marker byte (see *Resolved questions* Q2):

- **No byte value is special**, so a content stream that legitimately contains
  `0x00` — or any other sentinel — cannot be confused with an elided span. The
  question of marker collisions does not arise rather than being argued away.
- **The elision count is pinned structurally.** `W` is recoverable from the run
  count, so a skeleton cannot be reinterpreted under a different word count. The
  in-band form left that to a global argument over the bundle's segment count;
  this makes it local to the leaf.
- **Run boundaries pin elision *positions*.** Because each run's length is
  committed, a word span cannot be slid along the stream without changing the
  leaf — so the tokenizer's output is bound, not merely its results' contents.

A skeleton records word *positions*, never word *lengths* or contents, so it
leaks nothing about redacted text and stays stable when a destruction token
changes a word's length.

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

One deterministic global sequence, in **two ranges**, so that the redactable
leaves form a contiguous prefix (see *Resolved questions* Q3):

1. **Words**, ids `0 .. W-1` — objects in obj-id ascending order, and within each
   content object its words in stream order.
2. **Containers**, ids `W .. N-1` — objects in obj-id ascending order; a content
   object contributes its skeleton leaf, a non-content object its object leaf.

`segment_id` remains a dense `0..N-1` index over that sequence, keyed
`segment_id.to_be_bytes()` — unchanged framing, so ADR-0005 length-prefixing and
the existing `redaction_leaf_for_segment` primitive are untouched.

The split earns its extra pass over the objects:

- **"Is this id redactable?" becomes `id < W`** — a bound check rather than a
  manifest-kind lookup, so the guard below is structural rather than a lookup
  that a future call site can forget to perform.
- **The frontend mapping is an index, not a lookup.** B-3 maps a pdf.js
  text-layer selection to word ids; with words dense from zero in stream order
  that is direct, and it does not shift when a container leaf is added.
- **B-4's run-block grouping becomes a range operation**, since the words it
  groups are contiguous.

### Skeleton and object leaves are not redactable

They exist to bind the container, not to be hidden. `apply_redaction` must reject
a request selecting one, the same way the structural-object guard already rejects
a `/Page` / `/Pages` / `/Catalog` selection (`SegmentError::StructuralObject`).
With the id split above, that guard is `id >= W` — a bound check against the
manifest's word count, not a per-row kind test. The manifest row still carries
the kind, for the producer UI and for human-readable rejection messages.

### Verifier contract

Both verifiers gain a `pdf-textrun` arm that:

- runs the existing canonical-container validation (reused from the
  `pdf-xref-stream` path — the artifact is the same rebuilt traditional-xref
  shape);
- **independently re-derives** every span: object spans from the xref, then within
  each content object the word spans from its own port of the tokenizer, the
  `/Length` value span from the dictionary, and the skeleton span as the object's
  whole logical body;
- **recomputes `/Length`** for every content object and rejects one whose declared
  value disagrees with its actual payload extent — the value is elided from the
  skeleton precisely because it is derived, so this check replaces it;
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
  redaction — i.e. that redaction changes bytes *only* inside word spans and the
  `/Length` value, the two things the skeleton elides. If a future re-emit changed
  anything else, skeleton leaves would stop reproducing — loudly, as a
  verification failure, which is the correct direction to fail. Auditors should
  treat "what does re-emission touch?" as the question that keeps this format
  sound, since it is the one assumption the leaf set cannot itself enforce.

## Alternatives considered

- **Residue leaf** — one leaf over "everything that is not a word", committed as a
  flat byte string. Rejected: the residue is *not* invariant under redaction,
  because content objects are re-emitted with a new `/Length`, so the artifact's
  residue never matches the one committed at ingest. The skeleton is the same idea
  made invariant — it elides `/Length`'s derived value alongside the words and
  commits the remainder as length-prefixed runs, which is what buys back the
  invariance a flat residue lacks.
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
- **Hex-string words are coarse, and that hardens on acceptance.** A whole hex
  string is one segment, so a user cannot redact one word of hex-encoded text
  without hiding the whole run. Q1 recommends accepting this, but note the
  timing: once the format ships, changing it is a new format version rather than
  a patch, because the migration-free window this RFC depends on closes then.
- **Two more verifier ports.** The word tokenizer must be re-implemented
  byte-exactly in Rust and JavaScript and pinned by vectors. That is the standard
  verifier pattern here, but it is real work and a real drift risk.

## Resolved questions

The four questions this RFC opened are answered below and folded into the design
above. They are the **author's proposed resolutions**; the RFC stays *Draft*
until they are accepted. Q4 is not a proposal — it is an audit result, and it is
reported as fact.

### Q1 — Hex-string granularity: stay whole-string

**Recommendation: keep the whole hex string as one word.** Splitting on decoded
glyph runs requires the segmenter to interpret font `/Encoding` — including
embedded CMaps and composite fonts — and, under this repo's discipline, that
interpretation must then be ported **byte-exactly into both offline verifiers**
and pinned by vectors. This RFC already lists "two more verifier ports" as a real
drift risk; font-encoding parsing would make it three implementations of a
genuinely hard specification, in the one place where the three must agree
perfectly or bundles stop verifying.

The asymmetry decides it. Coarse granularity fails toward **over**-redaction —
the operator hides a whole hex run when they wanted one word — which is visible
to them at selection time and safe. An encoding bug fails toward
**under**-redaction or a cross-verifier disagreement, neither of which is.

Accepting this does have a cost worth stating plainly rather than burying: it is
**not** freely revisable later. Once `pdf-textrun` ships, finer hex granularity
is a leaf-set change and therefore a new format version, not a patch — the
migration-free window this RFC relies on closes on acceptance. The recommendation
is to take the sound coarse format now and treat finer granularity as a
deliberate future version.

### Q2 — Elision byte: dissolve the question, don't answer it

**Recommendation: no marker byte at all.** The question as posed ("is `0x00`
enough, or domain-separate it?") accepts an in-band sentinel and then argues
about collisions. Both options are worse than removing the sentinel.

The design above commits the skeleton as the length-prefixed sequence of runs
between the elided spans, so no byte value is reserved and a content stream
containing `0x00` raises no question at all.

Working through this also surfaced a hole in the RFC's own claim. Chasing what a
marker would have to survive made it necessary to say exactly which bytes the
skeleton spans — and the answer, "the whole logical body," collides with
`/Length`, whose value is not invariant under redaction. That is the same
non-invariance this RFC cites to reject the residue leaf, and the first draft's
leaf table would have inherited it. `/Length` is now an elided span alongside the
words, recomputed by the verifier instead of committed. The framing question and
the completeness bug turned out to be the same question asked twice.

This matters more than it first appears. With an in-band marker, the argument
that a marker collision is unexploitable runs through the bundle's *global*
segment count and per-word leaves — it is probably correct, but it is a subtle,
non-local argument, and these bundles are court evidence. The run encoding makes
the property local to the leaf: the run count pins the word count structurally.
Prefer the framing that removes the question over the one that survives it.

Cost: none of substance. It is the same bytes, framed rather than concatenated.

### Q3 — Ordering: reserve the range, words first

**Recommendation: words take ids `0..W-1`, containers take `W..N-1`.**

The decisive property is that **the redactable set becomes a contiguous prefix**,
so "may this id be hidden?" is a bound check rather than a manifest lookup. A
lookup is something a future call site can forget; a bound derived from the
manifest's word count is not. The frontend and B-4 benefits (direct index
mapping, range-based grouping) are real but secondary — they would not on their
own justify departing from a single obj-id walk.

Cost: `extract` makes two passes over the objects instead of one, and an object's
skeleton no longer sits adjacent to its words in id space. Both are trivial
against a structural fail-closed guard.

### Q4 — Does `text-line` have the same gap? **No — audited, and neither does `ooxml-part`**

Checked against `main` at `2aa2817`. This is a factual result, not a judgement:

**`text-line` — clean on both sides.**
- *Commitment*: `block_spans` (`src-tauri/src/zk/segment/text.rs`) tiles
  `[0, len)` exactly — every byte of the file falls in exactly one block, with
  `line_spans_tile_the_file_exactly` asserting contiguity and full coverage.
  `reemit` walks the segments in order and concatenates, so the artifact *is* the
  concatenation of the segments.
- *Verification*: `text_line_spans` (`verifiers/rust/src/redaction.rs`) rejects any
  gap (`offset != pos` → "artifact bytes not fully covered") and any trailing
  bytes (`pos != artifact.len()`). The JavaScript verifier performs the identical
  two checks.

**`ooxml-part` — also clean**, checked with the same lens though the question did
not ask. `ooxml_payload_spans` walks local headers consecutively, then
`validate_canonical_ooxml_central_directory` pins the central directory field by
field and ends with `i + 22 != artifact.len()` → "hidden bytes after ooxml EOCD".
The JavaScript verifier has the same final check.

**The structural reason, which is the useful part.** In all four accepted formats
a segment **is** a container unit, so the verifier can independently re-derive the
container's structure and refuse any byte it cannot attribute to a segment.
`pdf-textrun` is the only format whose segments are *sub-units* of a container,
and that — not anything about text or PDFs specifically — is what leaves bytes
uncommitted. The distinction to carry forward is **sub-unit segmentation**, and any
future format that adopts it inherits this RFC's obligations wholesale.
