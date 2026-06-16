# ADR-0029: End-user visual redaction — object labels + content-stream text-run redaction

- **Status:** **Proposed — 2026-06-14.** *(Phase A1 implemented 2026-06-16:
  `POST /redaction/describe` — object classification + labels/previews +
  page grouping, presentation-only. Remaining: A2 frontend, B1–B3 text-run
  segmenter + visual layer.)*
- **Builds on:** ADR-0025 (object-level redaction circuit/witness), ADR-0026
  (`Segmenter` abstraction + `SegmentManifest` + hiding leaf), ADR-0028
  (modern-PDF xref-stream/ObjStm parsing). **The `redaction_validity` circuit,
  witness, bundle, vkey, and trusted setup are reused UNCHANGED** — a text run is
  just another *segment*.
- **Supersedes (the rejection it does NOT revive):** ADR-0023/0024 rejected
  **rasterizing for the commitment** (trusting a renderer's pixels as
  cryptographic truth → renderer RCE/licensing/provenance loss). This ADR uses a
  renderer (`pdf.js`) **for display only**; the commitment stays content-based in
  Rust. That distinction is the whole point.

## Context

Redaction today is **object-level**: the producer hides whole PDF indirect
objects, and the UI lists them by id + byte size (`#37 · 45592 bytes`, ×479 for a
real PDF). Two problems surfaced in use:

1. **Unintelligible selection.** An end user cannot map "the source's name I must
   hide" to "object #37". The list needs human labels + previews.
2. **Wrong granularity for the real need.** Redaction granularity = commitment
   granularity = **object** granularity. A whole page's text is typically **one**
   content-stream object, so object-level redaction can hide *a whole page's
   text* but not *one name in a paragraph* — and for a press-freedom / court-
   evidence tool, "black out the name, prove the rest is authentic" is the core
   use case. Object-level cannot express it.

## Decision

Two phases, both keeping the unchanged circuit + hiding-leaf primitive.

### Phase A — usable object selection (no crypto change)

Make the existing object scheme usable for hiding **whole elements** (images,
attachments, metadata, a full page's text):

- **Backend `POST /redaction/describe`** (scope-gated like the other producer
  endpoints): takes the uploaded bytes + `content_hash`, verifies the hash
  matches the committed manifest, and returns per-segment **labels + previews**
  classified from the bytes: object `/Type` `/Subtype` (Page, Image w/ `/Width`×
  `/Height`, Font `/BaseFont`, Metadata, Annotation, Content stream…) and the
  owning page number (resolved via the `/Pages → /Kids → /Page /Contents` tree).
  Previews: extracted text for content streams, a decoded thumbnail for images.
  **Labels/previews are presentation, computed on demand — NOT persisted in the
  commitment** (so they need no re-ingest and never touch the leaf).
- **Frontend** groups the checklist by **page** and **type**, shows the preview,
  and renders the page with `pdf.js` for context. The user hides whole elements.
- **No leaf / circuit / manifest-schema change.**

### Phase B — visual text-region redaction (`pdf-textrun` Segmenter)

Introduce `SegmentFormat::PdfTextRun` (tag `pdf-textrun`) — a new `Segmenter`
under the **existing** abstraction:

- **Segment = one text-show run.** Parse each page's content stream into its
  text-showing operators (`Tj` / `TJ`, with the active position/font from the
  graphics state) → an ordered list of **runs**, each a `(run_id, run_bytes)`
  unit where `run_bytes` is the shown string (+ its placement). One hiding leaf
  per run via the existing `olympus_crypto::redaction` primitive, keyed by
  `run_id.to_be_bytes()` — identical to every other segment. Leaves fold into the
  **same** 1024-leaf `redaction_validity` tree.
- **Redaction = remove the selected runs' operators** from the content stream and
  paint a black rectangle at their bounding box, then re-emit the content stream
  object (a re-serialise, like the OOXML/modern-PDF container-rebuild model). The
  proof shows every **non-redacted** run's leaf is unchanged — i.e. *"the rest of
  the page is authentic; exactly these runs were removed."* This is the property
  object-level can't give.
- **Display + selection (frontend, `pdf.js`, display-only).** Render the page to
  a canvas; use `pdf.js`'s **text layer** so the user highlights text or draws a
  box. Map the selection → `run_id`s via the text layer's span↔operator
  correspondence, and send `run_id`s to `/redaction/redact`. The renderer never
  feeds the commitment — it only helps the human point.

### Why this needs no new circuit / ceremony

The circuit treats leaves as opaque field elements and folds 1024 of them; it
neither knows nor cares whether a leaf is a PDF object, an OOXML part, a text
block, or a content-stream run. A run is a segment. So Phase B is a new
**segmenter + a frontend visual layer**, reusing the proving stack verbatim — no
vkey, no ceremony, no verifier change.

## Hard parts / honest constraints

- **1024-leaf cap.** A dense or multi-page document can exceed 1024 text runs.
  v1 scopes to `≤ MAX_SEGMENTS` runs and **fails closed → chunk fallback**
  (logged) above it; the natural extensions are (a) group adjacent runs into
  selectable **blocks** (coarser, fits more text) or (b) **per-page** commitments
  (one root per page). Pick (a) for v1; record the granularity limit in the UI.
- **Content-stream parse + rewrite.** Text positioning (`Td`/`TD`/`Tm`/`TJ`
  kerning arrays), font encodings (to know what bytes a run shows and where), and
  re-emitting a still-valid stream with correct `/Length` are non-trivial. v1 may
  restrict to common encodings and skip exotic constructs (fail closed → Phase-A
  object redaction remains available).
- **Box→run mapping fidelity.** `pdf.js` abstracts the content stream; aligning
  its text-layer spans to the exact operators the Rust parser produced needs a
  stable run ordering shared by both. Mismatch must fail safe (no silent
  mis-redaction) — verify the chosen runs against the committed manifest before
  proving.
- **Provability granularity = run granularity.** You can prove "these runs
  removed, those intact"; you cannot prove sub-run (mid-word) edits. Acceptable
  for redaction.

## Security & invariants

- Same hiding-leaf (`content_scalar`/`derive_blinding`/`redaction_leaf`), same
  domain-1 fold, same circuit/vkey/ceremony, same offline verifiers — all reused.
- `pdf.js` is a frontend **display** dependency (MIT). It is **not** in the
  Rust crypto path and is **not** a commitment trust boundary — distinct from the
  ADR-0023/0024 rejection.
- No new GPL; content-stream parsing/rewriting is pure-Rust byte work (no
  renderer, no native lib) — same discipline as the other segmenters.
- Redacted content destroyed at the byte source (the run's operators removed
  before re-emit), consistent with the leak fix in ADR-0028.

## Phased implementation

1. **A1** `POST /redaction/describe` (classify + preview) + tests. **— done
   (2026-06-16):** `src-tauri/src/zk/pdf_describe.rs` classifies each committed
   object (catalog/pages/page/content-stream/image/font/metadata/annotation),
   resolves page numbers via the `/Pages → /Kids → /Page /Contents` tree, and
   extracts a text preview (FlateDecode-aware) for content streams; wired at
   `src-tauri/src/api/redaction/describe.rs`. Image **thumbnail** previews are
   deferred (they'd need a display-only image decoder) — image objects carry a
   `width×height (filter)` label instead.
2. **A2** Frontend: page-grouped, previewed, `pdf.js`-rendered object selection.
3. **B1** `pdf-textrun` segmenter (content-stream run extraction → leaves) +
   run-removal redaction + happy-path prover test. No UI yet.
4. **B2** Frontend visual layer: `pdf.js` text-layer selection → `run_id`s.
5. **B3** Cap handling (run-block grouping) + multi-page.

## Alternatives considered

- **Rasterized tile redaction (ADR-0023/0024).** Rejected previously (renderer
  as commitment trust boundary, RCE, provenance loss); not revived. Display-only
  rendering here is categorically different.
- **Object-level only.** Insufficient — cannot redact sub-page text.
- **A new fine-grained circuit.** Unnecessary — the 1024-leaf fold already
  accommodates runs-as-segments; a new circuit would add a ceremony for no gain.
