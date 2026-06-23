# Plan (for review): Visual Box Redaction — pdf.js render + drag-box

**Status:** Draft for review. Extends **ADR-0029** (visual-text-region-redaction;
Phase A complete). Not yet an ADR amendment — this is the pre-implementation plan.

**Goal:** Let a user *render a committed PDF and drag a box over the region they
want to hide*, instead of guessing raw object numbers. Make signature/stamp/image
redaction feel like Adobe today, and lay the path to true sub-page text redaction.

---

## 1. Motivation

Today's `RedactTab` shows a flat list of indirect-object numbers (`#1 #2 #96 …`)
with size bars. The ADR-0029 Phase A `/redaction/describe` endpoint *labels* them
("Page 2 — text", "Image 699×92") — but it is **gated to `pdf-object`
(traditional-xref) PDFs only**, so for a modern `pdf-xref-stream` document (the
common case, e.g. `2.pdf`) the user falls back to raw numbers. Result: a user
redacts "object 2" thinking it's a piece of page 2 and silently blanks the
**entire** page (object 2 is page 2's whole `/Contents` stream). The guard keeps
the file *valid*, but the UX is a footgun.

The fix users expect: **render the page, draw a box, redact what's under it.**

---

## 2. Invariants this plan MUST obey (Olympus dev standards)

1. **Commitment is byte-based and sealed at ingest.** Redaction *hides* committed
   hiding-leaves; it cannot cut finer than the leaves the segmenter produced at
   ingest. **Box granularity is therefore decided by the segmenter, not the UI.**
2. **pdf.js is display-only — NOT a trust boundary.** No security-sensitive crypto
   in TS. The frontend renders and emits a *selection* (object-ids / run-ids); the
   actual cut + leaf binding happen in Rust, and the selection is re-validated
   server-side against the committed manifest (fail-closed on any id not in it).
3. **`/redaction/describe` stays presentation-only** — recomputed on demand, never
   persisted, never touches a hiding leaf or the Merkle root (ADR-0029 §A).
4. **The V3 signed-Merkle bundle is format-agnostic.** New granularity = a new
   `Segmenter` impl + format tag; the fold, signature, and both offline verifiers
   are unchanged in shape. Per-segment `artifact_offset`/`artifact_length` spans
   already let the bundle re-emit a rebuilt artifact (the modern-PDF path does
   this) — so a re-emitted content stream is supported by design.
5. **Granularity change ⇒ re-ingest** under the new segmenter (the existing
   manifest-geometry re-ingest pattern).
6. **New leaf inputs are length-prefixed + domain-separated** (ADR-0005); a new
   segment format moves the schema, both verifiers, and the cross-language
   vectors together, in one commit.
7. **The structural-object guard still applies** (a box that resolves to a
   `/Page`/`/Pages`/`/Catalog` object is still rejected — no corrupt artifacts).

---

## 3. Two increments

### Phase A.5 — Visual box → **object** selection (no crypto change)

The high-leverage, low-risk first step. Reuses the existing object-level
commitment and V3 bundle **unchanged**; the box is purely a selection gesture
that toggles the object checkboxes RedactTab already has.

- Box over an **image** (signature/stamp) → resolves to that image XObject →
  redact it. Surgical and correct (this is object `#96` on `2.pdf`).
- Box over **text** → resolves to that page's content-stream object → whole-page
  blank (honest and *labelled as such* so the user isn't surprised).
- Works on **already-committed** object-level docs, including `pdf-xref-stream`.

**Backend (Rust — owned by me):**

- **Extend `/redaction/describe` to `pdf-xref-stream`** (today gated to
  `pdf-object` in `api/redaction/describe.rs`). The modern segmenter already
  yields the logical objects; classification (`zk/pdf_describe.rs`) is
  format-agnostic on the object body. Keep the fail-closed manifest cross-check.
- **Add per-object placement geometry** to `RedactionObjectDescription`:
  `placements: [{ page: u32, x: f32, y: f32, w: f32, h: f32 }]` in PDF user space
  (origin bottom-left). Derivation:
  - *Image XObject* → walk each page's content stream tracking the CTM; every
    `Do` that paints this image yields one placement rect (`CTM · unit square`).
  - *Content stream* → the owning page's `MediaBox` (whole page).
  - *Document-level objects* (catalog, fonts, metadata) → no placement.
  Pure byte parsing, no renderer (same discipline as `pdf_describe`).
- Contract stays presentation-only (recomputed, never persisted).

**Frontend (React + pdf.js — owned by Claude Design):**

- Render each page to a canvas with **pdf.js** (display-only).
- Overlay a selection layer; drag to draw a box. On release, hit-test the box
  against `placements` (rect intersection) → set of object-ids → toggle the
  existing object checkboxes. Existing apply/redact/bundle flow is untouched.
- Show the resolved selection ("this box covers: Image 699×92 (#96)") before the
  user commits, so whole-page resolution is never a surprise.

**Tauri/desktop path:** add a `describe_by_path(path)` IPC (the deferred A2b item)
and expose the file bytes to pdf.js for rendering. No bytes-in-JS crypto — bytes
are only for *display* + the describe call; the cut stays in Rust.

**Crypto/commitment:** unchanged. The box changes only *which object-ids are
selected*; `apply_redaction_with_spans` + the V3 bundle are byte-identical to
today. The structural guard still rejects a box that lands on a Page/Pages/Catalog.

### Phase B — **Word-run** granularity (true sub-page text redaction) — *target: word level*

Lets "box this word/sentence, nothing else" actually cut at sub-page granularity.
**Prototype validated word-granularity as the target** (see §6a): it is cheap
(~4k leaves for a 28-page doc vs the 2²⁰ cap), the deterministic re-emit
round-trips with the **real** `olympus-crypto` leaf, and redacted-word reflow is
solved with a width-preserving `TJ` move. Word level subsumes line level, so we
go straight to words.

**Backend (Rust — owned by me):**

- New **`pdf-textrun` `Segmenter`** (new `SegmentFormat::PdfTextRun`, tag
  `pdf-textrun`): at **ingest**, parse content-stream text-show operators
  (`Tj`/`TJ`/`'`/`"`) into individual **runs**, each with its glyph bytes +
  position metadata. Each run becomes **one hiding leaf**, keyed by a canonical
  **run index** (content-stream order), folded into the *same* variable-depth
  Poseidon root + V3 bundle. **No new crypto primitive** — it reuses the existing
  format-agnostic redaction hiding-leaf (`OLY:REDACTION:OBJ:V1`, segment_key =
  run index big-endian, already length-prefixed per ADR-0005).
- `apply_redaction` re-emits the content stream with redacted runs' text operands
  removed/blanked, and returns **per-run `artifact_offset/length` spans** (exactly
  how the modern-PDF rebuild already supplies spans). Revealed runs' bytes in the
  re-emitted artifact must recompute their committed leaf → the re-emit must be
  **deterministic** and preserve revealed-run operands verbatim. *Byte-stability
  of neighbours is NOT required* because the bundle carries fresh per-run spans
  (same property the xref-stream rebuild relies on).
- ADR-0005 discipline: schema, **both** offline verifiers (rust + js), and the
  cross-language `vectors.json` move in the same commit.

**Frontend (Claude Design):** pdf.js **text layer** gives per-span geometry; map
box → spans → **run-ids** (ordering must equal the backend's canonical
content-stream order — defined once, agreed both sides). Select runs; redact.

**Granularity:** run-level needs the doc **re-ingested** under `pdf-textrun` (the
manifest-geometry re-ingest pattern). Existing object-level docs keep working at
object granularity.

**Cap handling (ADR-0029 §B3):** a page with `> CANOPY/leaf cap` runs groups runs
into run-blocks; multi-page handled by per-page run indexing.

---

## 4. Cross-boundary contracts (defined first, per standards)

| Boundary | Change | Phase |
|---|---|---|
| HTTP `POST /redaction/describe` | accept `pdf-xref-stream`; add `placements[]` per object | A.5 |
| Tauri IPC | `describe_by_path(path) -> RedactionDescribeResponse`; file bytes for pdf.js render | A.5 |
| `SegmentFormat` | new variant `PdfTextRun` (tag `pdf-textrun`); `from_tag` fail-closed | B |
| HTTP describe | run-level descriptions with per-run `bbox` when format is `pdf-textrun` | B |
| V3 bundle | unchanged shape; `format` carries the new tag; per-run spans | B |

`describe` and the redact request keep validating every selected id against the
committed manifest — a render can mislead the human but cannot change what is
committed or cut.

---

## 5. Security / threat model

- **Render is untrusted.** pdf.js could draw anything; it only informs the human.
  The redaction set (object/run-ids) is re-validated server-side against the
  on-ledger manifest; unknown ids → `422`. The commitment + cut are byte-based in
  Rust.
- **describe leaks nothing new** — presentation-only, never persisted, never
  touches leaf/root (ADR-0029 §A preserved across the `pdf-xref-stream` extension).
- **No TS crypto.** Frontend hashes/signs nothing.
- **Length-prefix + domain separation** for the run leaf are inherited from the
  existing redaction hiding-leaf (segment_key framed per ADR-0005).
- **Structural guard intact** — Phase A.5 box that lands on Page/Pages/Catalog is
  rejected (the guard shipped in PR #1306).
- **Over-redaction is surfaced, not silent** — the UI shows what a box resolves to
  before commit (whole-page vs run).

---

## 6. Milestones & rough effort

| # | Deliverable | Owner | Size |
|---|---|---|---|
| A.5-1 | `/redaction/describe` supports `pdf-xref-stream` | me | M |
| A.5-2 | `placements[]` (CTM-tracked image rects + page boxes) | me | M |
| A.5-3 | `describe_by_path` IPC + file bytes to pdf.js | me | S |
| A.5-4 | pdf.js render + drag-box → object hit-test + selection preview | Design | M |
| B-1 | `pdf-textrun` segmenter: extract + apply_redaction + spans | me | L |
| B-2 | run leaf vectors + both offline verifiers updated | me | M |
| B-3 | pdf.js text-layer box → run-ids; canonical ordering contract | Design + me | M |
| B-4 | cap/run-block grouping + multi-page | me | M |

Ship **A.5 first** — it solves the signature/image case end-to-end on modern PDFs
with **zero crypto change**, and de-risks the renderer/box UX before the
heavier Phase B segmenter.

---

## 6a. Prototype validation (2026-06-23)

Throwaway prototypes (`OneDrive/Documents/olympus-redaction-prototype/`,
`src-tauri/examples/textrun_real_leaf.rs`) validated the load-bearing claims on
the **real page-2 content stream** of `2.pdf`:

| claim | result |
|---|---|
| word segmentation on real text | 142 word-units (`POSITIVE CHILDHOOD ALLIANCE, INC. …`) |
| deterministic re-emit | byte-identical on repeat |
| round-trip (BLAKE3 stand-in leaf) | 127/127 revealed words recompute; 0 mismatched |
| **round-trip (real `olympus-crypto` leaf)** | **127/127 revealed words recompute the genuine BN254 leaf** (`content_scalar → pedersen_commit → poseidon_hash`); 0 mismatched |
| redacted content gone | all `CHILDHOOD` + digit words absent; each redacted unit blanked |
| **no reflow** (width-preserving `TJ`) | max reflow of a revealed word = **0.0** glyph units (vs 64691 for empty-blank), using real `/Widths` |
| cost | ~142 leaves/page → ~4k for 28 pages (cap 2²⁰ ≈ 1.05M) → **cheap** |

The round-trip is **leaf-function-independent**: byte-exact recovery of a revealed
word from its artifact span is necessary *and* sufficient for any deterministic
`f(key, bytes)` leaf to recompute — so the stand-in proof transfers to the real
leaf (the Rust example confirms with the genuine primitive).

**Net:** word granularity is the target; the crux is de-risked; what remains is
Rust engineering (real leaf wiring + escaping/kerning/CID fonts + canonical
ordering) and the frontend box→word mapping.

## 7. Risks / open questions

- ~~**Phase B re-emit determinism** is the crux~~ — **VALIDATED (see §6a).** The
  prototype proves a deterministic, byte-identical re-emit whose revealed words
  recompute the **real `olympus-crypto` leaf** from their per-word spans, and
  width-preserving `TJ` moves eliminate reflow. Remaining engineering (not
  conceptual): PDF-string escaping of `()\`, `TJ` kerning, CID/Type0 font widths,
  and a single canonical word ordering shared with the frontend.
- **Run ordering parity**: pdf.js text-layer order vs the backend's
  content-stream run order must match exactly. Define the canonical order in Rust;
  the frontend maps to it via the describe response's per-run index, not by
  re-deriving order in JS.
- **Partial-image redaction** (box covers *half* an image) is **out of scope**: a
  box over an image redacts the whole image object. Documented limitation; true
  pixel-region image redaction is a separate (rasterizing) segmenter, explicitly
  deferred (cf. ADR-0023/0024 rejection — rasterization must never become the
  commitment source).
- **pdf.js in Vite/Tauri**: worker bundling + size; virtualize pages for large
  PDFs so render stays responsive.
- **Re-ingest UX** for run-level: needs a "re-commit at finer granularity"
  affordance; reuse the existing re-ingest path.
- **CTM tracking for placements** (A.5-2): nested form XObjects + multiple paints
  of one image; reuse `pdf_describe`'s content-stream walker, cycle-guarded.

---

## 8. Ownership (per the frontend boundary)

- **Rust (me):** describe `xref-stream` support + `placements`, `describe_by_path`
  IPC, the `pdf-textrun` segmenter, server-side region→object/run *validation*,
  vectors + verifiers.
- **React/pdf.js (Claude Design):** page render, drag-box gesture, selection
  overlay + preview, text-layer selection.
- **ADR:** amend **ADR-0029** with Phase A.5 + the Phase B contract (or a new ADR
  if the reviewer prefers); record before B-1 lands.

---

## 9. Testing

- **A.5:** golden tests for `placements` on a fixture PDF (image rects + page
  boxes); describe parity between `pdf-object` and `pdf-xref-stream`; box→object
  hit-test unit tests (frontend); E2E — box the signature → resolves to the image
  object → valid redacted PDF + signed bundle; structural guard still rejects a
  page box.
- **B:** `pdf-textrun` extract/redact **round-trip** (revealed runs recompute
  their leaf from the artifact span); cross-language vectors for the run format;
  cap/run-block boundary tests; pdf.js text-layer ↔ run-id ordering test.
- Coverage gate: happy path + one error path per new public fn (standards).
