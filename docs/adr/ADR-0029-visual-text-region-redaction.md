# ADR-0029: End-user visual redaction — object labels + content-stream text-run redaction

- **Status:** **Proposed; Phase A1 implemented — 2026-06-14.** *(`POST /redaction/describe` shipped 2026-06-16:
  `POST /redaction/describe` — object classification + labels/previews +
  page grouping, presentation-only. Extended to modern cross-reference-stream
  PDFs 2026-08-01 (A.5-1), so both committed PDF object schemes are described,
  per-object placement geometry added the same day (A.5-2), and the desktop
  `describe_by_path` IPC (A.5-3), and the pdf.js render + drag-box for the browser
  path (A.5-4). Remaining: the read-for-render IPC that extends box selection to
  the desktop path, and B1–B3 text-run segmenter + visual layer — the latter
  blocked on RFC-0000 `0000-textrun-container-commitment.md`.)*
- **Builds on:** ADR-0025 (object-level redaction circuit/witness), ADR-0026
  (`Segmenter` abstraction + `SegmentManifest` + hiding leaf), ADR-0028
  (modern-PDF xref-stream/ObjStm parsing). **The `redaction_validity` circuit,
  witness, bundle, vkey, and trusted setup are reused UNCHANGED** — a text run is
  just another *segment*. This circuit-reuse statement was superseded by
  ADR-0030; the live design keeps the segment abstraction but verifies redaction
  with a signed Merkle fold instead of Groth16.
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
  Previews: extracted text for content streams. (Image previews ship in A1 as a
  structural `/Width`×`/Height` (`/Filter`) label; a *decoded thumbnail* is a
  later enhancement — it would need a display-only image decoder, see the
  Phased-implementation A1 note.)
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

> **Correction (2026-08-01): the "no verifier change" half of that is wrong.**
> The circuit/ceremony claim holds — the fold really is leaf-agnostic. But every
> other format's segments *are* container units, so its verifier accounts for
> every byte via `spans.len() == segments.len()` plus canonical-container
> validation. `pdf-textrun` is the first format whose segments are **sub-units**,
> and the commitment was never extended to match: whole non-content objects, a
> content stream's non-word bytes, and hex-string show operands are covered by no
> leaf. Both offline verifiers therefore **refuse** the tag (see their
> `REJECTED_FORMATS` notes), and verifier work alone cannot lift that — a verifier
> cannot constrain bytes the commitment never covered.
> [RFC-0000 `0000-textrun-container-commitment.md`](../rfcs/0000-textrun-container-commitment.md)
> proposes the leaf-set change that fixes it; this section should be rewritten
> when that RFC is accepted.

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
  domain-1 fold, same circuit/vkey/ceremony — all genuinely reused, and unchanged
  by RFC-0000.
- **The offline verifiers were NOT reused.** This record originally said "same
  offline verifiers — all reused," and that was false: both verifiers *refused*
  `pdf-textrun`, and correctly so. Its leaf set committed words alone, so every
  operator, coordinate, inter-word byte, and whole non-content object was covered
  by nothing — and no verifier-side check can constrain bytes the commitment
  never covered. RFC-0000 fixed that at the commitment level (skeleton and object
  leaves, hex operands as word sources), after which each verifier needed a real
  new arm: a byte-exact port of the content-stream tokenizer and the skeleton
  encoding, pinned by vectors generated from the actual producer. Corrected
  2026-08-02, when those arms landed.
- `pdf.js` is a frontend **display** dependency (**Apache-2.0** — this ADR
  originally said MIT; corrected 2026-08-01 against `pdfjs-dist@6.2.108`'s own
  `package.json` when the dependency was actually added. Permissive either way,
  so the no-GPL-in-the-runtime-graph posture is unaffected). It is **not** in the
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
   **A.5-1 (2026-08-01):** extended to `pdf-xref-stream` commitments. The
   classification only ever read an object's own dictionary + optional stream
   payload, which is format-agnostic, so both schemes now share
   `pdf_describe::describe_regions`; they differ only in how each object's
   committed bytes are recovered (`extract_object_spans` vs
   `pdf_xref::logical_objects`). `byte_length` is per-scheme — the framed
   `N G obj … endobj` span for `pdf-object`, the trimmed logical body for
   `pdf-xref-stream` — matching what each segmenter commits. Structural
   containers (`/ObjStm`, `/XRef`) stay excluded, and the fail-closed
   described-set-vs-manifest cross-check is unchanged.
   **A.5-2 (2026-08-01):** each description now carries `placements[]` — where
   the object paints, in PDF user space (origin bottom-left), from
   `src-tauri/src/zk/pdf_placement.rs`. An image XObject reports the CTM applied
   to the unit square, once per `Do`; a form reports its `/BBox` under
   `/Matrix × CTM` and is recursed into (cycle-guarded, depth-capped); a content
   stream reports its page's `/MediaBox`, inherited through `/Parent` — honest
   rather than precise, because redacting one blanks the whole page (§5's
   over-redaction-is-surfaced rule). Document-level objects get none. The walk
   interprets only `q`/`Q`/`cm`/`Do`, skipping strings and inline-image data so
   binary payload cannot forge a paint. Still presentation-only: no commitment,
   schema, or root is touched, and the redact request re-validates every selected
   id against the manifest regardless of what geometry was displayed.
   **A.5-3 (2026-08-01):** the desktop path reaches the endpoint natively via a
   `describe_by_path` Tauri command (`src-tauri/src/commands.rs`) — Rust reads,
   BLAKE3-hashes, and base64-encodes the picked file, so a path-based document
   gets the same descriptions the browser path had. Until now that path produced
   no labels at all, because it deliberately keeps the bytes out of JS. Best-effort
   at the call site, as in the browser flow: a failure leaves the plain id/size
   listing. Handing the bytes to a renderer is *not* part of this — it has no
   consumer until A.5-4 exists. (A.5-4 shipped that consumer; A.5-5 below is the
   IPC this sentence deferred.)
2. **A2** Frontend: page-grouped, previewed, `pdf.js`-rendered object selection.
   **A.5-4 (2026-08-01):** shipped for the browser path, **page 1 only**.
   `app/public-ui/src/components/PdfBoxSelect.tsx` renders a page with pdf.js and
   resolves a drag to object ids via
   `app/public-ui/src/lib/redactionHitTest.ts`. Explicit non-guarantee: only the
   first page is rendered — every other page remains checklist-only, which the UI
   states rather than implying whole-document coverage. The load-bearing detail is
   the coordinate flip: `placements[]` are PDF user space (origin bottom-left, y
   up, page-box origin not necessarily `0 0`) while a canvas is top-left/y-down,
   and getting it wrong selects the object mirrored about the page axis
   *silently*. Hits are returned smallest-area first so the signature leads the
   page-sized content stream that also covers the point, and a `content_stream`
   hit is labelled "hides the entire page" before the operator commits (§5). The
   Tauri CSP grants `wasm-unsafe-eval` but not `unsafe-eval`; pdf.js v6 needs
   nothing extra, having removed its eval-based path outright. (An earlier
   revision of this record said the component passes `isEvalSupported: false` —
   it does not, and cannot: v5 wanted that option, v6 removed it and passing it
   is a type error. Corrected 2026-08-02.) Its worker loads from a same-origin
   bundled URL, which `default-src 'self'` permits. Display-only throughout: the
   box proposes ids, and the server re-validates each against the committed
   manifest.

   **A.5-5 (2026-08-02): the desktop path now has box selection too.**
   `read_file_for_render` (`src-tauri/src/commands.rs`) hands the picked file's
   bytes to the webview as raw binary, and `useRedactionCreate.onFilePath` calls
   it once descriptions exist. This is a deliberate, narrow relaxation of the
   desktop path's keep-bytes-out-of-JS discipline, and the reasoning is worth
   recording: that discipline is a copy-and-memory choice, not a trust boundary —
   the webview is the same trust domain as the app — and the alternative was a
   *second* renderer in Rust, which would mean a second implementation of the
   coordinate flip above. Since that flip is the one piece of this feature that
   fails silently when wrong, one renderer with one set of tests is worth more
   than one avoided copy. Bounded by its own `RENDER_BYTES_LIMIT` (64 MiB), a
   compile-time assertion below the 128 MiB commit/redact `IPC_BYTES_LIMIT`: the
   render read is optional, so refusing an oversize file costs only the drag-box
   affordance, whereas refusing to *redact* it would fail the operator's actual
   task. Best-effort like `describe_by_path` — on failure `documentBytes` stays
   null and the checklist still works on the same document. The page-1
   non-guarantee above applies to both paths equally.
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
