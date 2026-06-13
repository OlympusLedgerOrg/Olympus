# ADR-0028: Modern-PDF (cross-reference-stream + object-stream) redaction

- **Status:** **Accepted — 2026-06-13.** Implemented in
  `src-tauri/src/zk/segment/pdf_xref.rs`: xref-stream decode (+ PNG predictor 12),
  ObjStm decode, logical-object extraction, and rebuild-to-traditional redaction,
  with a synthetic-fixture round-trip test. Wired into ingest via the
  `segment_document` PDF two-try (traditional → modern → chunk).
- **Builds on:** **ADR-0025** (PDF object-level redaction circuit/witness — *Accepted*)
  and **ADR-0026** (multi-format segment producer — *Proposed*; introduced the
  `Segmenter` trait + `SegmentManifest` + the per-format hiding leaf). ADR-0026
  explicitly scoped PDF support to **traditional cross-reference tables only**
  (`PdfObjectError::NotTraditionalXref`); this ADR extends it to **PDF 1.5+
  files that use cross-reference *streams* and compressed *object streams*** —
  i.e. essentially everything modern tooling (Acrobat, LibreOffice, browsers,
  most libraries) emits today.
- **Related invariants:** ADR-0005 (length-prefixed leaf framing), ADR-0009
  (Poseidon suite — unchanged). **The circuit, witness, public signals, vkey,
  and trusted setup are unchanged** — this only adds a new `Segmenter` that
  produces the same opaque hiding leaves.

## Context

ADR-0026 made `detect_format` route `%PDF-` to the PDF segmenter and fall back
to the non-redactable **chunk** commitment whenever the parser returns
`NotTraditionalXref`. In practice that fallback catches the **majority** of real
PDFs: PDF 1.5 (2003) introduced two compression features that are now the
default in most producers:

1. **Cross-reference streams** — the `startxref` offset points at an indirect
   object `<< /Type /XRef /W [w1 w2 w3] /Index [...] /Size n /Filter /FlateDecode
   [/DecodeParms << /Predictor 12 /Columns c >>] >>` whose (decompressed,
   possibly PNG-predictor-filtered) body is a packed binary table of fixed-width
   entries, instead of the ASCII `xref` table the traditional parser walks.
2. **Object streams (`ObjStm`)** — many indirect objects are packed, DEFLATE-
   compressed, inside a single `<< /Type /ObjStm /N k /First f /Filter
   /FlateDecode >>` object. Such objects have **no independent byte span** in the
   file (xref "type 2" entries point at `(objstm_obj_num, index_within_stream)`),
   so ADR-0025's in-place NUL-fill — which depends on each object owning a byte
   range delimited by `obj`/`endobj` — cannot reach them.

The product requirement (2026-06-13) is that redaction work for modern PDFs.

## Decision

### 1. Parse cross-reference streams + object streams into *logical objects*

Add a `ModernPdfSegmenter` (`SegmentFormat::PdfXrefStream`, tag `pdf-xref-stream`)
that:

- Locates the last `startxref`, reads the xref-stream object, FlateDecodes its
  body, reverses the **PNG predictor** if `/Predictor >= 10` (predictor 12 "up"
  is overwhelmingly the common case), and parses the `/W`-width, `/Index`-framed
  entries (with the `/Prev` chain, latest wins — the same precedence the
  traditional walker uses).
- Resolves every **in-use** object to its **logical body bytes**:
  - **type 1** (free-floating): the bytes between `obj` and `endobj`, exactly as
    the traditional path defines them.
  - **type 2** (in an `ObjStm`): FlateDecode the containing `ObjStm`, read its
    `/N` `(objnum, rel_offset)` header pairs, and slice the object's bytes out of
    the concatenated body.
- Produces one segment per in-use object, **keyed by `obj_id` big-endian** (so
  the generic producer's revealed-blinding re-derivation and the existing PDF
  leaf-keying convention carry over unchanged), with the hiding leaf computed
  over the object's logical body (ADR-0026 §1). `segment_id = obj_id`,
  `label = None` (the obj-id is the label), as in the traditional PDF path.

The leaf is therefore over **logical object content**, not file byte ranges —
the necessary change, because ObjStm objects have no file byte range.

### 2. Redaction model: rebuild-to-traditional (container rebuild)

Because the committed leaves bind **logical object content** (not file offsets),
the redacted artifact does not need to preserve the original file's bytes — it
only needs every **revealed** object's logical body to be reproducible, and the
**redacted** objects' content destroyed. We therefore redact by **rebuilding the
PDF in a normalised, fully-decompressed traditional-xref form**:

- Every **content** object is re-emitted as a free-floating `N G obj <body>
  endobj` (objects that were inside an `ObjStm` become ordinary objects — a
  standard, lossless "decompress object streams" transform). **Redacted** objects
  are re-emitted with their body replaced by the PDF `null` object (the ASCII
  token `null`), which destroys the content; the rebuild is a full
  re-serialisation, so it does **not** preserve byte length and does **not**
  NUL-fill in place (unlike the traditional-xref scheme).
- **Structural container objects are dropped, not re-emitted** — both the
  `/ObjStm` containers (whose compressed stream physically holds the type-2
  objects) and the old cross-reference stream object. This is a **security
  requirement**, not just cleanup: re-emitting an `/ObjStm` verbatim would carry a
  redacted member's plaintext through inside the compressed stream, fully
  recoverable with one `zlib` inflate. Consequently `/ObjStm` containers are never
  committed as redactable segments either (they are not document content).
- A fresh traditional `xref` table + trailer (`/Root`, `/Size` carried from the
  xref-stream trailer dict) is written over the re-emitted content objects.
- The result is a valid traditional-xref PDF. A recipient re-extracts logical
  bodies with the **same logical-body rule** and recomputes revealed leaves; the
  redacted objects' destroyed bodies (`null`) carry no content. Non-redacted
  objects' logical bodies are byte-identical, so their leaves are preserved.

This is the **container-rebuild** model ADR-0026 anticipated for compressed
formats (the OOXML canonical-package decision is the same shape): you cannot
zero bytes in place inside a compressed container, so you commit to logical
content and re-serialise.

### 3. Ingest detection + idempotency

- `detect_format`: a `%PDF-` file is first tried by the **traditional**
  segmenter; on `NotTraditionalXref` it is retried by `ModernPdfSegmenter`; if
  *that* also fails (encrypted, linearised-but-broken, predictor we don't
  implement), it falls back to the chunk commitment — explicit, never silent.
  (Implementation: the PDF branch of `segmenter_for`/ingest tries both PDF
  segmenters in order before chunk.)
- The blinding binds `content_hash = blake3(uploaded bytes)`, so re-ingesting the
  identical file reproduces the same root (insert-or-ignore manifest write).

### 4. No circuit / verifier / ceremony change

As in ADR-0026, the circuit consumes opaque leaves; this ADR only adds a
producer-side extractor + a redaction re-serialiser. The 1024/10 circuit, public
signals, vkey, and trusted setup are reused unchanged. The offline Groth16 +
bundle-signature verifiers are format-agnostic and unchanged.

## Security & invariant analysis

- **Leaf framing / hiding.** Identical to ADR-0026: `content_scalar(obj_id_be,
  logical_body)` → Pedersen hiding commitment → Poseidon leaf. Length-prefixed
  key; blinded so a low-entropy redacted object can't be brute-forced.
- **No new RCE surface / no GPL.** FlateDecode via `flate2` (MIT/Apache, already
  in the dependency graph). Pure-Rust byte parsing — no PDF renderer, no
  `pdfium`, no native lib (the reason ADR-0023/0024 were rejected).
- **Capacity.** > `MAX_SEGMENTS` (1024) in-use objects → `TooManySegments`, chunk
  fallback (never a silent truncation that would leave objects uncommitted).
- **Decompression bombs.** ObjStm / xref-stream inflate is bounded by a max
  output size; an oversized stream errors → chunk fallback rather than OOM.
- **Object generations / free entries.** Only in-use (type-1/type-2) entries are
  committed; free ("type 0") entries and the `/Prev` chain follow the same
  latest-wins precedence as the traditional walker.

## Phased implementation

1. **Parser + extraction** (committable): xref-stream decode (+ PNG predictor),
   ObjStm decode, logical-object extraction → `SegmentManifest`. Synthetic
   modern-PDF fixtures in unit tests. Modern PDFs become object-committed at
   ingest and appear in `GET /redaction/manifest`.
2. **Redaction rebuild**: rebuild-to-traditional re-serialiser with redacted
   bodies blanked; round-trip test (rebuild → re-extract → revealed leaves
   recompute, redacted bodies destroyed).
3. **Prover happy-path test** + flip ADR-0026/0028 to Accepted.

## Alternatives considered

- **In-place NUL-fill for modern PDFs.** Impossible for ObjStm objects (no file
  byte span); rejected.
- **Normalise to traditional-xref at *ingest* and commit that.** Would change the
  on-ledger `content_hash` to the normalised bytes, so a later upload of the
  user's original file wouldn't match. Rejected — `content_hash` must identify
  the file the user actually holds. (We normalise only the *redacted output*, not
  the committed input.)
- **Rasterise (ADR-0023/0024).** Rejected previously (renderer trust boundary,
  in-process RCE, loss of byte/semantic provenance); not revisited.
