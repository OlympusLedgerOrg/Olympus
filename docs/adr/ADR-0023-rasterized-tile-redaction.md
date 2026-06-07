# ADR-0023: In-house rasterized tile redaction (format-agnostic redactor + pluggable importers)

- **Status:** **REJECTED — 2026-06-07.** See "Rejection rationale" below.
  *Historical context: previously Accepted; Phase 1 (crypto core +
  cross-language verifiers + image/PDF importers) was implemented via PRs
  #1217 and #1218.*
- **Date proposed:** 2026-06-07
- **Date rejected:** 2026-06-07
- **Direction going forward:** the chunk-based Circom `redaction_validity`
  circuit (`proofs/circuits/redaction_validity.circom`,
  `src-tauri/src/zk/chunk.rs`, `src-tauri/src/api/redaction.rs`) remains the
  canonical redaction primitive. Existence / non-existence / redaction_validity
  circuits work end-to-end on current main; round-trip tests pass against the
  on-disk artifacts.
- **Supersedes / builds on:** the chunk-based `redaction_validity` scheme
  (`proofs/circuits/redaction_validity.circom`, `src-tauri/src/zk/chunk.rs`,
  `src-tauri/src/api/redaction.rs`). This ADR previously proposed to **replace**
  the 16-chunk raw-byte commitment as the redaction primitive; that proposal is
  no longer the direction (see *Rejection rationale*).
- **Related invariants:** ADR-0005 (structured leaf prefix) for the
  domain-separation + length-prefix framing conventions used in the rejected
  design; the Critical-Invariant rule that a commitment-format change moves
  `olympus-crypto` + both verifiers + golden vectors in one commit.

## Rejection rationale

The rasterized tile-redaction primitive proposed in this ADR shifts the
verifiable property from **facts about the document bytes the issuer
committed** to **facts about images of those documents**. That shift is
deliberate in the ADR's *Decision* section — and it's the shift the
project is now declining to make. Three load-bearing concerns drove the
rejection:

1. **Trust boundary migrates to "canonical renderer fidelity."** The ADR
   acknowledges this directly ("Render fidelity is a one-time, auditable
   trust in the canonical renderer"). With a *dynamically-loaded* libpdfium
   resolved at runtime from `OLYMPUS_PDFIUM_PATH` and no version pin in
   tree, two honest issuers running two pdfium builds can produce
   different `tiles_root` for the same source PDF. The recipient never
   re-renders, so verification *runs* — but if a render-fidelity dispute
   arises the project has nothing canonical to point at. The chunk-based
   Circom path commits to source bytes directly and is immune to this
   class of dispute.

2. **In-process PDFium is an unmitigated RCE surface.** ADR §"Untrusted-
   file parsing = RCE surface" calls out the requirement to run importers
   as sandboxed subprocesses, then ships them in-process behind the
   `redaction-pdf` feature. The follow-up note "sandbox-subprocess
   hardening tracked for later" has no concrete issue or step number
   anywhere in repo. Until that sandboxing exists, every PDF redaction
   would parse attacker-supplied bytes inside the desktop's address
   space — load-bearing the existence of mitigation that has not been
   written.

3. **Semantic provenance is lost in raster collapse.** Rasterization
   discards text content, layer/object structure, document metadata,
   embedded scripting, fonts, and the source's signature surface. A
   redaction proof should be able to answer "what was originally there
   and what did you cover" at the level the document semantically *is* —
   not at the level of "what did your rasterizer paint." The byte-level
   commitment the chunk scheme provides is preserved by retaining the
   sealed source; the tile scheme intentionally collapses that into
   pixels and discards the rest.

The chunk-based `redaction_validity` circuit ships, has an in-circuit
EdDSA-Poseidon issuer signature (audit M-2), and is well-tested
end-to-end (see `src-tauri/tests/zk_prove_redaction.rs`). Its
limitations enumerated in this ADR's *Context* section (length-dependent
chunk boundaries, no partial-tile reveal, 16-chunk cap) are accepted as
the cost of source-byte fidelity for v0.9; revisiting that trade is a
**separate** decision and not coupled to ADR-0023's specific design.

### Code disposition

Code from PRs **#1217** and **#1218** is parked. Future work on
tile-redaction is halted; the disposition (revert vs. quarantine behind
a permanent default-off feature flag) is a separate decision, intentionally
not made in this ADR. Until then:

- `src-tauri/src/zk/redaction_tile.rs`, `src-tauri/src/zk/redaction_import.rs`,
  and `src-tauri/src/zk/redaction_issue.rs` remain on disk but are not
  reachable from any live endpoint.
- `redaction-import` and `redaction-pdf` Cargo features stay default-off.
- `verifiers/rust/src/redaction_tile.rs` and
  `verifiers/javascript/test_redaction_tile.js` plus
  `verifiers/test_vectors/tile_redaction_vectors.json` remain (the
  cross-language verifier vectors are inert when no producer emits them).
- The canonical redaction primitive is the chunk-based Circom circuit;
  `/redaction/issue` continues to invoke it via
  `crate::zk::prove::prove_redaction`.

---

## Historical proposal (preserved verbatim — for context only)

Everything below this line is the original proposal as written prior to
rejection. Read for context; do **not** treat as forward-looking direction.

## Context

The shipped redaction feature commits a document as **16 variable-size raw-byte
chunks** (`chunk_size = ceil(filelen / 16)`), proves a Groth16
`redaction_validity` statement over the masked chunk leaves, and binds a dropped
file to the proof by re-chunking it and recomputing `redactedCommitment`
(`src-tauri/src/zk/chunk.rs`, `app/public-ui/src/lib/redactionBinding.ts`). In
practice this does not model real document redaction:

1. **Chunk boundaries are length-dependent.** `ceil(n/16)` shifts every boundary
   when the file length changes, so a redacted artifact of a different size binds
   to nothing — even its unmodified regions.
2. **Editor redaction re-serializes the whole file.** Producing a redacted PDF in
   any editor rewrites xref tables, object offsets, and streams; essentially no
   byte range survives, so the revealed-bytes binding can never match the
   original. (Observed: a 578.3 KB original vs a 559.8 KB editor-redacted copy
   share no chunk hashes.)
3. **Raw byte chunks are not semantic.** A chunk cannot be partially revealed, so
   redaction granularity is "1/16 of the raw bytes," unrelated to where the
   sensitive content actually is.
4. **The trustless property never held for real documents.** The whole point of a
   redaction *validity* proof is to remove trust in the redactor (prove the
   visible content is the authentic original without revealing the hidden part).
   For any re-rendered document that is information-theoretically impossible: with
   no surviving bytes there is nothing to check against the original commitment.

The root cause is that Olympus does **not own the redaction operation** — it
audits a file someone else produced. If Olympus owns the redactor, it controls
the byte transformation and can restore a provable binding.

## Decision

Build an **in-house redactor** with a **format-agnostic, tile-based commitment**,
fed by **pluggable per-format importers**. The redactor — not an external tool —
produces both the redacted artifact and the bundle.

### Pipeline (issuer side)

1. **Import → canonical raster.** A per-format importer renders the source
   document to **canonical page images** at a pinned DPI. Rasterization is the
   universal normalizer: it also strips hidden text, metadata, prior incremental
   revisions, annotations, and scripts.
2. **Tile + commit (seal).** Each page image is split into fixed-size **tiles**.
   Each tile is committed as a **Pedersen commitment** over Baby Jubjub:
   `m_i = BLAKE3(OLY:REDACTION:TILE:V1 || lp(page) || lp(tile_xy) || tile_bytes) mod r`
   (content binding), then `C_i = m_i·G + b_i·H` where `b_i` is a per-tile random
   blinding and `H` is the independent generator from `OLY:PEDERSEN:H:V1`
   (`crates/babyjubjub-permissive`). The leaf is the compressed point `C_i`; leaves
   fold into a Merkle root `original_root` (Poseidon/BLAKE3 node hashing). This root
   is anchored/sealed; the blindings `b_i` are stored with the sealed original.
3. **Redactor picks spots.** The frontend renders the page images for display and
   the operator draws boxes. The frontend sends **coordinates only** — no hashing
   or rendering of ledger material happens in TS.
4. **Blank + rebuild.** Rust **overwrites** (not overlays) the pixels of every
   tile covered by a box (with a margin; whole-tile granularity), then encodes a
   fresh **image-only** redacted artifact.
5. **Bundle + sign.** The bundle reveals, for each non-redacted tile, its blinding
   `b_i` (so the recipient recomputes `m_i` from the artifact tile and checks
   `C_i = m_i·G + b_i·H`); for each redacted tile, it carries the committed leaf
   `C_i` only (`b_i` and `m_i` withheld). The authority signs
   `(original_root, descriptor_hash, recipient_id)` with a domain-separated tag
   (`OLY:REDACTION:BUNDLE:V1`).

### Verification (recipient side) — no re-render required

The recipient hashes the artifact's revealed tiles (using the revealed salts),
combines with the published redacted-tile leaves, recomputes the Merkle root, and
asserts it equals `original_root`; then checks the authority signature. **The
recipient never re-renders the source format** — they only re-hash image tiles
they can see — so cross-platform render reproducibility is *not* required. Only
the issuer renders, once, at seal time.

### Two security invariants (BLOCKING)

- **Image-only output, pixels overwritten.** The artifact has no text/font/object
  layer (nothing to `pdftotext` or select), and redacted regions are overwritten
  in the pixel buffer before encoding — never drawn as a removable overlay.
- **Redacted-tile commitments are perfectly hiding (Pedersen).** A bare `H(tile)`
  is dictionary-attackable for low-entropy content (SSNs, names, templated
  fields). Pedersen `C_i = m_i·G + b_i·H` with a secret uniform blinding `b_i` is
  *perfectly* hiding — `C_i` is uniformly distributed regardless of `m_i`, so even
  brute-forcing candidate tile contents cannot confirm a guess without `b_i`. The
  blinding is revealed only for *revealed* tiles. (Salted BLAKE3 was the
  considered alternative — computationally hiding only; Pedersen chosen for the
  stronger guarantee and reuse of the existing `OLY:PEDERSEN:H:V1` generator.)

### Layer ownership (dev standards)

- **Rust** (`src-tauri/`) owns import, render, tile, commit, salt generation,
  blank, rebuild, and sign — all crypto/data-critical.
- **TypeScript** owns the box-drawing canvas only; it receives page images and
  returns coordinates. No crypto, no hashing of ledger material in TS.
- New domain constants (`OLY:REDACTION:TILE:V1`, `OLY:REDACTION:BUNDLE:V1`) live
  in `crates/olympus-crypto`, length-prefixed framing per ADR-0005.

### Importer tiers (format → canonical raster pages)

| Tier | Formats | Mechanism | Dependency | Phase |
|------|---------|-----------|------------|-------|
| Trivial | PNG, JPEG, TIFF, BMP, WEBP | decode (`image` crate, MIT) | none | 1 |
| Core | PDF | pdfium (BSD-3), **bundled** per-platform | one native lib | 1 |
| Office | DOCX, XLSX, PPTX, ODF, RTF | LibreOffice headless → PDF → pdfium | heavy (~300 MB) | 2 |
| Markup | TXT, CSV, MD, HTML | deterministic text/HTML layout → raster | light–medium | 3 |

"All formats" is purely an importer roadmap; it does **not** widen the
commitment's Critical-Invariant surface (the tile scheme is format-agnostic).

## Migration / circuit disposition

This replaces the raw-byte chunk commitment. Recommended: **retire the
`redaction_validity` Groth16 circuit** in favour of the salted-tile redactable
hash + authority signature. Benefits: no in-circuit Merkle/EdDSA cost, **no
Phase-2 trusted-setup ceremony dependency for redaction** (one fewer blocker for
v1.0 — see CHANGELOG v0.9.0 ceremony note), simpler verifiers. The current
circuit's only unique property over this scheme (an *in-circuit* issuer
signature) is preserved off-circuit by the bundle signature, and the chunk scheme
did not provide trustless faithfulness for real documents anyway.

No pre-launch ledger / committed redactions exist, so there is **no data
migration** — the chunk path is removed, not dual-supported. `chunk.rs`,
`witness/redaction.rs`, `redactionBinding.ts`, the circuit, its vkey, and
manifest are removed; the new tile commitment + golden vectors are added in the
same commit (per the Critical Invariant).

## Consequences / trade-offs

- **Capability gained:** openable redacted document (image pages) **+** a
  shippable bundle **+** trustless faithfulness on the rendered image **+**
  arbitrary spot selection (tile granularity) **+** genuine content destruction
  (rasterized, no recoverable text). This is the workflow the chunk scheme could
  not deliver.
- **Bundle weight (the cost):** pdfium is a native lib; LibreOffice is large.
  Mitigate by phasing — images + PDF (Phase 1) cover most needs with one native
  dep; Office support is optional/detected, not bundled by default.
- **Untrusted-file parsing = RCE surface.** PDF/Office renderers parse
  attacker-supplied input. Run importers as **sandboxed subprocesses**, isolated
  from the main process — for safety and to keep licensing clean.
- **Licensing (no-GPL law).** The ban is on GPL libs *linked* into the binary.
  pdfium (BSD) ✓ and LibreOffice (MPL/LGPL, separate process) ✓. **Avoid pandoc
  (GPL) and MuPDF (AGPL)** — MuPDF is banned even as a lib; prefer LibreOffice or
  a Rust renderer for markup.
- **Render fidelity is a one-time, auditable trust** in the canonical renderer
  (that the sealed render faithfully represents the source). Acceptable; it is the
  only residual trust and it is checkable against the retained original.
- **Original retention:** the sealed original is held by the issuer for audit. The
  recipient cannot read redacted content from the artifact; destroying the
  original itself is a separate retention policy, not a redaction property.
- **Context leakage** (visible surroundings implying the hidden value) is
  semantic and out of scope for any commitment scheme.

## Alternatives considered

- **Keep the 16-chunk raw-byte scheme:** rejected — length-dependent boundaries +
  editor re-serialization mean it binds nothing for real redacted documents, and
  it never provided trustless faithfulness.
- **Redact-then-commit (issuer-attested), keep a real editor-made PDF:** viable
  and cheap (commit the final redacted PDF, sign a link to the sealed original),
  but gives only *attested* faithfulness, not trustless. Kept as a possible
  lighter-weight fallback mode, not the primary design.
- **Byte-range container (zero raw byte ranges, length-preserving):** trustless
  but produces a non-openable artifact and only redacts opaque byte regions —
  rasterization supersedes it.
- **Keep the ZK circuit, rework its witness to tiles:** more work, retains a
  ceremony dependency, and the in-circuit signature is replaceable off-circuit —
  rejected in favour of the redactable-hash scheme.
- **Semantic/content-layer redaction (per-glyph / content-stream):** the "true
  PDF redaction" ideal, but fragile across fonts/reflow and far larger scope —
  deferred.

## Risks & mitigations

- **Renderer RCE on untrusted input** → sandboxed subprocess importers; never
  link a document parser into the main process.
- **Low-entropy redacted content leak via tile hash** → salted/hiding leaves
  (BLOCKING invariant above); reviewed as policy, not optional.
- **Partial-glyph leakage at box edges** → whole-tile blanking with a margin
  (redact slightly more than the box; the safe direction).
- **Overlay-instead-of-overwrite regression** → test that decoded artifact pixels
  in redacted tiles are the solid fill, and that the committed redacted leaf is
  not recomputable from the artifact.
- **Cross-platform render variance** → not a verification concern (recipient never
  re-renders); only the issuer's one-time seal render must be deterministic on its
  own machine.

## Implementation plan (phased)

1. **Core crypto (Rust):** `OLY:REDACTION:TILE:V1` / `OLY:REDACTION:BUNDLE:V1`
   constants in `olympus-crypto`; salted tile leaf + Merkle root + bundle sign /
   verify; unit tests (happy path + tampered-tile + low-entropy-non-recompute).
2. **Importer interface + Phase-1 importers:** `image` decode + pdfium (sandboxed
   subprocess). Pinned DPI + tile size as named consts.
3. **Tauri contract + redactor UI:** IPC for seal / list-pages / issue; React
   canvas for box selection (coordinates only).
4. **Verifiers + vectors:** implement the tile commitment in `verifiers/rust` and
   `verifiers/javascript`; regenerate golden vectors; remove the chunk vectors.
5. **Remove chunk path + circuit:** delete `chunk.rs`, `witness/redaction.rs`,
   `redactionBinding.ts`, `redaction_validity.circom` + its vkey/manifest; update
   `CLAUDE.md`, CHANGELOG, and the ceremony docs (one fewer circuit).
6. **Phase 2/3 importers:** Office (optional LibreOffice) and markup, behind the
   same interface; no crypto changes.

## Resolved decisions (2026-06-07)

1. **Tile size + DPI — best-case fidelity/granularity.** Pinned consts:
   **300 DPI** render, **32×32 px tiles** (`REDACTION_DPI`, `REDACTION_TILE_PX`).
   At 300 DPI a US-Letter page is 2550×3300 px ≈ 8 200 tiles; each tile is ~2.7 mm,
   fine enough that whole-tile blanking over-redacts negligibly. There is no ZK
   circuit over the tiles (redactable hash, not Groth16), so a large tile count is
   only hashing + Pedersen commits — cheap; the bundle carries revealed blindings
   (~tens of bytes/tile), a few hundred KB/page, acceptable. Both consts are
   pinned (a change is a commitment-format/migration-class event).
2. **pdfium is bundled** per-platform (Win/Linux/macOS) — not a detected system
   install — so redaction works out of the box on a fresh desktop.
3. **Pedersen tile leaves** (over salted BLAKE3) — perfectly hiding; reuses the
   `OLY:PEDERSEN:H:V1` generator and `crates/babyjubjub-permissive`. See pipeline
   step 2 and the hiding invariant.
4. **Keep issuer-attested redact-then-commit as a documented secondary mode** for
   users who need a real *vector* (non-image) PDF and accept attested (not
   trustless) faithfulness. Primary path is rasterized tile redaction; this mode
   is the lighter-weight alternative, not the default.
