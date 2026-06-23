# ADR-0034: Standardized fixed-width redaction tokens + format-specific sanitization

- **Status:** **Proposed — 2026-06-23.**
- **Supersedes:** the **width-preserving space-fill** approach (PR #1309, *closed
  without merging*). That approach replaced redacted bytes in place with a
  same-length ASCII-space run. It fixed the NUL-byte rendering/truncation bugs
  but **leaked the byte-length** of every redacted unit (the span kept its size)
  — a size oracle on the hidden content. This ADR keeps the rendering fix and
  **closes the size oracle**.
- **Builds on:** ADR-0026 (`Segmenter`/`SegmentManifest` + hiding leaf),
  ADR-0028 (modern-PDF xref-stream rebuild with `null` bodies), ADR-0030 (the V3
  signed-Merkle bundle; redaction is not a SNARK). **No circuit, vkey, ceremony,
  leaf function, or cross-language vector changes** — see §Crypto invariance.
- **Related invariants:** the redaction binding holds because every *revealed*
  segment's bytes recompute its committed leaf; redacted segments are
  authoritative via `leaf_hex` and their bytes are never re-hashed.

## Context

Redaction destroys a selected segment's content while keeping the artifact
verifiable: the V3 bundle carries, per segment, the byte span
(`artifact_offset`/`artifact_length`) into the **produced** artifact, and the
offline verifier recomputes each *revealed* leaf from those span bytes.

Two fill strategies have now been tried and found wanting:

1. **In-place NUL-fill** (original): preserves byte-width but writes `0x00`,
   which truncates C-style string reads and renders as binary garbage.
2. **In-place width-preserving space-fill** (PR #1309, closed): fixes the
   rendering problem but, by preserving each redacted span's exact length,
   **discloses how many bytes were hidden** — unacceptable for a redaction tool
   whose whole job is to hide the sensitive content, size included.

The requirement: blank redacted content **without** revealing its length, and
**without** leaving NUL garbage.

## Decision

### 1. Standardized fixed-width replacement (length-independent)

Replace a redacted unit's content with a **single constant token whose size is
independent of the original content length**, so the artifact reveals only *that*
a unit was redacted, never *how large* it was. For text/Markdown the token is a
pinned marker (e.g. `[REDACTED]\n`); for structured formats it is the format's
structural null (§2). The token is a pinned constant — one source of truth, like
the superseded `REDACTION_FILL_BYTE`.

Because the token length differs from the original span, the **in-place** formats
(text, traditional PDF) become **re-emit** formats: they rebuild the artifact and
report the shifted per-segment spans via `apply_redaction_with_spans` — exactly
the contract OOXML and modern PDF already satisfy.

### 2. Format-specific sanitization (don't byte-fill structured containers)

| Format | Redaction | Length hidden? |
|---|---|---|
| **text / Markdown** | re-emit; redacted line-block → one constant token (`[REDACTED]\n`) | ✅ (token size is constant) |
| **traditional PDF** | rebuild the file: revealed objects emitted **verbatim** at new offsets, redacted objects → `N G obj\nnull\nendobj`, fresh xref + `startxref` | ✅ (`null` is constant size) |
| **modern PDF (xref-stream)** | **unchanged** — already rebuilds with a `null` object body (ADR-0028) | ✅ |
| **OOXML** | **strip / empty** the redacted part's payload in the canonical Stored-ZIP re-emit (entry name survives, payload → 0 bytes) | ✅ (0 bytes reveals nothing about original size) |

For structured formats the "fixed token" is the format's own null, not five
spaces: PDF → the `null` object token; OOXML → an emptied entry. Never attempt an
in-place byte fill of a compressed/offset-indexed container.

## Crypto invariance (why no verifier / vector / ceremony change)

The hiding leaf binds `(segment_id, segment_bytes)` — **not byte offset.** Offsets
exist only in the V3 bundle and are recomputed by the producer against the
produced artifact. The offline verifier (confirmed in
`verifiers/rust/src/redaction.rs`) reconstructs every revealed leaf from
`artifact[artifact_offset .. +artifact_length]` and, for `pdf-object`/`text-line`,
hashes that slice verbatim — with **no assumption that the span equals the
original committed offset.** Therefore:

- Changing a redacted unit's length is safe **iff** (a) every revealed segment's
  bytes are preserved, (b) the segmenter reports correct post-redaction spans,
  and (c) the verifier reads those spans (it does).
- **Traditional PDF must emit revealed objects byte-for-byte verbatim.** Its leaf
  commits to the **full** `N G obj … endobj` span (the verifier hashes the whole
  slice), unlike modern PDF which commits to the *trimmed logical body*. So the
  rebuild relocates revealed objects to new offsets but must not re-serialize
  their bytes; only redacted objects change (→ `null`) and the xref is rebuilt.
- The cross-language `redaction_vectors.json` are **synthetic bundle fixtures**
  (hand-authored segment tables → table_hash → signature), independent of
  producer fill bytes, so they do **not** regenerate.

No leaf function, fold, circuit, vkey, ceremony, bundle schema, or verifier leg
changes. This is a producer-only output change.

## Security analysis

- **Closes the size oracle.** A constant-width token (and `null` / empty entry)
  reveals nothing about the redacted content's original length — the defect that
  closed PR #1309.
- **Residual disclosure (stated, not hidden).** The bundle still flags *which*
  segments are redacted, so the **count and position** of redactions remain
  visible (one token per hidden unit). Fixed-width hides *size*, not *existence*.
  Hiding existence/count is a different primitive (e.g. dropping units and
  re-folding) and is out of scope.
- **Content hiding unchanged.** Redacted plaintext is overwritten/removed at the
  byte source; the existing "redacted plaintext must be ABSENT from the artifact"
  tests still hold. The redacted leaf stays a hiding Pedersen→Poseidon commitment.
- **Structural-object guard retained (PDF).** The rebuild must still refuse to
  `null` a Catalog/Pages/Page (the #1306 guard) — nulling the skeleton corrupts
  the document.
- **Box→segment fidelity (when a visual layer exists, ADR-0029).** Any UI that
  maps a selection to segment ids must be re-verified server-side against the
  committed manifest before proving; fail closed on mismatch.

## Phased implementation

1. **Text** — `[REDACTED]` token re-emit + `apply_redaction_with_spans` override;
   update the NUL/space tests to assert the token + recomputed spans. *(lowest risk)*
2. **OOXML** — keep the canonical re-emit, redacted payload emptied (0-length);
   confirm the bundle's dense-id rule still holds (all segments listed; redacted
   span length 0). *(revert of the closed PR's OOXML change)*
3. **Traditional PDF** — file rebuild: verbatim revealed object spans + `null`
   redacted bodies + fresh xref/`startxref` + span override; retain the
   structural-object guard. *(highest risk — most work; do last, behind its own
   prover/round-trip test)*

## Alternatives considered

- **Width-preserving space-fill (PR #1309).** Rejected — leaks redacted length.
- **In-place NUL-fill (original).** Rejected — NUL rendering/truncation bugs.
- **Rasterized tile / pixel-mask redaction (ADR-0023/0024).** Rejected
  previously (renderer-as-commitment trust boundary, in-process RCE, provenance
  loss); not revived.
- **Pad the `null`/token to the original length.** Rejected — re-introduces the
  size oracle; the whole point is a length-*independent* replacement.
