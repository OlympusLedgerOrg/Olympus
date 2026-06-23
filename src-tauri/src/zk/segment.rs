//! Format-agnostic redaction *segment* abstraction (ADR-0026 §2).
//!
//! A **segment** is a format-defined, independently-redactable unit of a
//! document: a PDF indirect object, a plain-text line-block, or an OOXML
//! package part. Each segment yields exactly one **hiding** leaf
//! (`olympus_crypto::redaction::redaction_leaf` — a blinded Pedersen commitment),
//! and the leaves fold into the ADR-0030 **variable-depth** domain-1 Poseidon
//! commitment the V3 signed-Merkle bundle proves over.
//!
//! The whole crypto stack downstream of a segment is format-agnostic: the
//! variable-depth fold, the bundle signature, and both offline verifiers consume
//! opaque leaf field-elements + published blindings — they never see document
//! structure. So **only two operations are format-specific**: parsing bytes into
//! segments ([`Segmenter::extract`]) and producing the redacted artifact
//! ([`Segmenter::apply_redaction`]). Everything else — the Merkle fold, root
//! recompute — lives here once and is shared by every format.
//!
//! The per-segment leaf (identical construction for every format, ADR-0026 §1):
//! ```text
//! content_i = reduce_l(BLAKE3_XOF("OLY:REDACTION:OBJ:V1" || lp(segment_key_i) || segment_bytes_i))
//! b_i       = reduce_l(BLAKE3_XOF("OLY:REDACTION:BLIND:V1" || lp(secret) || lp(content_hash) || lp(segment_key_i)))
//! leaf_i    = Poseidon((content_i·G + b_i·H).x, .y)
//! ```
//! `segment_key_i` is the segment's `segment_id` as 4 big-endian bytes — for PDF
//! that is the indirect-object number, for text the block index. The
//! length-prefix framing (ADR-0005) means part-name / line-index / obj-id keys
//! cannot collide by boundary shifting.

use ark_bn254::Fr;
use thiserror::Error;

use crate::zk::field_validation::validate_be_bytes_to_fr;
use crate::zk::poseidon::{domain_node, NODE_DOMAIN};

pub mod ooxml;
/// ADR-0029 Phase B word-run segmentation (next-phase; gated, not yet wired into
/// ingest/dispatch — see `docs/plans/visual-box-redaction.md`).
#[cfg(feature = "textrun-segmenter")]
pub mod pdf_textrun;
pub mod pdf_xref;
pub mod text;

/// Upper bound on committed segments for the **ADR-0030 V3** variable-depth fold.
/// Pinned (migration-class): a change must land in this module, both offline
/// verifiers, and the cross-language vectors together. Bounds the fold at ~2.1M
/// Poseidon hashes / depth 20 so a pathological document cannot force unbounded
/// work / OOM on the producer or the offline verifiers.
pub const MAX_REDACTION_SEGMENTS: usize = 1 << 20; // 1_048_576
/// Hard cap on bytes any single decompression may produce (PDF FlateDecode of an
/// xref stream / ObjStm, or a ZIP package entry) — a decompression-bomb guard
/// shared by the modern-PDF and OOXML segmenters. Over-cap → `SegmentError`,
/// which routes to the non-redactable chunk fallback at the ingest call site.
pub(crate) const MAX_INFLATE: usize = 64 * 1024 * 1024;

// ── Format tag ────────────────────────────────────────────────────────────────

/// The commitment format persisted on `redaction_segment_manifests.format` and
/// used to dispatch [`apply_redaction`]. Fail-closed: an unrecognised tag is
/// rejected by [`SegmentFormat::from_tag`] rather than defaulting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentFormat {
    /// Traditional-xref PDF; one segment per indirect object (`pdf_objects`).
    PdfObject,
    /// PDF 1.5+ with cross-reference streams / object streams; one segment per
    /// logical indirect object ([`crate::zk::segment::pdf_xref`], ADR-0028).
    PdfXrefStream,
    /// UTF-8 text / Markdown; one segment per line-block ([`text`]).
    TextLine,
    /// OOXML package part ([`ooxml`], ADR-0026 Phase 3).
    OoxmlPart,
    /// PDF word-run granularity — one segment per text word in a page content
    /// stream (ADR-0029 Phase B; `pdf_textrun`). Next-phase: a `pdf-textrun`
    /// manifest/bundle is only produced when the `textrun-segmenter` feature is
    /// built; the tag itself round-trips regardless.
    PdfTextRun,
}

impl SegmentFormat {
    /// The DB / wire tag string. Frozen — these are persisted in
    /// `redaction_segment_manifests.format` and read back across releases.
    pub fn as_tag(&self) -> &'static str {
        match self {
            SegmentFormat::PdfObject => "pdf-object",
            SegmentFormat::PdfXrefStream => "pdf-xref-stream",
            SegmentFormat::TextLine => "text-line",
            SegmentFormat::OoxmlPart => "ooxml-part",
            SegmentFormat::PdfTextRun => "pdf-textrun",
        }
    }

    /// Parse a persisted tag. Returns `None` for an unknown tag (fail-closed).
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "pdf-object" => Some(SegmentFormat::PdfObject),
            "pdf-xref-stream" => Some(SegmentFormat::PdfXrefStream),
            "text-line" => Some(SegmentFormat::TextLine),
            "ooxml-part" => Some(SegmentFormat::OoxmlPart),
            "pdf-textrun" => Some(SegmentFormat::PdfTextRun),
            _ => None,
        }
    }
}

// ── Segment + manifest ──────────────────────────────────────────────────────

/// One independently-redactable unit of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Stable segment identifier. **Also the content/blinding key** — the leaf
    /// is keyed by `segment_id.to_be_bytes()`, so this value MUST be the same at
    /// extraction time and when re-deriving a revealed blinding in the bundle.
    /// PDF: the indirect-object number. Text: the 0-based block index.
    pub segment_id: u32,
    /// Optional human-facing label for the producer UI (e.g. a text block's
    /// `"lines 12–18"`, or later an OOXML part name). PDF leaves it `None`
    /// because the obj-id is already the label.
    pub label: Option<String>,
    /// Byte offset of the segment in the *original* artifact.
    pub byte_offset: u64,
    /// Byte length of the segment in the *original* artifact.
    pub byte_length: u64,
    /// Lower-hex 32-byte field element of the segment's hiding Poseidon leaf.
    pub leaf_hex: String,
}

/// A document's full segment commitment: ordered segments + the ADR-0030
/// variable-depth Merkle root the V3 signed-Merkle bundle proves over.
/// Generalises ADR-0025's `PdfObjectManifest` across formats.
#[derive(Debug, Clone)]
pub struct SegmentManifest {
    pub format: SegmentFormat,
    /// In commitment order (PDF: obj-id ascending; text: block index ascending).
    /// `segment_id`s are strictly ascending and unique.
    pub segments: Vec<Segment>,
    /// 64-char lower-hex variable-depth Merkle root over the segment leaves —
    /// the ledger leaf and the bundle's `original_root`.
    pub original_root_hex: String,
    /// `⌈log2 N⌉` for `N` segments (ADR-0030 §1).
    pub tree_depth: u8,
    /// The real segment count `N` (ADR-0030 §1 — no fixed padding).
    pub max_leaves: usize,
}

/// `(tree_depth, max_leaves)` for an `N`-segment ADR-0030 variable-depth fold:
/// `depth = ⌈log2 N⌉` and `max_leaves = N` (the real count, no fixed padding).
/// `N` must be `>= 2` (the redactable minimum, ADR-0030 §1).
pub(crate) fn variable_geometry(n: usize) -> (u8, usize) {
    debug_assert!(n >= 2);
    let depth = n.next_power_of_two().trailing_zeros() as u8;
    (depth, n)
}

#[derive(Debug, Error)]
pub enum SegmentError {
    #[error("document could not be parsed as {0}")]
    Unsupported(&'static str),
    #[error("malformed {format} document: {detail}")]
    Malformed {
        format: &'static str,
        detail: String,
    },
    #[error("segment id {0} is not present in the manifest")]
    UnknownSegment(u32),
    #[error("segment {0} byte range is out of bounds for the supplied artifact")]
    OutOfBounds(u32),
    #[error(
        "document has {found} segments, exceeding the {max}-leaf commitment capacity; \
         it cannot be sealed for object-level redaction (ADR-0025)"
    )]
    TooManySegments { found: usize, max: usize },
    #[error(
        "document has {found} redactable segment(s); object-level redaction needs \
         at least {min} (a single-segment document offers no reveal/hide partition) \
         — it routes to the chunk fallback (ADR-0030 §1)"
    )]
    TooFewSegments { found: usize, min: usize },
    #[error("leaf computation failed: {0}")]
    LeafComputationFailed(String),
    #[error("Poseidon error: {0}")]
    Poseidon(String),
    #[error(
        "object {id} is a structural PDF object ({kind}); redacting it would corrupt \
         the document — a redacted object is replaced with `null`, and a page-tree \
         node or document root that resolves to `null` is an invalid PDF (strict \
         readers reject it; lenient ones silently drop the page). Object-level \
         redaction targets content objects (images, content streams, fonts), not the \
         page-tree skeleton."
    )]
    StructuralObject { id: u32, kind: &'static str },
}

// ── structural-object guard (PDF) ─────────────────────────────────────────────

/// Classify a PDF indirect object's logical body as a *structural* object whose
/// redaction would corrupt the document rather than hide content.
///
/// Both PDF segmenters destroy a redacted object's content — the modern path
/// (`pdf_xref`) re-emits it as the literal `null`, the traditional path
/// (`pdf_objects`) NUL-fills its body in place. That is safe for **content**
/// leaves (image XObjects, content streams, fonts, annotations) but catastrophic
/// for the document's structural skeleton:
/// - a `/Type /Page` or `/Type /Pages` node nulled out leaves the page tree
///   pointing at a non-dictionary — strict readers (Adobe, Chrome, Edge) report
///   the file as corrupt; lenient ones (qpdf) silently drop the page;
/// - a nulled `/Type /Catalog` removes the document root entirely.
///
/// Returns the offending kind (for the error message) when `body` is one of those
/// three, so the redaction producer can fail closed **before** emitting a broken
/// artifact. This is a deliberately conservative, fail-closed heuristic: it keys
/// off the object's declared `/Type` (always present on Catalog/Pages/Page from
/// real-world producers). A false positive merely asks the operator to pick a
/// different object; it never lets a structural object through.
pub(crate) fn pdf_structural_object_type(body: &[u8]) -> Option<&'static str> {
    match pdf_type_name(body) {
        Some(b"Catalog") => Some("Catalog — the document root"),
        Some(b"Pages") => Some("Pages — a page-tree node"),
        Some(b"Page") => Some("Page — a whole page"),
        _ => None,
    }
}

/// Read the `/Type` name value from a PDF object's leading dictionary as a
/// complete, delimiter-terminated token, returned WITHOUT its leading `/`.
///
/// Parsing the value as a full name token (not a substring `find`) is what keeps
/// `/Page` from matching the prefix of `/Pages`. The first `/Type` occurrence is
/// the object's own type in real PDFs (a stream object's `/Type` lives in the dict
/// that precedes the `stream` keyword), so scanning the whole body is sufficient.
fn pdf_type_name(body: &[u8]) -> Option<&[u8]> {
    fn is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00)
    }
    fn is_delim(b: u8) -> bool {
        matches!(
            b,
            b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
        )
    }
    fn skip_ws(b: &[u8], mut i: usize) -> usize {
        while i < b.len() && is_ws(b[i]) {
            i += 1;
        }
        i
    }
    /// Index just past a name token whose `/` is at `i-1` (i.e. `i` points at the
    /// first name char). Runs until whitespace or a delimiter.
    fn name_end(b: &[u8], mut i: usize) -> usize {
        while i < b.len() && !is_ws(b[i]) && !is_delim(b[i]) {
            i += 1;
        }
        i
    }
    /// Index just past a `(...)` literal string starting at `i` (`b[i] == '('`),
    /// honouring `\`-escapes and balanced inner parens.
    fn skip_lit_str(b: &[u8], mut i: usize) -> usize {
        i += 1;
        let mut depth = 1usize;
        while i < b.len() && depth > 0 {
            match b[i] {
                b'\\' => i += 2,
                b'(' => {
                    depth += 1;
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    i += 1;
                }
                _ => i += 1,
            }
        }
        i
    }
    /// Skip a bracketed group starting at `i` — a dict `<<…>>` (`array == false`)
    /// or an array `[…]` (`array == true`) — recursing into nested groups of
    /// EITHER kind and honouring literal strings, hex strings, and comments, so a
    /// `>>`/`]` inside a string or a differently-typed nested group can't end it
    /// early.
    fn skip_group(b: &[u8], mut i: usize, array: bool) -> usize {
        i += if array { 1 } else { 2 };
        let mut depth = 1usize;
        while i < b.len() && depth > 0 {
            let c = b[i];
            if c == b'<' && b.get(i + 1) == Some(&b'<') {
                if array {
                    i = skip_group(b, i, false); // nested dict inside an array
                } else {
                    depth += 1;
                    i += 2;
                }
            } else if c == b'>' && b.get(i + 1) == Some(&b'>') {
                if array {
                    i += 2;
                } else {
                    depth -= 1;
                    i += 2;
                }
            } else if c == b'[' {
                if array {
                    depth += 1;
                    i += 1;
                } else {
                    i = skip_group(b, i, true); // nested array inside a dict
                }
            } else if c == b']' {
                if array {
                    depth -= 1;
                    i += 1;
                } else {
                    i += 1;
                }
            } else if c == b'(' {
                i = skip_lit_str(b, i);
            } else if c == b'<' {
                i += 1;
                while i < b.len() && b[i] != b'>' {
                    i += 1;
                }
                i += 1;
            } else if c == b'%' {
                while i < b.len() && b[i] != b'\n' && b[i] != b'\r' {
                    i += 1;
                }
            } else {
                i += 1;
            }
        }
        i
    }
    /// Index just past ONE dictionary value object beginning at `i`.
    fn skip_value(b: &[u8], i: usize) -> usize {
        let i = skip_ws(b, i);
        if i >= b.len() {
            return i;
        }
        match b[i] {
            b'/' => name_end(b, i + 1),
            b'(' => skip_lit_str(b, i),
            b'<' if b.get(i + 1) == Some(&b'<') => skip_group(b, i, false),
            b'<' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'>' {
                    j += 1;
                }
                j + 1
            }
            b'[' => skip_group(b, i, true),
            c if c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.') => {
                // a number, possibly the head of an `N G R` indirect reference
                let num = |b: &[u8], mut i: usize| {
                    while i < b.len()
                        && (b[i].is_ascii_digit()
                            || matches!(b[i], b'+' | b'-' | b'.' | b'e' | b'E'))
                    {
                        i += 1;
                    }
                    i
                };
                let e = num(b, i);
                let g = skip_ws(b, e);
                if g < b.len() && b[g].is_ascii_digit() {
                    let g2 = num(b, g);
                    let r = skip_ws(b, g2);
                    if b.get(r) == Some(&b'R')
                        && (r + 1 >= b.len() || is_ws(b[r + 1]) || is_delim(b[r + 1]))
                    {
                        return r + 1; // consumed `N G R`
                    }
                }
                e
            }
            // bool / null keyword
            _ => {
                let mut j = i;
                while j < b.len() && b[j].is_ascii_alphabetic() {
                    j += 1;
                }
                if j > i {
                    j
                } else {
                    i + 1
                }
            }
        }
    }

    // Walk the OUTER dictionary's key→value pairs. `/Type` matched here is the
    // object's own type; a `/Type` inside a value (nested dict/array), a literal
    // string, a hex string, a comment, or the stream payload (after `>>`) is
    // skipped by `skip_value` / never reached.
    let open = body.windows(2).position(|w| w == b"<<")? + 2;
    let mut i = open;
    loop {
        i = skip_ws(body, i);
        if i >= body.len() {
            return None;
        }
        match body[i] {
            b'>' if body.get(i + 1) == Some(&b'>') => return None, // dict closed, no /Type
            b'%' => {
                while i < body.len() && body[i] != b'\n' && body[i] != b'\r' {
                    i += 1;
                }
            }
            b'/' => {
                let ks = i + 1;
                let ke = name_end(body, ks);
                if &body[ks..ke] == b"Type" {
                    let vi = skip_ws(body, ke);
                    if vi < body.len() && body[vi] == b'/' {
                        let vs = vi + 1;
                        return Some(&body[vs..name_end(body, vs)]);
                    }
                    return None; // `/Type` present but its value is not a name
                }
                i = skip_value(body, ke); // skip this key's value, land on the next key
            }
            _ => return None, // expected a key name; malformed dict — give up
        }
    }
}

// ── The per-format contract ───────────────────────────────────────────────────

/// The byte span of one segment in the **produced (redacted) artifact** —
/// the `artifact_offset` / `artifact_length` the ADR-0030 §2a V3 bundle ships per
/// segment so a recipient verifier reconstructs each revealed leaf by a direct
/// slice (`artifact[offset .. offset + length]`) and the per-format
/// `content_bytes` rule (ADR-0030 §3). Returned for **every** segment (revealed
/// and redacted) by [`Segmenter::apply_redaction_with_spans`], in the manifest's
/// ascending `segment_id` order. The span of a redacted segment points at its
/// destroyed region (its `leaf_hex` is authoritative, the bytes are advisory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentSpan {
    pub segment_id: u32,
    pub artifact_offset: u64,
    pub artifact_length: u64,
}

/// The format-specific operations the redaction producer needs. One impl per
/// supported format; the rest of the pipeline is format-agnostic.
pub trait Segmenter {
    /// Which [`SegmentFormat`] this segmenter produces.
    fn format(&self) -> SegmentFormat;

    /// Parse `bytes` into ordered segments, compute each hiding leaf from
    /// `blind_secret`, and fold the commitment root. Pure byte ops — no
    /// renderer, no native lib (ADR-0026 §Security).
    fn extract(&self, bytes: &[u8], blind_secret: &[u8]) -> Result<SegmentManifest, SegmentError>;

    /// Produce a redacted artifact with `redacted_ids` removed/zeroed, keeping
    /// every non-redacted segment's committed leaf reproducible (PDF/text: the
    /// other segments' bytes are byte-identical to the input).
    fn apply_redaction(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<Vec<u8>, SegmentError>;

    /// Like [`apply_redaction`](Segmenter::apply_redaction) but also returns each
    /// segment's byte span in the **produced** artifact (ADR-0030 §2a), so the V3
    /// producer can publish `artifact_offset` / `artifact_length` and the offline
    /// verifier reconstructs revealed leaves byte-exactly.
    ///
    /// The default impl is valid **only for the in-place formats** whose output
    /// span equals the original committed span — `pdf-object` and `text-line`
    /// NUL-fill in place, so every segment keeps its `byte_offset` / `byte_length`.
    /// The re-emit formats (`pdf-xref-stream`, `ooxml-part`) **override** this:
    /// their output offsets come from the rebuilt container, not the original.
    fn apply_redaction_with_spans(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
        let artifact = self.apply_redaction(bytes, manifest, redacted_ids)?;
        let spans = manifest
            .segments
            .iter()
            .map(|s| SegmentSpan {
                segment_id: s.segment_id,
                artifact_offset: s.byte_offset,
                artifact_length: s.byte_length,
            })
            .collect();
        Ok((artifact, spans))
    }
}

// ── Detection + dispatch ──────────────────────────────────────────────────────

/// Sniff the format of `bytes` for the *ingest* commitment path.
///
/// `%PDF-` → PDF (a malformed / cross-reference-stream PDF is still routed here
/// and surfaces its own parse error, so an unsupported PDF falls back to the
/// chunk commitment at the call site rather than being mis-segmented). A ZIP
/// carrying an OOXML `[Content_Types].xml` part → OOXML. Valid UTF-8 that is not
/// one of the above → text. Everything else (plain ZIPs, images, opaque
/// binaries) → `None`: committed but not object-redactable.
pub fn detect_format(bytes: &[u8]) -> Option<SegmentFormat> {
    if bytes.starts_with(b"%PDF-") {
        return Some(SegmentFormat::PdfObject);
    }
    if looks_like_ooxml(bytes) {
        return Some(SegmentFormat::OoxmlPart);
    }
    if std::str::from_utf8(bytes).is_ok() && !bytes.is_empty() {
        return Some(SegmentFormat::TextLine);
    }
    None
}

/// Cheap OOXML sniff: a ZIP (`PK\x03\x04`) that names an OOXML content-types
/// part. The segmenter does the authoritative parse; a false positive here just
/// routes to the OOXML extractor, which errors and falls back to chunk.
fn looks_like_ooxml(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"PK\x03\x04") {
        return false;
    }
    // `[Content_Types].xml` is mandatory in every OPC/OOXML package and is
    // conventionally the first entry; its name appears verbatim in the ZIP.
    bytes
        .windows(b"[Content_Types].xml".len())
        .any(|w| w == b"[Content_Types].xml")
}

/// The [`Segmenter`] for a format — used to dispatch [`apply_redaction`] from a
/// loaded manifest's `format`.
pub fn segmenter_for(format: SegmentFormat) -> Option<Box<dyn Segmenter>> {
    match format {
        SegmentFormat::PdfObject => Some(Box::new(crate::zk::pdf_objects::PdfSegmenter)),
        SegmentFormat::PdfXrefStream => Some(Box::new(pdf_xref::ModernPdfSegmenter)),
        SegmentFormat::TextLine => Some(Box::new(text::TextSegmenter)),
        SegmentFormat::OoxmlPart => Some(Box::new(ooxml::OoxmlSegmenter)),
        #[cfg(feature = "textrun-segmenter")]
        SegmentFormat::PdfTextRun => Some(Box::new(pdf_textrun::PdfTextRunSegmenter)),
        #[cfg(not(feature = "textrun-segmenter"))]
        SegmentFormat::PdfTextRun => None,
    }
}

/// Segment a document for the **ingest** commitment: detect the format and run
/// the matching segmenter. A `%PDF-` file is tried as a **traditional-xref**
/// object scheme first, then as a **modern** (cross-reference-stream / ObjStm)
/// PDF (ADR-0028); the format tag recorded on the returned manifest reflects
/// whichever succeeded, so the producer dispatches the right redaction path.
/// Any error (unsupported, malformed, over-capacity) is returned to the caller,
/// which falls back to the non-redactable chunk commitment.
pub fn segment_document(
    bytes: &[u8],
    blind_secret: &[u8],
) -> Result<SegmentManifest, SegmentError> {
    match detect_format(bytes) {
        Some(SegmentFormat::PdfObject) => crate::zk::pdf_objects::PdfSegmenter
            .extract(bytes, blind_secret)
            .or_else(|_| pdf_xref::ModernPdfSegmenter.extract(bytes, blind_secret)),
        Some(other) => segmenter_for(other)
            .expect("detected format always has a segmenter")
            .extract(bytes, blind_secret),
        None => Err(SegmentError::Unsupported("unknown")),
    }
}

/// Produce the redacted artifact for an already-loaded manifest, dispatching on
/// its `format`. The single entry point the producer endpoints call.
pub fn apply_redaction(
    bytes: &[u8],
    manifest: &SegmentManifest,
    redacted_ids: &[u32],
) -> Result<Vec<u8>, SegmentError> {
    let segmenter = segmenter_for(manifest.format)
        .ok_or(SegmentError::Unsupported(manifest.format.as_tag()))?;
    segmenter.apply_redaction(bytes, manifest, redacted_ids)
}

/// Produce the redacted artifact **and** each segment's byte span in it
/// (ADR-0030 §2a), dispatching on `manifest.format`. The entry point the V3
/// `/redaction/redact` producer calls to populate the bundle's per-segment
/// `artifact_offset` / `artifact_length`.
pub fn apply_redaction_with_spans(
    bytes: &[u8],
    manifest: &SegmentManifest,
    redacted_ids: &[u32],
) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
    let segmenter = segmenter_for(manifest.format)
        .ok_or(SegmentError::Unsupported(manifest.format.as_tag()))?;
    segmenter.apply_redaction_with_spans(bytes, manifest, redacted_ids)
}

// ── Shared Merkle math (format-agnostic) ──────────────────────────────────────

impl SegmentManifest {
    /// Decode the `leaf_hex` of every segment into the `N` **real** leaves (no
    /// padding) in commitment order. Fails closed on a non-canonical
    /// (`≥ modulus`) or over-long persisted leaf — the same F-RD-2 guard
    /// `pdf_objects` applies, so a tampered manifest can't smuggle a reduced
    /// field element into the fold. Rejects `> MAX_REDACTION_SEGMENTS` segments.
    pub(crate) fn leaves(&self) -> Result<Vec<Fr>, SegmentError> {
        if self.segments.len() > MAX_REDACTION_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: self.segments.len(),
                max: MAX_REDACTION_SEGMENTS,
            });
        }
        let mut leaves: Vec<Fr> = Vec::with_capacity(self.segments.len());
        for s in &self.segments {
            let bytes = hex::decode(&s.leaf_hex)
                .map_err(|e| SegmentError::LeafComputationFailed(e.to_string()))?;
            // A leaf_hex longer than 32 bytes would panic the fixed-buffer copy
            // (`off` saturates to 0, src longer than dst). Reject it.
            if bytes.len() > 32 {
                return Err(SegmentError::LeafComputationFailed(format!(
                    "leaf_hex decodes to {} bytes (> 32)",
                    bytes.len()
                )));
            }
            let mut padded = [0u8; 32];
            let off = 32 - bytes.len();
            padded[off..].copy_from_slice(&bytes);
            leaves.push(
                validate_be_bytes_to_fr(&padded)
                    .map_err(|e| SegmentError::LeafComputationFailed(e.to_string()))?,
            );
        }
        Ok(leaves)
    }

    /// Recompute the commitment root from the segment leaves and return it as
    /// lower-hex — the ADR-0030 §1 variable-depth domain-1 fold. Callers that
    /// load a persisted manifest MUST assert this equals `original_root_hex`
    /// before issuing a bundle (F-RD-2).
    pub fn recompute_root(&self) -> Result<String, SegmentError> {
        Ok(crate::zk::chunk::fr_to_hex(variable_depth_fold_root(
            &self.leaves()?,
        )?))
    }
}

/// ADR-0030 §1 **variable-depth** commitment fold for the V3 signed-Merkle bundle.
///
/// Pads the `N` real leaves (already in ascending `segment_id` order) up to
/// `2^depth`, `depth = ⌈log2 N⌉`, with the **BN254 scalar-field zero `Fr(0)`** —
/// **not** the `OLY:EMPTY-LEAF:V1` SMT sentinel (they are disjoint trees, ADR-0030
/// §1) — and folds with `domain_node(NODE_DOMAIN,…)`.
///
/// Rejects `N < 2` ([`SegmentError::TooFewSegments`] → chunk fallback) and
/// `N > MAX_REDACTION_SEGMENTS` ([`SegmentError::TooManySegments`], the DoS guard
/// that replaces the deleted 1024 cap).
pub(crate) fn variable_depth_fold_root(leaves: &[Fr]) -> Result<Fr, SegmentError> {
    let n = leaves.len();
    if n < 2 {
        return Err(SegmentError::TooFewSegments { found: n, min: 2 });
    }
    if n > MAX_REDACTION_SEGMENTS {
        return Err(SegmentError::TooManySegments {
            found: n,
            max: MAX_REDACTION_SEGMENTS,
        });
    }
    // width = 2^⌈log2 N⌉ — the smallest power of two ≥ N (next_power_of_two is the
    // identity on an exact power of two, so N=1024 → 1024 → depth 10, not 11).
    let width = n.next_power_of_two();
    let mut level: Vec<Fr> = Vec::with_capacity(width);
    level.extend_from_slice(leaves);
    level.resize(width, Fr::from(0u64));
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(
                domain_node(NODE_DOMAIN, pair[0], pair[1])
                    .map_err(|e| SegmentError::Poseidon(e.to_string()))?,
            );
        }
        level = next;
    }
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tag_roundtrips() {
        for f in [
            SegmentFormat::PdfObject,
            SegmentFormat::PdfXrefStream,
            SegmentFormat::TextLine,
            SegmentFormat::OoxmlPart,
            SegmentFormat::PdfTextRun,
        ] {
            assert_eq!(SegmentFormat::from_tag(f.as_tag()), Some(f));
        }
        assert_eq!(SegmentFormat::from_tag("bogus"), None);
    }

    #[test]
    fn detect_pdf_text_and_binary() {
        assert_eq!(
            detect_format(b"%PDF-1.7\n..."),
            Some(SegmentFormat::PdfObject)
        );
        assert_eq!(
            detect_format(b"hello\nworld\n"),
            Some(SegmentFormat::TextLine)
        );
        // ZIP magic is binary → falls through to the chunk path (None).
        assert_eq!(detect_format(b"PK\x03\x04\x00\x00\xff\xfe"), None);
        assert_eq!(detect_format(b""), None);
    }

    #[test]
    fn every_format_has_a_segmenter() {
        assert!(segmenter_for(SegmentFormat::PdfObject).is_some());
        assert!(segmenter_for(SegmentFormat::TextLine).is_some());
        assert!(segmenter_for(SegmentFormat::OoxmlPart).is_some());
    }

    #[test]
    fn non_pdf_manifest_recompute_matches_committed_root() {
        // The segment→fold bridge is format-agnostic: a text manifest's real
        // leaves must fold (ADR-0030 §1 variable-depth) to its committed root.
        // This is the V3 producer's F-RD-2 cross-check, for a NON-PDF format.
        let doc = b"alpha line\nbeta line\ngamma line\ndelta line\n";
        let m = text::TextSegmenter.extract(doc, &[0x5au8; 32]).unwrap();
        assert_eq!(
            m.recompute_root().unwrap(),
            m.original_root_hex,
            "text manifest leaves fold to its committed variable-depth root"
        );
    }

    #[test]
    fn detect_distinguishes_ooxml_from_plain_zip() {
        // A ZIP that names the OOXML content-types part → OOXML.
        let mut docx = b"PK\x03\x04".to_vec();
        docx.extend_from_slice(b"....[Content_Types].xml....");
        assert_eq!(detect_format(&docx), Some(SegmentFormat::OoxmlPart));
        // A plain ZIP without it (binary, non-UTF-8) stays in the chunk fallback.
        assert_eq!(detect_format(b"PK\x03\x04\x14\x00\xff\xfe\xab\xcd"), None);
    }

    fn leaf_segment(id: u32, leaf_hex: String) -> Segment {
        Segment {
            segment_id: id,
            label: None,
            byte_offset: 0,
            byte_length: 0,
            leaf_hex,
        }
    }

    #[test]
    fn leaves_reject_oversized_leaf_hex_without_panic() {
        // A leaf_hex decoding to > 32 bytes must error, not panic the fixed buffer.
        // (Two segments so the variable-depth fold's N>=2 guard isn't what fires.)
        let (depth, max_leaves) = variable_geometry(2);
        let m = SegmentManifest {
            format: SegmentFormat::TextLine,
            segments: vec![
                leaf_segment(0, "ab".repeat(40)), // 40 bytes
                leaf_segment(1, "00".repeat(32)),
            ],
            original_root_hex: "00".repeat(32),
            tree_depth: depth,
            max_leaves,
        };
        assert!(matches!(
            m.recompute_root(),
            Err(SegmentError::LeafComputationFailed(_))
        ));
    }

    // ── ADR-0030 §1 variable-depth fold ───────────────────────────────────────

    #[test]
    fn variable_depth_fold_rejects_n_below_two() {
        // N=0 and N=1 are non-redactable (no reveal/hide partition) → chunk fallback.
        assert!(matches!(
            variable_depth_fold_root(&[]),
            Err(SegmentError::TooFewSegments { found: 0, min: 2 })
        ));
        assert!(matches!(
            variable_depth_fold_root(&[Fr::from(1u64)]),
            Err(SegmentError::TooFewSegments { found: 1, min: 2 })
        ));
    }

    #[test]
    fn variable_depth_fold_rejects_over_cap() {
        // len() is checked before any folding, so this errors immediately.
        let leaves = vec![Fr::from(0u64); MAX_REDACTION_SEGMENTS + 1];
        assert!(matches!(
            variable_depth_fold_root(&leaves),
            Err(SegmentError::TooManySegments { found, max })
                if found == MAX_REDACTION_SEGMENTS + 1 && max == MAX_REDACTION_SEGMENTS
        ));
    }

    #[test]
    fn variable_depth_fold_n2_is_single_domain_node() {
        let leaves = [Fr::from(5u64), Fr::from(6u64)];
        let expected = domain_node(NODE_DOMAIN, Fr::from(5u64), Fr::from(6u64)).unwrap();
        assert_eq!(variable_depth_fold_root(&leaves).unwrap(), expected);
    }

    #[test]
    fn variable_depth_fold_pads_non_power_of_two_with_fr_zero() {
        // N=3 → width 4, padded with one Fr(0); two node levels. Pins the pad value
        // to the BN254 field zero (NOT the OLY:EMPTY-LEAF sentinel) and the fold shape.
        let leaves = [Fr::from(7u64), Fr::from(8u64), Fr::from(9u64)];
        let l0 = domain_node(NODE_DOMAIN, Fr::from(7u64), Fr::from(8u64)).unwrap();
        let l1 = domain_node(NODE_DOMAIN, Fr::from(9u64), Fr::from(0u64)).unwrap();
        let expected = domain_node(NODE_DOMAIN, l0, l1).unwrap();
        assert_eq!(variable_depth_fold_root(&leaves).unwrap(), expected);
    }

    #[test]
    fn variable_depth_fold_at_exact_power_of_two_needs_no_padding() {
        // N == 1024 is an exact power of two → depth 10, no Fr(0) padding. Pin the
        // result against an independent level-by-level recomputation of the same
        // domain-1 fold over exactly the 1024 leaves.
        let leaves: Vec<Fr> = (0..1024u64).map(Fr::from).collect();
        let mut level = leaves.clone();
        while level.len() > 1 {
            level = level
                .chunks(2)
                .map(|p| domain_node(NODE_DOMAIN, p[0], p[1]).unwrap())
                .collect();
        }
        assert_eq!(variable_depth_fold_root(&leaves).unwrap(), level[0]);
        assert_eq!(variable_geometry(1024), (10, 1024));
    }
}
