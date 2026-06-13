//! Format-agnostic redaction *segment* abstraction (ADR-0026 §2).
//!
//! A **segment** is a format-defined, independently-redactable unit of a
//! document: a PDF indirect object, a plain-text line-block, or (Phase 3) an
//! OOXML package part. Each segment yields exactly one **hiding** circuit leaf
//! (`olympus_crypto::redaction::redaction_leaf` — a blinded Pedersen commitment),
//! and the leaves fold into the **unchanged** depth-10 / 1024-leaf
//! `redaction_validity` Poseidon tree (ADR-0025).
//!
//! The whole crypto stack downstream of a segment is format-agnostic: the
//! circuit, witness ([`crate::zk::witness::redaction`]), bundle signature, and
//! both offline verifiers consume opaque leaf field-elements + published
//! blindings — they never see document structure. So **only two operations are
//! format-specific**: parsing bytes into segments ([`Segmenter::extract`]) and
//! producing the redacted artifact ([`Segmenter::apply_redaction`]). Everything
//! else — the Merkle fold, witness inputs, reveal mask, root recompute — lives
//! here once and is shared by every format.
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
use crate::zk::poseidon::domain_node;
use crate::zk::witness::redaction::{MAX_LEAVES, REDACTION_DEPTH};

pub mod ooxml;
pub mod pdf_xref;
pub mod text;

/// Maximum committed segments — mirrors the circuit's `REDACTION_MAX_LEAVES`.
pub const MAX_SEGMENTS: usize = MAX_LEAVES;
/// Merkle depth such that `2^TREE_DEPTH == MAX_SEGMENTS`.
pub const TREE_DEPTH: u8 = REDACTION_DEPTH as u8;
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
        }
    }

    /// Parse a persisted tag. Returns `None` for an unknown tag (fail-closed).
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "pdf-object" => Some(SegmentFormat::PdfObject),
            "pdf-xref-stream" => Some(SegmentFormat::PdfXrefStream),
            "text-line" => Some(SegmentFormat::TextLine),
            "ooxml-part" => Some(SegmentFormat::OoxmlPart),
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

/// A document's full segment commitment: ordered segments + the Merkle root the
/// `redaction_validity` circuit proves over. Generalises ADR-0025's
/// `PdfObjectManifest` across formats.
#[derive(Debug, Clone)]
pub struct SegmentManifest {
    pub format: SegmentFormat,
    /// In commitment order (PDF: obj-id ascending; text: block index ascending).
    /// `segment_id`s are strictly ascending and unique.
    pub segments: Vec<Segment>,
    /// 64-char lower-hex Merkle root over the (padded) segment leaves — the
    /// ledger leaf and the circuit's `originalRoot`.
    pub original_root_hex: String,
    pub tree_depth: u8,
    pub max_leaves: usize,
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
    #[error("leaf computation failed: {0}")]
    LeafComputationFailed(String),
    #[error("Poseidon error: {0}")]
    Poseidon(String),
}

// ── The per-format contract ───────────────────────────────────────────────────

/// The two format-specific operations the redaction producer needs. One impl
/// per supported format; the rest of the pipeline is format-agnostic.
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

// ── Shared Merkle math (format-agnostic) ──────────────────────────────────────

impl SegmentManifest {
    /// Decode the `leaf_hex` of every segment into a `MAX_SEGMENTS`-padded leaf
    /// vector (real leaves in commitment order, then zero-leaf padding). Fails
    /// closed on a non-canonical (`≥ modulus`) persisted leaf — the same F-RD-2
    /// guard `pdf_objects` applies, so a tampered manifest can't smuggle a
    /// reduced field element past the circuit.
    pub(crate) fn padded_leaves(&self) -> Result<Vec<Fr>, SegmentError> {
        // Fail closed rather than silently truncating in `resize` below — a
        // manifest with > MAX_SEGMENTS segments would otherwise fold/prove a root
        // over only the first MAX_SEGMENTS leaves. (extract() and the loader also
        // reject this; this guards every caller of the shared helper.)
        if self.segments.len() > MAX_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: self.segments.len(),
                max: MAX_SEGMENTS,
            });
        }
        let mut leaves: Vec<Fr> = Vec::with_capacity(MAX_SEGMENTS);
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
        leaves.resize(MAX_SEGMENTS, Fr::from(0u64));
        Ok(leaves)
    }

    /// Recompute the commitment root from the segment leaves and return it as
    /// lower-hex — the identical domain-1 fold the circuit performs. Callers
    /// that load a persisted manifest MUST assert this equals
    /// `original_root_hex` before building a witness (F-RD-2).
    pub fn recompute_root(&self) -> Result<String, SegmentError> {
        let leaves = self.padded_leaves()?;
        Ok(crate::zk::chunk::fr_to_hex(fold_root(&leaves)?))
    }

    /// The 1024-leaf `redaction_validity` witness inputs (padded leaves +
    /// per-leaf Merkle `(path_elements, path_indices)`). Format-agnostic: it
    /// only reads `leaf_hex`. Replaces `pdf_objects::witness_inputs` for the
    /// generalised producer.
    #[allow(clippy::type_complexity)]
    pub fn witness_inputs(&self) -> Result<(Vec<Fr>, Vec<Vec<Fr>>, Vec<Vec<u8>>), SegmentError> {
        let leaves = self.padded_leaves()?;

        // Pre-compute every tree level once; each leaf's path is the sibling at
        // the right index per level (same algorithm as `pdf_objects::witness_inputs`).
        let mut levels: Vec<Vec<Fr>> = Vec::with_capacity(TREE_DEPTH as usize + 1);
        levels.push(leaves.clone());
        for d in 0..TREE_DEPTH as usize {
            let cur = &levels[d];
            let mut next = Vec::with_capacity(cur.len() / 2);
            for pair in cur.chunks(2) {
                next.push(
                    domain_node(1, pair[0], pair[1])
                        .map_err(|e| SegmentError::Poseidon(e.to_string()))?,
                );
            }
            levels.push(next);
        }

        let mut path_elements = Vec::with_capacity(MAX_SEGMENTS);
        let mut path_indices = Vec::with_capacity(MAX_SEGMENTS);
        for leaf_i in 0..MAX_SEGMENTS {
            let mut idx = leaf_i;
            let mut pe = Vec::with_capacity(TREE_DEPTH as usize);
            let mut pi = Vec::with_capacity(TREE_DEPTH as usize);
            for level in levels.iter().take(TREE_DEPTH as usize) {
                let sibling = idx ^ 1;
                pe.push(level[sibling]);
                pi.push((idx & 1) as u8);
                idx /= 2;
            }
            path_elements.push(pe);
            path_indices.push(pi);
        }
        Ok((leaves, path_elements, path_indices))
    }
}

/// Fold `leaves` (padded to `MAX_SEGMENTS` with zero-leaves) into a depth-
/// `TREE_DEPTH` domain-1 Poseidon root — byte-identical to
/// `pdf_objects::merkle_root` and the circuit's flat fold.
pub(crate) fn fold_root(leaves: &[Fr]) -> Result<Fr, SegmentError> {
    debug_assert!(leaves.len() <= MAX_SEGMENTS);
    let mut level: Vec<Fr> = leaves.to_vec();
    level.resize(MAX_SEGMENTS, Fr::from(0u64));
    for _ in 0..TREE_DEPTH {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next.push(
                domain_node(1, pair[0], pair[1])
                    .map_err(|e| SegmentError::Poseidon(e.to_string()))?,
            );
        }
        level = next;
    }
    debug_assert_eq!(level.len(), 1);
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_tag_roundtrips() {
        for f in [
            SegmentFormat::PdfObject,
            SegmentFormat::TextLine,
            SegmentFormat::OoxmlPart,
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
    fn non_pdf_manifest_witness_paths_reach_committed_root() {
        // The segment→witness bridge is format-agnostic: a text manifest's
        // padded leaves + Merkle paths must fold to its committed root exactly
        // as the `redaction_validity` circuit will. This exercises the same
        // `witness_inputs()` → `RedactionWitness` path the producer uses, for a
        // NON-PDF format, without needing circuit artifacts.
        use ark_ff::PrimeField;
        let doc = b"alpha line\nbeta line\ngamma line\ndelta line\n";
        let m = text::TextSegmenter.extract(doc, &[0x5au8; 32]).unwrap();
        let (leaves, pe, pi) = m.witness_inputs().unwrap();
        let root_bytes = hex::decode(&m.original_root_hex).unwrap();
        let mut padded = [0u8; 32];
        padded[32 - root_bytes.len()..].copy_from_slice(&root_bytes);
        let root = Fr::from_be_bytes_mod_order(&padded);
        let mask = vec![false; leaves.len()];
        let w = crate::zk::witness::RedactionWitness::new_test(
            root,
            leaves,
            mask,
            pe,
            pi,
            Fr::from(7u64),
        )
        .expect("witness constructs from a text manifest");
        assert!(
            w.verify_all_paths().is_ok(),
            "text manifest leaves + paths fold to its committed root"
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
    fn padded_leaves_rejects_oversized_leaf_hex_without_panic() {
        // A leaf_hex decoding to > 32 bytes must error, not panic the fixed buffer.
        let m = SegmentManifest {
            format: SegmentFormat::TextLine,
            segments: vec![leaf_segment(0, "ab".repeat(40))], // 40 bytes
            original_root_hex: "00".repeat(32),
            tree_depth: TREE_DEPTH,
            max_leaves: MAX_SEGMENTS,
        };
        assert!(matches!(
            m.recompute_root(),
            Err(SegmentError::LeafComputationFailed(_))
        ));
    }

    #[test]
    fn padded_leaves_rejects_over_capacity_without_truncating() {
        // > MAX_SEGMENTS segments must fail closed, not silently fold a subset.
        let segments = (0..=MAX_SEGMENTS as u32)
            .map(|i| leaf_segment(i, "00".repeat(32)))
            .collect();
        let m = SegmentManifest {
            format: SegmentFormat::TextLine,
            segments,
            original_root_hex: "00".repeat(32),
            tree_depth: TREE_DEPTH,
            max_leaves: MAX_SEGMENTS,
        };
        assert!(matches!(
            m.recompute_root(),
            Err(SegmentError::TooManySegments { .. })
        ));
    }
}
