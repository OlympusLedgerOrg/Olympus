//! Plain-text / Markdown line-block segmenter (ADR-0026 Phase 2).
//!
//! Segments a UTF-8 document into contiguous **line blocks** that tile the whole
//! file on `\n` boundaries, one hiding leaf per block. A file with ≤
//! [`MAX_REDACTION_SEGMENTS`] lines gets one block per line; a larger file groups
//! consecutive lines into ≤ `MAX_REDACTION_SEGMENTS` equal-ish blocks so any text
//! file fits the ADR-0030 variable-depth commitment. Redaction **re-emits** the
//! document, replacing each selected block with the fixed-width token
//! [`REDACTION_TEXT_TOKEN`] (`[REDACTED]\n`, ADR-0034) — a length-INDEPENDENT
//! constant, so the artifact never discloses how many bytes were hidden (closing
//! the size oracle of the superseded width-preserving fill). Every non-redacted
//! block's bytes are emitted **verbatim** (byte-identical, just relocated), so its
//! leaf recomputes unchanged from the per-segment span the bundle publishes; the
//! redacted block's true leaf is carried in the bundle (`leaf_hex`) and its bytes
//! are gone. Because the token length differs from the original block, this is a
//! re-emit format (offsets shift) — it overrides
//! [`Segmenter::apply_redaction_with_spans`] to report the produced offsets.
//!
//! The leaf construction is identical to every other format
//! ([`crate::zk::segment`] module docs): the content/blinding key is the block's
//! `segment_id` as 4 big-endian bytes, so the producer's generic revealed-
//! blinding re-derivation works without a format branch.

use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

use crate::zk::chunk::fr_to_hex;
use crate::zk::segment::{
    variable_depth_fold_root, variable_geometry, Segment, SegmentError, SegmentFormat,
    SegmentManifest, SegmentSpan, Segmenter, MAX_REDACTION_SEGMENTS,
};

/// Fixed-width replacement for a redacted text block (ADR-0034). Length-
/// INDEPENDENT of the hidden content, so the artifact discloses only *that* a
/// block was redacted, never its original size. The trailing `\n` preserves line
/// structure (a redacted block never concatenates onto the surrounding lines).
/// The redacted block's committed leaf is authoritative in the bundle, so this
/// token never enters any leaf or verifier computation — it is presentation only.
pub const REDACTION_TEXT_TOKEN: &[u8] = b"[REDACTED]\n";

/// The text/Markdown [`Segmenter`].
pub struct TextSegmenter;

/// One source line as a half-open byte span `[start, end)` covering the line
/// **and its trailing `\n`** (the final line has no trailing newline). The
/// spans tile `[0, len)` exactly.
fn line_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            spans.push((start, i + 1));
            start = i + 1;
        }
    }
    if start < bytes.len() {
        spans.push((start, bytes.len()));
    }
    spans
}

/// Group `n` lines into ≤ [`MAX_REDACTION_SEGMENTS`] contiguous blocks. Returns
/// the source lines per block (≥ 1); the block count is `ceil(n / lines_per_block)`.
fn lines_per_block(n: usize) -> usize {
    if n <= MAX_REDACTION_SEGMENTS {
        1
    } else {
        n.div_ceil(MAX_REDACTION_SEGMENTS)
    }
}

/// Re-emit the document with each `redacted_ids` block replaced by the fixed-width
/// [`REDACTION_TEXT_TOKEN`], returning the produced artifact plus each segment's
/// span **in that artifact** (ADR-0034). Revealed blocks are copied byte-for-byte
/// (so their committed leaf recomputes from the published span); redacted blocks
/// become the constant token (length-independent → no size disclosure). The
/// segments tile `[0, len)` in ascending byte order, so concatenating them
/// reconstructs the document exactly. Fails closed if a redacted id is unknown or
/// a revealed segment's committed span is out of bounds for `bytes`.
fn reemit(
    bytes: &[u8],
    manifest: &SegmentManifest,
    redacted_ids: &[u32],
) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
    let redacted: std::collections::HashSet<u32> = redacted_ids.iter().copied().collect();
    // Every redacted id must be a real segment (fail closed before producing).
    for &id in &redacted {
        if !manifest.segments.iter().any(|s| s.segment_id == id) {
            return Err(SegmentError::UnknownSegment(id));
        }
    }

    let mut out = Vec::with_capacity(bytes.len());
    let mut spans = Vec::with_capacity(manifest.segments.len());
    for seg in &manifest.segments {
        let artifact_offset = out.len() as u64;
        if redacted.contains(&seg.segment_id) {
            out.extend_from_slice(REDACTION_TEXT_TOKEN);
        } else {
            let start = seg.byte_offset as usize;
            let end = start
                .checked_add(seg.byte_length as usize)
                .filter(|&e| e <= bytes.len())
                .ok_or(SegmentError::OutOfBounds(seg.segment_id))?;
            out.extend_from_slice(&bytes[start..end]);
        }
        spans.push(SegmentSpan {
            segment_id: seg.segment_id,
            artifact_offset,
            artifact_length: out.len() as u64 - artifact_offset,
        });
    }
    Ok((out, spans))
}

impl Segmenter for TextSegmenter {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::TextLine
    }

    fn extract(&self, bytes: &[u8], blind_secret: &[u8]) -> Result<SegmentManifest, SegmentError> {
        if std::str::from_utf8(bytes).is_err() {
            return Err(SegmentError::Unsupported("text-line"));
        }
        // Blinding is keyed by the ORIGINAL file's content hash (ADR-0026), so
        // re-ingesting the same bytes under the same secret reproduces the root.
        let content_hash = blake3::hash(bytes);

        let lines = line_spans(bytes);
        if lines.is_empty() {
            // Empty / whitespace-free-of-newlines-and-empty file: nothing to
            // segment. (A single-line file yields one block and is correctly
            // un-redactable downstream — you can't reveal-all or hide-all.)
            return Err(SegmentError::Unsupported("text-line"));
        }
        let per_block = lines_per_block(lines.len());

        let mut segments: Vec<Segment> = Vec::new();
        let mut leaves = Vec::new();
        for (block_idx, chunk) in lines.chunks(per_block).enumerate() {
            let segment_id = block_idx as u32;
            let start = chunk.first().expect("non-empty chunk").0;
            let end = chunk.last().expect("non-empty chunk").1;
            let id_be = segment_id.to_be_bytes();

            let content = content_scalar(&id_be, &bytes[start..end]);
            let blinding = derive_blinding(blind_secret, content_hash.as_bytes(), &id_be);
            let leaf_fr = redaction_leaf(&content, &blinding)
                .map_err(|e| SegmentError::LeafComputationFailed(e.to_string()))?;

            // 0-based line range → 1-based inclusive label for the producer UI.
            let first_line = block_idx * per_block + 1;
            let last_line = first_line + chunk.len() - 1;
            let label = if chunk.len() == 1 {
                format!("line {first_line}")
            } else {
                format!("lines {first_line}-{last_line}")
            };

            leaves.push(leaf_fr);
            segments.push(Segment {
                segment_id,
                label: Some(label),
                byte_offset: start as u64,
                byte_length: (end - start) as u64,
                leaf_hex: fr_to_hex(leaf_fr),
            });
        }

        // Tiling above caps the block count at MAX_REDACTION_SEGMENTS, but assert
        // it so a future change to the grouping can't silently overflow the fold.
        if segments.len() > MAX_REDACTION_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: segments.len(),
                max: MAX_REDACTION_SEGMENTS,
            });
        }

        // ADR-0030 §1 variable-depth fold over the real leaves. A single-line
        // file (N=1) surfaces here as `TooFewSegments`, which the ingest caller
        // routes to the (non-redactable) chunk fallback — exactly as intended.
        let root = variable_depth_fold_root(&leaves)?;
        let (tree_depth, max_leaves) = variable_geometry(segments.len());
        Ok(SegmentManifest {
            format: SegmentFormat::TextLine,
            segments,
            original_root_hex: fr_to_hex(root),
            tree_depth,
            max_leaves,
        })
    }

    fn apply_redaction(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<Vec<u8>, SegmentError> {
        Ok(reemit(bytes, manifest, redacted_ids)?.0)
    }

    /// Text is a **re-emit** format (the fixed-width token shifts offsets), so it
    /// overrides the default in-place span impl and returns the produced offsets
    /// (ADR-0034 §2a). The verifier slices `artifact[offset..offset+length]` and
    /// recomputes each revealed block's leaf over those (byte-identical) bytes.
    fn apply_redaction_with_spans(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
        reemit(bytes, manifest, redacted_ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = &[0x5au8; 32];

    #[test]
    fn line_spans_tile_the_file_exactly() {
        let doc = b"alpha\nbeta\ngamma";
        let spans = line_spans(doc);
        assert_eq!(spans, vec![(0, 6), (6, 11), (11, 16)]);
        // Spans are contiguous and cover [0, len).
        assert_eq!(spans.first().unwrap().0, 0);
        assert_eq!(spans.last().unwrap().1, doc.len());
        for w in spans.windows(2) {
            assert_eq!(w[0].1, w[1].0);
        }
    }

    #[test]
    fn trailing_newline_is_owned_by_its_line() {
        let spans = line_spans(b"a\nb\n");
        assert_eq!(spans, vec![(0, 2), (2, 4)]);
    }

    #[test]
    fn extract_is_deterministic_and_root_recomputes() {
        let doc = b"first line\nsecond line\nthird line\n";
        let m1 = TextSegmenter.extract(doc, SECRET).unwrap();
        let m2 = TextSegmenter.extract(doc, SECRET).unwrap();
        assert_eq!(m1.original_root_hex, m2.original_root_hex);
        assert_eq!(m1.format, SegmentFormat::TextLine);
        assert_eq!(m1.segments.len(), 3);
        // The generic fold over the persisted leaves matches the stored root.
        assert_eq!(m1.recompute_root().unwrap(), m1.original_root_hex);
        // segment_ids strictly ascending from 0.
        assert_eq!(
            m1.segments.iter().map(|s| s.segment_id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(m1.segments[0].label.as_deref(), Some("line 1"));
    }

    #[test]
    fn root_changes_with_secret_and_content() {
        let doc = b"aaa\nbbb\nccc\n";
        let base = TextSegmenter
            .extract(doc, SECRET)
            .unwrap()
            .original_root_hex;
        let other_secret = TextSegmenter
            .extract(doc, &[0xCDu8; 32])
            .unwrap()
            .original_root_hex;
        let other_doc = TextSegmenter
            .extract(b"aaa\nbbb\nxxx\n", SECRET)
            .unwrap()
            .original_root_hex;
        assert_ne!(base, other_secret, "blinding binds the secret");
        assert_ne!(base, other_doc, "content binds the leaf");
    }

    #[test]
    fn large_file_is_one_block_per_line_under_the_cap() {
        // 3000 lines ≤ MAX_REDACTION_SEGMENTS (2²⁰) → one block per line (no
        // grouping; the old fixed-1024 cap is gone, ADR-0030 §1). The block count
        // stays bounded and the blocks still tile the file exactly.
        let doc: Vec<u8> = (0..3000)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        let m = TextSegmenter.extract(&doc, SECRET).unwrap();
        assert_eq!(m.segments.len(), 3000, "one block per line under the cap");
        assert!(m.segments.len() <= MAX_REDACTION_SEGMENTS);
        // Variable-depth geometry: depth = ⌈log2 3000⌉ = 12, max_leaves = N.
        assert_eq!(m.max_leaves, 3000);
        assert_eq!(m.tree_depth, 12);
        // Blocks tile the file: contiguous and covering [0, len).
        assert_eq!(m.segments.first().unwrap().byte_offset, 0);
        let last = m.segments.last().unwrap();
        assert_eq!(last.byte_offset + last.byte_length, doc.len() as u64);
        for w in m.segments.windows(2) {
            assert_eq!(w[0].byte_offset + w[0].byte_length, w[1].byte_offset);
        }
        // A single-line block carries a "line N" label.
        assert_eq!(m.segments[0].label.as_deref(), Some("line 1"));
    }

    #[test]
    fn apply_redaction_replaces_target_block_with_token() {
        let doc = b"keep one\nHIDE TWO\nkeep three\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let out = TextSegmenter.apply_redaction(doc, &m, &[1]).unwrap();
        // Re-emit: revealed blocks verbatim, block 1 → the fixed-width token.
        assert_eq!(
            out, b"keep one\n[REDACTED]\nkeep three\n",
            "redacted block replaced by the fixed-width token, others verbatim"
        );
        // The artifact length depends on the TOKEN, not the hidden content — the
        // size oracle is closed (a 8-byte secret and an 800-byte secret both yield
        // the same token).
        let expected_len = doc.len() - "HIDE TWO\n".len() + REDACTION_TEXT_TOKEN.len();
        assert_eq!(out.len(), expected_len);
        // SECURITY: the redacted line's plaintext is absent from the output.
        assert!(
            !out.windows(8).any(|w| w == b"HIDE TWO"),
            "redacted plaintext must not survive in the artifact"
        );
    }

    #[test]
    fn token_length_is_independent_of_redacted_content() {
        // Two documents identical except for the SIZE of the hidden line must
        // produce the same artifact length — the defining property of ADR-0034.
        let short = b"a\nX\nb\n";
        let long = b"a\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nb\n";
        let ms = TextSegmenter.extract(short, SECRET).unwrap();
        let ml = TextSegmenter.extract(long, SECRET).unwrap();
        let os = TextSegmenter.apply_redaction(short, &ms, &[1]).unwrap();
        let ol = TextSegmenter.apply_redaction(long, &ml, &[1]).unwrap();
        assert_eq!(
            os, ol,
            "redacted artifacts are byte-identical → length hidden"
        );
    }

    #[test]
    fn empty_input_is_unsupported() {
        // Valid UTF-8 but no lines → nothing to segment (not object-redactable).
        assert!(matches!(
            TextSegmenter.extract(b"", SECRET),
            Err(SegmentError::Unsupported("text-line"))
        ));
    }

    #[test]
    fn redacted_artifact_reproduces_revealed_leaves() {
        // The verifier recomputes revealed leaves from the redacted artifact's
        // bytes (sliced at the PUBLISHED span — offsets shift under re-emit) +
        // published blindings; they must match the committed manifest.
        let doc = b"public a\nSECRET b\npublic c\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let content_hash = blake3::hash(doc);
        let (redacted, spans) = TextSegmenter
            .apply_redaction_with_spans(doc, &m, &[1])
            .unwrap();
        for (seg, span) in m.segments.iter().zip(&spans) {
            if seg.segment_id == 1 {
                continue; // redacted — its bytes are gone by design
            }
            let id_be = seg.segment_id.to_be_bytes();
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
            let content = content_scalar(&id_be, &redacted[s..e]);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(leaf, seg.leaf_hex, "revealed leaf recomputes from artifact");
        }
    }

    #[test]
    fn spans_locate_revealed_leaves() {
        // ADR-0030 §2a/§3 `text-line` (ADR-0034 re-emit): the per-segment span
        // returned alongside the artifact must let a verifier slice the revealed
        // bytes (full line block, including the trailing `\n`) and recompute the
        // committed leaf. Re-emit ⇒ offsets shift, so the spans are the PRODUCED
        // offsets (contiguous, tiling the artifact), not the original ones.
        let doc = b"public a\nSECRET b\npublic c\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let content_hash = blake3::hash(doc);
        let (artifact, spans) = TextSegmenter
            .apply_redaction_with_spans(doc, &m, &[1])
            .unwrap();
        assert_eq!(spans.len(), m.segments.len());
        // Spans tile the produced artifact contiguously from 0.
        assert_eq!(spans.first().unwrap().artifact_offset, 0);
        for w in spans.windows(2) {
            assert_eq!(
                w[0].artifact_offset + w[0].artifact_length,
                w[1].artifact_offset,
                "spans are contiguous in the artifact"
            );
        }
        let last = spans.last().unwrap();
        assert_eq!(
            last.artifact_offset + last.artifact_length,
            artifact.len() as u64,
            "spans cover the whole artifact"
        );
        for (seg, span) in m.segments.iter().zip(&spans) {
            assert_eq!(span.segment_id, seg.segment_id);
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
            if seg.segment_id == 1 {
                // Redacted span is exactly the fixed-width token.
                assert_eq!(&artifact[s..e], REDACTION_TEXT_TOKEN);
                continue; // leaf_hex is authoritative, original bytes are gone
            }
            let id_be = seg.segment_id.to_be_bytes();
            // text-line content_bytes = the raw slice.
            let content = content_scalar(&id_be, &artifact[s..e]);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, seg.leaf_hex,
                "revealed leaf recomputes from artifact span"
            );
        }
    }

    #[test]
    fn unknown_segment_id_is_rejected() {
        let doc = b"a\nb\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        assert!(matches!(
            TextSegmenter.apply_redaction(doc, &m, &[99]),
            Err(SegmentError::UnknownSegment(99))
        ));
    }

    #[test]
    fn redacted_artifact_folds_to_original_root() {
        // The load-bearing binding (ADR-0030 §3): the produced artifact's revealed
        // bytes (at the published spans) + the committed redacted leaf must fold
        // back to the on-ledger `original_root`. The re-emit shifts offsets, so
        // this proves the span override keeps the binding intact.
        let doc = b"public a\nSECRET b\npublic c\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let content_hash = blake3::hash(doc);
        let (artifact, spans) = TextSegmenter
            .apply_redaction_with_spans(doc, &m, &[1])
            .unwrap();

        let mut leaves = Vec::with_capacity(m.segments.len());
        for (seg, span) in m.segments.iter().zip(&spans) {
            let id_be = seg.segment_id.to_be_bytes();
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let content = if seg.segment_id == 1 {
                // Redacted: the artifact no longer holds its bytes, so recompute
                // the committed leaf from the ORIGINAL block (the value the bundle
                // carries as `leaf_hex`).
                let s = seg.byte_offset as usize;
                let e = s + seg.byte_length as usize;
                content_scalar(&id_be, &doc[s..e])
            } else {
                // Revealed: recompute from the ARTIFACT span — this is what a
                // recipient does, and it must match the committed leaf.
                let s = span.artifact_offset as usize;
                let e = s + span.artifact_length as usize;
                content_scalar(&id_be, &artifact[s..e])
            };
            leaves.push(redaction_leaf(&content, &blinding).unwrap());
        }
        let root = variable_depth_fold_root(&leaves).unwrap();
        assert_eq!(
            fr_to_hex(root),
            m.original_root_hex,
            "artifact + committed redacted leaf fold back to the on-ledger root"
        );
    }

    #[test]
    fn non_utf8_is_unsupported() {
        assert!(matches!(
            TextSegmenter.extract(&[0xff, 0xfe, 0x00], SECRET),
            Err(SegmentError::Unsupported("text-line"))
        ));
    }
}
