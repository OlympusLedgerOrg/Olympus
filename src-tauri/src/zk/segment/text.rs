//! Plain-text / Markdown line-block segmenter (ADR-0026 Phase 2).
//!
//! Segments a UTF-8 document into contiguous **line blocks** that tile the whole
//! file on `\n` boundaries, one hiding leaf per block. A file with ≤
//! [`MAX_SEGMENTS`] lines gets one block per line; a larger file groups
//! consecutive lines into ≤ `MAX_SEGMENTS` equal-ish blocks so any text file fits
//! the 1024-leaf commitment. Redaction NUL-fills the selected block's byte span
//! in place — the file length and every other block's bytes are preserved
//! byte-for-byte, so non-redacted leaves recompute unchanged (the same
//! byte-identity property the PDF object scheme relies on).
//!
//! The leaf construction is identical to every other format
//! ([`crate::zk::segment`] module docs): the content/blinding key is the block's
//! `segment_id` as 4 big-endian bytes, so the producer's generic revealed-
//! blinding re-derivation works without a format branch.

use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

use crate::zk::chunk::fr_to_hex;
use crate::zk::segment::{
    fold_root, Segment, SegmentError, SegmentFormat, SegmentManifest, Segmenter, MAX_SEGMENTS,
    TREE_DEPTH,
};

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

/// Group `n` lines into ≤ [`MAX_SEGMENTS`] contiguous blocks. Returns the number
/// of source lines per block (≥ 1); the block count is `ceil(n / lines_per_block)`.
fn lines_per_block(n: usize) -> usize {
    if n <= MAX_SEGMENTS {
        1
    } else {
        n.div_ceil(MAX_SEGMENTS)
    }
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

        // Tiling above caps the block count at MAX_SEGMENTS, but assert it so a
        // future change to the grouping can't silently overflow the tree.
        if segments.len() > MAX_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: segments.len(),
                max: MAX_SEGMENTS,
            });
        }

        let root = fold_root(&leaves)?;
        Ok(SegmentManifest {
            format: SegmentFormat::TextLine,
            segments,
            original_root_hex: fr_to_hex(root),
            tree_depth: TREE_DEPTH,
            max_leaves: MAX_SEGMENTS,
        })
    }

    fn apply_redaction(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<Vec<u8>, SegmentError> {
        let mut out = bytes.to_vec();
        for &id in redacted_ids {
            let seg = manifest
                .segments
                .iter()
                .find(|s| s.segment_id == id)
                .ok_or(SegmentError::UnknownSegment(id))?;
            let start = seg.byte_offset as usize;
            let end = start
                .checked_add(seg.byte_length as usize)
                .filter(|&e| e <= out.len())
                .ok_or(SegmentError::OutOfBounds(id))?;
            // NUL-fill the whole block span: length + every other block's bytes
            // are preserved, so non-redacted leaves recompute unchanged.
            for b in &mut out[start..end] {
                *b = 0;
            }
        }
        Ok(out)
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
    fn large_file_groups_into_at_most_max_segments() {
        // 3000 lines > MAX_SEGMENTS (1024) → grouped into ≤ 1024 blocks.
        let doc: Vec<u8> = (0..3000)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        let m = TextSegmenter.extract(&doc, SECRET).unwrap();
        assert!(m.segments.len() <= MAX_SEGMENTS);
        assert!(m.segments.len() > 1);
        // Blocks tile the file: contiguous and covering [0, len).
        assert_eq!(m.segments.first().unwrap().byte_offset, 0);
        let last = m.segments.last().unwrap();
        assert_eq!(last.byte_offset + last.byte_length, doc.len() as u64);
        for w in m.segments.windows(2) {
            assert_eq!(w[0].byte_offset + w[0].byte_length, w[1].byte_offset);
        }
        // A multi-line block carries a range label.
        assert!(m.segments[0]
            .label
            .as_deref()
            .unwrap()
            .starts_with("lines "));
    }

    #[test]
    fn apply_redaction_zeros_only_the_target_block() {
        let doc = b"keep one\nHIDE TWO\nkeep three\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let out = TextSegmenter.apply_redaction(doc, &m, &[1]).unwrap();
        assert_eq!(out.len(), doc.len(), "length preserved");
        // Block 0 + block 2 byte-identical; block 1 fully zeroed.
        let s1 = &m.segments[1];
        let (s, e) = (
            s1.byte_offset as usize,
            (s1.byte_offset + s1.byte_length) as usize,
        );
        assert!(out[s..e].iter().all(|&b| b == 0), "redacted block is NUL");
        assert_eq!(&out[..s], &doc[..s], "earlier bytes untouched");
        assert_eq!(&out[e..], &doc[e..], "later bytes untouched");
        // SECURITY: the redacted line's plaintext is absent from the output.
        assert!(
            !out.windows(8).any(|w| w == b"HIDE TWO"),
            "redacted plaintext must not survive in the artifact"
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
        // bytes + published blindings; they must match the committed manifest.
        let doc = b"public a\nSECRET b\npublic c\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let content_hash = blake3::hash(doc);
        let redacted = TextSegmenter.apply_redaction(doc, &m, &[1]).unwrap();
        for seg in &m.segments {
            if seg.segment_id == 1 {
                continue; // redacted — its bytes are gone by design
            }
            let id_be = seg.segment_id.to_be_bytes();
            let s = seg.byte_offset as usize;
            let e = s + seg.byte_length as usize;
            let content = content_scalar(&id_be, &redacted[s..e]);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(leaf, seg.leaf_hex, "revealed leaf recomputes from artifact");
        }
    }

    #[test]
    fn spans_locate_revealed_leaves() {
        // ADR-0030 §2a/§3 `text-line`: the per-segment span returned alongside the
        // artifact must let a verifier slice the revealed bytes (full line block,
        // including the trailing `\n`) and recompute the committed leaf. In-place
        // NUL-fill ⇒ the output span equals the original committed span.
        let doc = b"public a\nSECRET b\npublic c\n";
        let m = TextSegmenter.extract(doc, SECRET).unwrap();
        let content_hash = blake3::hash(doc);
        let (artifact, spans) = TextSegmenter
            .apply_redaction_with_spans(doc, &m, &[1])
            .unwrap();
        assert_eq!(artifact.len(), doc.len(), "in-place: length preserved");
        assert_eq!(spans.len(), m.segments.len());
        for (seg, span) in m.segments.iter().zip(&spans) {
            assert_eq!(span.segment_id, seg.segment_id);
            assert_eq!(
                span.artifact_offset, seg.byte_offset,
                "in-place span offset"
            );
            assert_eq!(
                span.artifact_length, seg.byte_length,
                "in-place span length"
            );
            if seg.segment_id == 1 {
                continue; // redacted — leaf_hex is authoritative, bytes are gone
            }
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
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
    fn non_utf8_is_unsupported() {
        assert!(matches!(
            TextSegmenter.extract(&[0xff, 0xfe, 0x00], SECRET),
            Err(SegmentError::Unsupported("text-line"))
        ));
    }
}
