//! OOXML (`.docx` / `.xlsx` / `.pptx`) package-part segmenter (ADR-0026 Phase 3).
//!
//! An OOXML file is a ZIP of XML/media **parts**. Unlike PDF/text there is no
//! meaningful in-place byte fill at the container level (entries are
//! DEFLATE-compressed with per-entry CRCs), so we define a **canonical package**
//! and commit one hiding leaf per part:
//!
//! * **Canonical package** — parts sorted by name, **Stored** (uncompressed),
//!   fixed/default ZIP metadata. The committed leaves depend only on
//!   `(segment_id, part_name, decompressed_payload)`, so the root is
//!   deterministic regardless of the source package's compression or entry order
//!   (idempotent re-ingest, ADR-0026 §3).
//! * **Segment** — one part. `segment_id` is the part's 0-based index in the
//!   canonical (sorted) order; `label` is the part name. The leaf is keyed by
//!   `segment_id.to_be_bytes()` (so the generic producer's revealed-blinding
//!   re-derivation works unchanged) and the part **name is bound into the leaf
//!   content** (`lp(name) || payload`) so a rename cannot move a payload under
//!   another part's identity.
//! * **Redaction** — width-preservingly space-fill the selected parts' payloads
//!   (to their original byte-length, [`REDACTION_FILL_BYTE`], ADR-0034) and
//!   re-emit the canonical package. Every non-redacted part's `(name, payload)`
//!   is byte-identical, so its leaf recomputes unchanged; the redacted parts'
//!   entries survive (names visible) and keep their byte-width, but their content
//!   is destroyed — the same shape as PDF object space-fill, one level up.
//!   (Width-preservation discloses each redacted part's byte-length; it hides
//!   content, not size — ADR-0034 §Security.)
//!
//! Pure-Rust `zip` read/write only — no Office renderer, no native lib (the
//! explicit reason ADR-0023/0024 were rejected).

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};

use olympus_crypto::length_prefixed as lp;
use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

use crate::zk::chunk::fr_to_hex;
use crate::zk::segment::{
    variable_depth_fold_root, variable_geometry, Segment, SegmentError, SegmentFormat,
    SegmentManifest, SegmentSpan, Segmenter, MAX_INFLATE, MAX_REDACTION_SEGMENTS,
    REDACTION_FILL_BYTE,
};

/// The OOXML [`Segmenter`].
pub struct OoxmlSegmenter;

fn malformed(detail: String) -> SegmentError {
    SegmentError::Malformed {
        format: "ooxml-part",
        detail,
    }
}

/// Parse a ZIP/OOXML package into `(part_name, decompressed_payload)` pairs,
/// skipping directory entries, **sorted by name** (the canonical order). Rejects
/// duplicate names so the `segment_id → name` mapping is unambiguous.
fn read_parts(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>, SegmentError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| malformed(format!("not a readable ZIP: {e}")))?;
    // `archive.len()` comes from the (attacker-influenced) central directory;
    // clamp the speculative allocation.
    let mut parts: Vec<(String, Vec<u8>)> =
        Vec::with_capacity(archive.len().min(MAX_REDACTION_SEGMENTS + 1));
    // Cumulative decompression budget across ALL entries — a zip/deflate bomb
    // (small compressed, gigabytes inflated) must not OOM the server. Mirrors the
    // modern-PDF `inflate` cap; over-budget → Malformed → chunk fallback.
    let mut remaining = MAX_INFLATE;
    for i in 0..archive.len() {
        let f = archive
            .by_index(i)
            .map_err(|e| malformed(format!("entry {i}: {e}")))?;
        if f.is_dir() {
            continue;
        }
        let name = f.name().to_string();
        let mut payload = Vec::new();
        // Read at most `remaining + 1` so an over-budget entry is detected without
        // buffering the whole bomb. `take` consumes `f`; name is already captured.
        f.take(remaining as u64 + 1)
            .read_to_end(&mut payload)
            .map_err(|e| malformed(format!("read entry {name}: {e}")))?;
        if payload.len() > remaining {
            return Err(malformed(
                "ooxml package decompresses past the size cap".to_string(),
            ));
        }
        remaining -= payload.len();
        parts.push((name, payload));
    }
    parts.sort_by(|a, b| a.0.cmp(&b.0));
    for w in parts.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(malformed(format!("duplicate part name {}", w[0].0)));
        }
    }
    Ok(parts)
}

/// The leaf content input for a part: `lp(part_name) || payload`. Binding the
/// length-prefixed name (ADR-0005) prevents a payload from being relabelled
/// under another part's identity without changing the leaf.
fn part_content_bytes(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut v = lp(name.as_bytes());
    v.extend_from_slice(payload);
    v
}

/// Re-emit `parts` as a canonical **Stored** ZIP: sorted order (as supplied),
/// no compression, fixed write-default metadata. Deterministic output.
fn build_canonical_zip(parts: &[(String, Vec<u8>)]) -> Result<Vec<u8>, SegmentError> {
    use zip::write::SimpleFileOptions;
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip::DateTime::default_for_write())
            .unix_permissions(0o644);
        for (name, payload) in parts {
            zw.start_file(name.as_str(), opts)
                .map_err(|e| malformed(format!("start entry {name}: {e}")))?;
            zw.write_all(payload)
                .map_err(|e| malformed(format!("write entry {name}: {e}")))?;
        }
        zw.finish()
            .map_err(|e| malformed(format!("finish zip: {e}")))?;
    }
    Ok(cursor.into_inner())
}

/// Re-derive the canonical parts from the committed original bytes and
/// width-preservingly space-fill the `redacted_ids` payloads (ADR-0034) — the
/// shared body of [`OoxmlSegmenter::apply_redaction`]
/// and its spans variant. `segment_id == sorted index` (the canonical order),
/// matching `extract`; fails closed if the upload's part set / names disagree with
/// the committed manifest.
fn redacted_parts(
    bytes: &[u8],
    manifest: &SegmentManifest,
    redacted_ids: &[u32],
) -> Result<Vec<(String, Vec<u8>)>, SegmentError> {
    let mut parts = read_parts(bytes)?;
    if parts.len() != manifest.segments.len() {
        return Err(malformed(format!(
            "artifact has {} parts but the committed manifest has {}",
            parts.len(),
            manifest.segments.len()
        )));
    }

    let redacted: HashSet<u32> = redacted_ids.iter().copied().collect();
    for &id in &redacted {
        let idx = id as usize;
        if idx >= parts.len() {
            return Err(SegmentError::UnknownSegment(id));
        }
        // Fail closed if the re-derived part name disagrees with the manifest
        // label at this index (would mean the upload isn't the committed doc).
        let label = manifest
            .segments
            .iter()
            .find(|s| s.segment_id == id)
            .and_then(|s| s.label.as_deref());
        if label != Some(parts[idx].0.as_str()) {
            return Err(malformed(format!(
                "part-name mismatch at segment {id}: manifest {label:?} vs artifact {:?}",
                parts[idx].0
            )));
        }
    }

    for (idx, part) in parts.iter_mut().enumerate() {
        if redacted.contains(&(idx as u32)) {
            // Width-preserving: overwrite the payload with same-length spaces so the
            // part keeps its byte-width in the canonical package (ADR-0034); the
            // entry (name) survives, the content is destroyed. The redacted part's
            // leaf is authoritative in the bundle (`leaf_hex`), so a verifier never
            // recomputes it from these bytes.
            part.1.fill(REDACTION_FILL_BYTE);
        }
    }
    Ok(parts)
}

/// Map each entry name in a produced canonical **Stored** ZIP to its
/// `(data_offset, payload_len)`. The local-file **DATA** offset is
/// `header_start + 30 + file_name_len + extra_field_len` (the ZIP local file
/// header is a fixed 30-byte prefix, then the name, then the extra field — APPNOTE
/// §4.3.7), mirroring the `zip` crate's own `find_data_start` without forcing a
/// full re-decompression of every entry. For a Stored entry the uncompressed
/// `size` IS the on-disk data length, so `artifact[offset..offset+len]` is the
/// raw payload (ADR-0030 §3 `ooxml-part`).
fn stored_data_spans(artifact: &[u8]) -> Result<HashMap<String, (u64, u64)>, SegmentError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(artifact))
        .map_err(|e| malformed(format!("re-read canonical zip: {e}")))?;
    let mut out = HashMap::with_capacity(archive.len());
    for i in 0..archive.len() {
        let f = archive
            .by_index(i)
            .map_err(|e| malformed(format!("re-read entry {i}: {e}")))?;
        let name = f.name().to_string();
        let size = f.size();
        let hs = f.header_start() as usize;
        drop(f);
        // Need bytes [hs+26, hs+30) for the two LE u16 length fields.
        let after_fixed = hs
            .checked_add(30)
            .filter(|&e| e <= artifact.len())
            .ok_or_else(|| malformed("local file header past end of produced zip".to_string()))?;
        let name_len = u16::from_le_bytes([artifact[hs + 26], artifact[hs + 27]]) as u64;
        let extra_len = u16::from_le_bytes([artifact[hs + 28], artifact[hs + 29]]) as u64;
        let data_offset = after_fixed as u64 + name_len + extra_len;
        out.insert(name, (data_offset, size));
    }
    Ok(out)
}

impl Segmenter for OoxmlSegmenter {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::OoxmlPart
    }

    fn extract(&self, bytes: &[u8], blind_secret: &[u8]) -> Result<SegmentManifest, SegmentError> {
        let content_hash = blake3::hash(bytes);
        let parts = read_parts(bytes)?;
        if parts.is_empty() {
            return Err(SegmentError::Unsupported("ooxml-part"));
        }
        if parts.len() > MAX_REDACTION_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: parts.len(),
                max: MAX_REDACTION_SEGMENTS,
            });
        }

        let mut segments = Vec::with_capacity(parts.len());
        let mut leaves = Vec::with_capacity(parts.len());
        for (idx, (name, payload)) in parts.iter().enumerate() {
            let segment_id = idx as u32;
            let id_be = segment_id.to_be_bytes();
            let content = content_scalar(&id_be, &part_content_bytes(name, payload));
            let blinding = derive_blinding(blind_secret, content_hash.as_bytes(), &id_be);
            let leaf_fr = redaction_leaf(&content, &blinding)
                .map_err(|e| SegmentError::LeafComputationFailed(e.to_string()))?;
            leaves.push(leaf_fr);
            segments.push(Segment {
                segment_id,
                label: Some(name.clone()),
                // OOXML redaction re-canonicalises from the original bytes rather
                // than slicing a byte range, so offset is unused; length is the
                // payload size for the producer UI.
                byte_offset: 0,
                byte_length: payload.len() as u64,
                leaf_hex: fr_to_hex(leaf_fr),
            });
        }

        // ADR-0030 §1 variable-depth fold over the real part leaves. A package
        // with a single part (N=1) surfaces as `TooFewSegments`, routing the
        // ingest caller to the (non-redactable) chunk fallback.
        let root = variable_depth_fold_root(&leaves)?;
        let (tree_depth, max_leaves) = variable_geometry(segments.len());
        Ok(SegmentManifest {
            format: SegmentFormat::OoxmlPart,
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
        build_canonical_zip(&redacted_parts(bytes, manifest, redacted_ids)?)
    }

    /// The output spans are the local-file **DATA** offsets of the produced
    /// canonical Stored ZIP (ADR-0030 §2a / §3 `ooxml-part`): the verifier slices
    /// `artifact[offset..offset+length]` as the raw uncompressed payload and
    /// reconstructs the leaf over `lp(label) || payload`, with no ZIP parsing.
    fn apply_redaction_with_spans(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
        let parts = redacted_parts(bytes, manifest, redacted_ids)?;
        let artifact = build_canonical_zip(&parts)?;
        let by_name = stored_data_spans(&artifact)?;
        let spans = manifest
            .segments
            .iter()
            .map(|s| {
                let name = s.label.as_deref().ok_or_else(|| {
                    malformed(format!("segment {} has no part-name label", s.segment_id))
                })?;
                let &(offset, length) = by_name.get(name).ok_or_else(|| {
                    malformed(format!("part {name:?} absent from the rebuilt package"))
                })?;
                Ok(SegmentSpan {
                    segment_id: s.segment_id,
                    artifact_offset: offset,
                    artifact_length: length,
                })
            })
            .collect::<Result<Vec<_>, SegmentError>>()?;
        Ok((artifact, spans))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = &[0x5au8; 32];

    /// Build a deflate-compressed package (mimics a real `.docx`) so `read_parts`
    /// exercises decompression. Parts are written in the given (unsorted) order.
    fn build_pkg(parts: &[(&str, &[u8])]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, payload) in parts {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(payload).unwrap();
            }
            zw.finish().unwrap();
        }
        cursor.into_inner()
    }

    fn sample_docx() -> Vec<u8> {
        build_pkg(&[
            (
                "word/document.xml",
                b"<w:document>hello secret world</w:document>",
            ),
            ("[Content_Types].xml", b"<Types/>"),
            ("_rels/.rels", b"<Relationships/>"),
        ])
    }

    #[test]
    fn extract_sorts_parts_and_root_recomputes() {
        let docx = sample_docx();
        let m = OoxmlSegmenter.extract(&docx, SECRET).unwrap();
        assert_eq!(m.format, SegmentFormat::OoxmlPart);
        assert_eq!(m.segments.len(), 3);
        // Sorted by name → deterministic segment_id assignment.
        let labels: Vec<&str> = m
            .segments
            .iter()
            .map(|s| s.label.as_deref().unwrap())
            .collect();
        assert_eq!(
            labels,
            vec!["[Content_Types].xml", "_rels/.rels", "word/document.xml"]
        );
        assert_eq!(
            m.segments.iter().map(|s| s.segment_id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(m.recompute_root().unwrap(), m.original_root_hex);
    }

    #[test]
    fn re_ingesting_the_same_bytes_is_idempotent() {
        // The blinding binds `content_hash = blake3(uploaded bytes)` (ADR-0026),
        // so re-ingesting the IDENTICAL file reproduces the same root — the
        // property the insert-or-ignore manifest write relies on. (Two different
        // serialisations of "the same logical document" are different files with
        // different content_hashes by design — not asserted here.)
        let docx = sample_docx();
        let a = OoxmlSegmenter.extract(&docx, SECRET).unwrap();
        let b = OoxmlSegmenter.extract(&docx, SECRET).unwrap();
        assert_eq!(a.original_root_hex, b.original_root_hex);
        // Part order/labels are canonical (sorted) and stable across runs.
        assert_eq!(
            a.segments
                .iter()
                .map(|s| s.label.clone())
                .collect::<Vec<_>>(),
            b.segments
                .iter()
                .map(|s| s.label.clone())
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn root_binds_secret_and_content() {
        let base = OoxmlSegmenter
            .extract(&sample_docx(), SECRET)
            .unwrap()
            .original_root_hex;
        let other_secret = OoxmlSegmenter
            .extract(&sample_docx(), &[0xCDu8; 32])
            .unwrap()
            .original_root_hex;
        let edited = build_pkg(&[
            ("word/document.xml", b"<w:document>DIFFERENT</w:document>"),
            ("[Content_Types].xml", b"<Types/>"),
            ("_rels/.rels", b"<Relationships/>"),
        ]);
        let other_content = OoxmlSegmenter
            .extract(&edited, SECRET)
            .unwrap()
            .original_root_hex;
        assert_ne!(base, other_secret);
        assert_ne!(base, other_content);
    }

    #[test]
    fn redaction_blanks_target_part_and_revealed_leaves_recompute() {
        let docx = sample_docx();
        let m = OoxmlSegmenter.extract(&docx, SECRET).unwrap();
        let content_hash = blake3::hash(&docx);
        // Redact word/document.xml (sorted index 2).
        let doc_seg = m
            .segments
            .iter()
            .find(|s| s.label.as_deref() == Some("word/document.xml"))
            .unwrap();
        let orig_payload_len = doc_seg.byte_length as usize;
        let redacted_artifact = OoxmlSegmenter
            .apply_redaction(&docx, &m, &[doc_seg.segment_id])
            .unwrap();

        // SECURITY: the redacted part's plaintext must be ABSENT from the output
        // bytes (the canonical re-emit must not carry a stray copy).
        let secret = b"hello secret world";
        assert!(
            !redacted_artifact.windows(secret.len()).any(|w| w == secret),
            "redacted part plaintext must not survive in the artifact"
        );

        // The redacted artifact is a valid canonical ZIP we can re-read.
        let parts = read_parts(&redacted_artifact).unwrap();
        assert_eq!(parts.len(), 3, "all entries (names) survive");
        for seg in &m.segments {
            let (name, payload) = &parts[seg.segment_id as usize];
            assert_eq!(Some(name.as_str()), seg.label.as_deref());
            if seg.segment_id == doc_seg.segment_id {
                // Width-preserving: payload keeps its original byte-length and is
                // entirely space-filled (ADR-0034).
                assert_eq!(
                    payload.len(),
                    orig_payload_len,
                    "redacted part keeps its byte-width"
                );
                assert!(
                    payload.iter().all(|&b| b == REDACTION_FILL_BYTE),
                    "redacted part payload is space-filled"
                );
                continue;
            }
            // Revealed parts recompute their committed leaf from the artifact.
            let id_be = seg.segment_id.to_be_bytes();
            let content = content_scalar(&id_be, &part_content_bytes(name, payload));
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(leaf, seg.leaf_hex, "revealed part leaf recomputes");
        }
    }

    #[test]
    fn spans_locate_revealed_part_leaves() {
        // ADR-0030 §2a/§3 `ooxml-part`: each span is the local-file DATA offset of
        // the produced canonical Stored ZIP, so `artifact[offset..offset+length]`
        // IS the raw uncompressed payload and the leaf recomputes over
        // `lp(label) || payload` with no ZIP parsing.
        let docx = sample_docx();
        let m = OoxmlSegmenter.extract(&docx, SECRET).unwrap();
        let content_hash = blake3::hash(&docx);
        let doc_seg_id = m
            .segments
            .iter()
            .find(|s| s.label.as_deref() == Some("word/document.xml"))
            .unwrap()
            .segment_id;
        let (artifact, spans) = OoxmlSegmenter
            .apply_redaction_with_spans(&docx, &m, &[doc_seg_id])
            .unwrap();
        assert_eq!(spans.len(), m.segments.len());
        for (seg, span) in m.segments.iter().zip(&spans) {
            assert_eq!(span.segment_id, seg.segment_id);
            let name = seg.label.as_deref().unwrap();
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
            let payload = &artifact[s..e];
            if seg.segment_id == doc_seg_id {
                // Width-preserving: the span keeps the original payload byte-length
                // and is entirely space-filled (ADR-0034).
                assert_eq!(
                    payload.len() as u64,
                    seg.byte_length,
                    "redacted part span keeps its byte-width"
                );
                assert!(
                    payload.iter().all(|&b| b == REDACTION_FILL_BYTE),
                    "redacted part payload space-filled at its span"
                );
                continue;
            }
            let id_be = seg.segment_id.to_be_bytes();
            // ooxml-part content_bytes = lp(label) || payload.
            let content = content_scalar(&id_be, &part_content_bytes(name, payload));
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, seg.leaf_hex,
                "revealed part leaf recomputes from data span"
            );
        }
    }

    #[test]
    fn unknown_segment_id_is_rejected() {
        let docx = sample_docx();
        let m = OoxmlSegmenter.extract(&docx, SECRET).unwrap();
        assert!(matches!(
            OoxmlSegmenter.apply_redaction(&docx, &m, &[99]),
            Err(SegmentError::UnknownSegment(99))
        ));
    }

    #[test]
    fn non_zip_is_malformed() {
        assert!(matches!(
            OoxmlSegmenter.extract(b"not a zip at all", SECRET),
            Err(SegmentError::Malformed {
                format: "ooxml-part",
                ..
            })
        ));
    }

    // NOTE: the `read_parts` duplicate-part-name guard is defense-in-depth
    // against a hand-crafted malicious package; it is not unit-tested here because
    // the `zip` writer refuses to emit a duplicate-named archive, so the input
    // can't be constructed through the normal API.

    #[test]
    fn empty_package_is_unsupported() {
        let empty = build_pkg(&[]);
        assert!(matches!(
            OoxmlSegmenter.extract(&empty, SECRET),
            Err(SegmentError::Unsupported("ooxml-part"))
        ));
    }

    #[test]
    fn deflate_bomb_is_rejected() {
        // A small compressed entry inflating past MAX_INFLATE must error, not OOM.
        let bomb_payload = vec![0u8; MAX_INFLATE + 1];
        let bomb = build_pkg(&[
            ("[Content_Types].xml", b"<Types/>"),
            ("word/document.xml", &bomb_payload),
        ]);
        assert!(
            bomb.len() < 1024 * 1024,
            "the compressed bomb is tiny ({} bytes)",
            bomb.len()
        );
        assert!(matches!(
            OoxmlSegmenter.extract(&bomb, SECRET),
            Err(SegmentError::Malformed {
                format: "ooxml-part",
                ..
            })
        ));
    }
}
