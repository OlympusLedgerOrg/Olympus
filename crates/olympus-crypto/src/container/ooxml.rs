// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! The canonical **Stored** (uncompressed) ZIP package codec for OOXML
//! redaction artifacts (ADR-0026 / ADR-0034).
//!
//! See the [module docs](super) for why this is shared. Redacted `.docx` /
//! `.xlsx` / `.pptx` artifacts are repackaged with no compression so the signed
//! `ooxml-part` spans address the raw payload bytes directly: a verifier slices
//! `artifact[offset..offset + length]` and reconstructs the leaf over
//! `lp(label) || payload` with no ZIP parsing at all.
//!
//! Both halves live here — the writer and the span reader — because the spans a
//! producer *signs* are derived by reading back what the writer produced. Split
//! across crates, those two could drift into disagreement, which is the failure
//! this module exists to prevent.

use std::collections::HashMap;
use std::io::{Cursor, Write};

/// A canonical-ZIP operation failed.
#[derive(Debug, thiserror::Error)]
#[error("canonical zip: {0}")]
pub struct ContainerError(String);

impl ContainerError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Re-emit `parts` as a canonical **Stored** ZIP: order as supplied, no
/// compression, and metadata pinned to a fixed 1980-01-01 epoch. Deterministic —
/// the same parts always produce the same bytes, in every feature configuration.
pub fn write_canonical_stored_zip(parts: &[(String, Vec<u8>)]) -> Result<Vec<u8>, ContainerError> {
    use zip::write::SimpleFileOptions;

    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            // `DateTime::default()` is a fixed 1980-01-01 (`mtime = 0`,
            // `mdate = 33`) — NOT `default_for_write()`, whose behaviour depends
            // on whether the `zip` crate's `time` feature happens to be enabled
            // somewhere in the dependency graph: with it, it returns the current
            // wall-clock time. See `canonical_profile_is_pinned_and_feature_independent`.
            .last_modified_time(zip::DateTime::default())
            .unix_permissions(0o644);
        for (name, payload) in parts {
            zw.start_file(name.as_str(), opts)
                .map_err(|e| ContainerError::new(format!("start entry {name}: {e}")))?;
            zw.write_all(payload)
                .map_err(|e| ContainerError::new(format!("write entry {name}: {e}")))?;
        }
        zw.finish()
            .map_err(|e| ContainerError::new(format!("finish zip: {e}")))?;
    }
    Ok(cursor.into_inner())
}

/// Read each entry's raw payload span out of a produced package, keyed by part
/// name: `name -> (data_offset, data_length)`.
///
/// `data_offset` addresses the local-file **data**, past that entry's local
/// header, file name, and extra field — the offset an `ooxml-part` segment
/// commits to. Deriving spans this way means what a producer signs is a property
/// of the artifact's actual bytes rather than of the writer's bookkeeping.
pub fn stored_data_spans(artifact: &[u8]) -> Result<HashMap<String, (u64, u64)>, ContainerError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(artifact))
        .map_err(|e| ContainerError::new(format!("re-read canonical zip: {e}")))?;
    let mut out = HashMap::with_capacity(archive.len());
    for i in 0..archive.len() {
        let f = archive
            .by_index(i)
            .map_err(|e| ContainerError::new(format!("re-read entry {i}: {e}")))?;
        let name = f.name().to_string();
        let size = f.size();
        let hs = f.header_start() as usize;
        drop(f);
        // Need bytes [hs+26, hs+30) for the two LE u16 length fields.
        let after_fixed = hs
            .checked_add(30)
            .filter(|&e| e <= artifact.len())
            .ok_or_else(|| ContainerError::new("local file header past end of produced zip"))?;
        let name_len = u16::from_le_bytes([artifact[hs + 26], artifact[hs + 27]]) as u64;
        let extra_len = u16::from_le_bytes([artifact[hs + 28], artifact[hs + 29]]) as u64;
        let data_offset = after_fixed as u64 + name_len + extra_len;
        out.insert(name, (data_offset, size));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> Vec<(String, Vec<u8>)> {
        vec![
            ("[Content_Types].xml".to_string(), b"<Types/>".to_vec()),
            ("word/document.xml".to_string(), b"<w:document/>".to_vec()),
            ("word/media/image1.png".to_string(), vec![0x89, 0x50, 0x4e]),
        ]
    }

    /// Minimal Stored-ZIP local-header walk, deliberately independent of the
    /// `zip` crate so it can disagree with [`stored_data_spans`].
    fn independent_spans(zip_bytes: &[u8]) -> Vec<(String, u64, u64)> {
        let mut out = Vec::new();
        let mut i = 0usize;
        let u16_at = |off: usize| u16::from_le_bytes([zip_bytes[off], zip_bytes[off + 1]]) as usize;
        let u32_at = |off: usize| {
            u32::from_le_bytes([
                zip_bytes[off],
                zip_bytes[off + 1],
                zip_bytes[off + 2],
                zip_bytes[off + 3],
            ]) as usize
        };
        while i + 30 <= zip_bytes.len() && &zip_bytes[i..i + 4] == b"PK\x03\x04" {
            let compressed = u32_at(i + 18);
            let name_len = u16_at(i + 26);
            let extra_len = u16_at(i + 28);
            let name = String::from_utf8_lossy(&zip_bytes[i + 30..i + 30 + name_len]).into_owned();
            let data_offset = i + 30 + name_len + extra_len;
            out.push((name, data_offset as u64, compressed as u64));
            i = data_offset + compressed;
        }
        out
    }

    /// The whole point of the Stored repackage: a signed span must slice the raw
    /// payload straight out of the artifact, with no ZIP parsing and no
    /// decompression.
    #[test]
    fn spans_slice_raw_payloads_out_of_the_package() {
        let parts = parts();
        let artifact = write_canonical_stored_zip(&parts).expect("write");
        let spans = stored_data_spans(&artifact).expect("spans");

        assert_eq!(spans.len(), parts.len());
        for (name, payload) in &parts {
            let &(offset, length) = spans.get(name).expect("part present");
            let slice = &artifact[offset as usize..(offset + length) as usize];
            assert_eq!(slice, payload.as_slice(), "payload for {name}");
        }
    }

    /// [`stored_data_spans`] must agree with an independent header walk — if the
    /// `zip` crate's `header_start` ever shifted meaning, this catches it rather
    /// than silently re-pointing every signed span.
    #[test]
    fn spans_agree_with_an_independent_header_walk() {
        let artifact = write_canonical_stored_zip(&parts()).expect("write");
        let via_crate = stored_data_spans(&artifact).expect("spans");

        let independent = independent_spans(&artifact);
        assert_eq!(independent.len(), via_crate.len());
        for (name, offset, length) in independent {
            assert_eq!(
                via_crate.get(&name).copied(),
                Some((offset, length)),
                "disagreement on {name}"
            );
        }
    }

    /// The canonical local-header profile both offline verifiers enforce:
    /// `version_needed ∈ {10, 20}`, no flags beyond UTF-8, Stored, `mtime == 0`,
    /// `mdate ∈ {0, 33}`, `comp == uncomp`, no extra field.
    ///
    /// The timestamp fields are the load-bearing part. `zip`'s
    /// `DateTime::default_for_write()` returns the **current wall-clock time**
    /// when the crate's `time` feature is active anywhere in the graph, and
    /// 1980-01-01 when it is not — so a writer using it emits a different
    /// artifact depending on an unrelated feature flag, is not reproducible, and
    /// stamps the redaction time into the artifact. Both offline verifiers reject
    /// `mtime != 0` as `non-canonical ooxml zip entry`, so in a graph that
    /// enables `time` every genuine `ooxml-part` bundle becomes unverifiable
    /// offline. That is not hypothetical: it was the shipping behaviour until
    /// this writer pinned `DateTime::default()`.
    ///
    /// **This test alone would not have caught that**, and it is worth being
    /// precise about why: this crate's own build resolves `zip` *without* `time`,
    /// so `default_for_write()` returns 1980 here and the assertions below pass
    /// either way. What catches the feature-dependent regression is
    /// `ooxml_part_bundle_from_real_producer_is_accepted_by_offline_verifier` in
    /// `src-tauri`, which builds under the union of the workspace's features —
    /// the configuration that actually ships. This test pins the *shape* of the
    /// profile; that gate pins it in the graph where it can break.
    #[test]
    fn canonical_profile_is_pinned_and_feature_independent() {
        let artifact = write_canonical_stored_zip(&parts()).expect("write");
        let mut i = 0usize;
        let mut entries = 0usize;
        while i + 30 <= artifact.len() && &artifact[i..i + 4] == b"PK\x03\x04" {
            let u16_at = |off: usize| u16::from_le_bytes([artifact[off], artifact[off + 1]]);
            let u32_at = |off: usize| {
                u32::from_le_bytes([
                    artifact[off],
                    artifact[off + 1],
                    artifact[off + 2],
                    artifact[off + 3],
                ])
            };
            let version = u16_at(i + 4);
            let flags = u16_at(i + 6);
            let method = u16_at(i + 8);
            let mtime = u16_at(i + 10);
            let mdate = u16_at(i + 12);
            let comp = u32_at(i + 18);
            let uncomp = u32_at(i + 22);
            let name_len = u16_at(i + 26) as usize;
            let extra_len = u16_at(i + 28) as usize;

            assert!(matches!(version, 10 | 20), "version_needed {version}");
            assert_eq!(flags & !0x0800, 0, "unexpected general-purpose flags");
            assert_eq!(method, 0, "entry must be Stored");
            assert_eq!(mtime, 0, "mtime must be the pinned 1980-01-01 epoch");
            assert!(
                matches!(mdate, 0 | 33),
                "mdate {mdate} outside the canonical set"
            );
            assert_eq!(comp, uncomp, "Stored entries must not be compressed");
            assert_eq!(extra_len, 0, "no extra field in the canonical profile");

            i = i + 30 + name_len + extra_len + comp as usize;
            entries += 1;
        }
        assert_eq!(entries, parts().len(), "walked every local header");
    }

    /// Determinism is what makes re-ingest reproduce the same commitment.
    #[test]
    fn output_is_byte_deterministic() {
        let a = write_canonical_stored_zip(&parts()).expect("write");
        let b = write_canonical_stored_zip(&parts()).expect("write");
        assert_eq!(a, b);
    }

    /// Emptied parts (how `ooxml-part` redaction destroys a payload) keep their
    /// entry and get a zero-length span rather than vanishing from the package.
    #[test]
    fn emptied_parts_keep_their_entry_with_a_zero_length_span() {
        let mut parts = parts();
        parts[1].1.clear();
        let artifact = write_canonical_stored_zip(&parts).expect("write");
        let spans = stored_data_spans(&artifact).expect("spans");

        assert_eq!(spans.len(), 3);
        assert_eq!(spans.get("word/document.xml").map(|s| s.1), Some(0));
        assert_eq!(independent_spans(&artifact).len(), 3);
    }

    /// Stored means stored: a payload must appear verbatim in the package, or the
    /// no-parsing verifier contract silently breaks.
    #[test]
    fn payloads_are_not_compressed() {
        let payload = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_vec();
        let artifact =
            write_canonical_stored_zip(&[("a.bin".to_string(), payload.clone())]).expect("write");
        assert!(
            artifact
                .windows(payload.len())
                .any(|w| w == payload.as_slice()),
            "payload should appear verbatim in a Stored package"
        );
    }
}
