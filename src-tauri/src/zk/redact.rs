//! Chunk-aligned in-place byte redactor for the chunk-based `redaction_validity`
//! circuit — the canonical redaction primitive (ADR-0023/0024 tile redaction is
//! rejected and parked, see #1221).
//!
//! ## Why this exists
//!
//! `redaction_validity` binds a redacted artifact to a committed original by
//! re-chunking the artifact and recomputing `redactedCommitment`. That binding
//! holds **only** when every *revealed* chunk is byte-identical to the original
//! at the same offset — which requires the redacted file to be the **same length**
//! with all surviving bytes untouched. An externally-edited document (a PDF or
//! Word file re-saved by an editor) re-serializes and shares no bytes with the
//! original, so the binding can never match — which is the whole reason redaction
//! "didn't work".
//!
//! This module is the Olympus-owned redaction *operation* that produces a
//! binding-compatible artifact: it overwrites the redacted byte ranges in place
//! with a fill byte (length and all other bytes preserved) and reports the
//! 16-chunk reveal mask. Feeding that artifact + mask into the existing
//! `/redaction/issue` path yields a proof whose binding check passes.
//!
//! ## Scope (text-oriented by design)
//!
//! In-place blanking keeps a file usable only for byte-streams where zeroing a
//! range doesn't break the container — text, CSV, JSON, logs, source. It will
//! corrupt structured binary formats (PDF/Office/images); those need a
//! different primitive (the rejected rasterized path) and are out of scope here.
//!
//! ## Granularity
//!
//! The circuit is fixed at `MAX_LEAVES = 16` chunks, so a redaction is hidden at
//! whole-chunk granularity: any chunk containing a redacted byte is masked out
//! entirely (≈ 1/16 of the file per touched chunk). This over-redacts around the
//! target but is the cost of reusing the shipped circuit; finer granularity is a
//! ceremony-class circuit change.

use crate::zk::witness::redaction::MAX_LEAVES;
use thiserror::Error;

/// Default fill byte for redacted regions. Cosmetic only: redacted chunks are
/// masked to `0` in the proof, so a redacted region's bytes never enter
/// `redactedCommitment` and never affect verification. Callers may pass a
/// printable fill (e.g. `b'X'`) for human-readable text artifacts.
pub const DEFAULT_FILL: u8 = 0x00;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RedactError {
    #[error("original is empty")]
    EmptyInput,
    #[error("no redaction ranges given")]
    NoRanges,
    #[error("range {0:?} is out of bounds for length {1}")]
    OutOfBounds((usize, usize), usize),
    #[error("range {0:?} is inverted (start >= end)")]
    InvertedRange((usize, usize)),
    #[error("redaction covers every chunk — nothing would be revealed")]
    AllRedacted,
}

/// Result of a chunk-aligned redaction.
#[derive(Debug, Clone)]
pub struct Redaction {
    /// Same-length artifact: `original` with the redacted ranges overwritten by
    /// the fill byte.
    pub redacted: Vec<u8>,
    /// 16-entry reveal mask: `1` = chunk unchanged (revealed), `0` = chunk
    /// overlapped a redacted range (hidden). Matches the `reveal_mask` the
    /// `/redaction/issue` path expects.
    pub reveal_mask: Vec<u8>,
}

/// Half-open byte interval `[start, end)`.
pub type ByteRange = (usize, usize);

/// Overwrite `ranges` in `original` with `fill` (preserving length) and compute
/// the 16-chunk reveal mask.
///
/// A chunk is marked redacted (`0`) iff it overlaps any redacted byte; otherwise
/// revealed (`1`). Because revealed chunks are byte-identical to the original and
/// the total length is unchanged, the redacted artifact re-chunks to the same
/// leaves at revealed positions — so `redaction_validity`'s binding check holds.
///
/// The chunk geometry mirrors [`crate::zk::chunk`] exactly
/// (`chunk_size = ceil(n / 16)`), so the mask computed here lines up with the
/// leaves committed at ingest.
pub fn redact_chunk_aligned(
    original: &[u8],
    ranges: &[ByteRange],
    fill: u8,
) -> Result<Redaction, RedactError> {
    let n = original.len();
    if n == 0 {
        return Err(RedactError::EmptyInput);
    }
    if ranges.is_empty() {
        return Err(RedactError::NoRanges);
    }
    for &(s, e) in ranges {
        if s >= e {
            return Err(RedactError::InvertedRange((s, e)));
        }
        if e > n {
            return Err(RedactError::OutOfBounds((s, e), n));
        }
    }

    let mut redacted = original.to_vec();
    for &(s, e) in ranges {
        redacted[s..e].fill(fill);
    }

    // Mirror crate::zk::chunk::chunk_into_16: chunk_size = ceil(n/16), 16 chunks,
    // the tail beyond `n` is zero-padding (and is never targeted by a range,
    // since every range end ≤ n).
    let chunk_size = n.div_ceil(MAX_LEAVES).max(1);
    let mut reveal_mask = vec![1u8; MAX_LEAVES];
    for (i, m) in reveal_mask.iter_mut().enumerate() {
        let cstart = (i * chunk_size).min(n);
        let cend = (cstart + chunk_size).min(n);
        // Non-empty chunk [cstart, cend) overlaps range [s, e) iff s < cend && cstart < e.
        let touched = cstart < cend && ranges.iter().any(|&(s, e)| s < cend && cstart < e);
        if touched {
            *m = 0;
        }
    }

    if reveal_mask.iter().all(|&m| m == 0) {
        return Err(RedactError::AllRedacted);
    }

    Ok(Redaction {
        redacted,
        reveal_mask,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::chunk::chunk_tree_from_bytes;

    /// 320-byte buffer ⇒ chunk_size = ceil(320/16) = 20; chunk i covers
    /// bytes [20*i, 20*i+20).
    fn sample() -> Vec<u8> {
        (0..320u32).map(|i| (i % 251) as u8 + 1).collect() // non-zero, varied
    }

    #[test]
    fn preserves_length() {
        let orig = sample();
        let r = redact_chunk_aligned(&orig, &[(40, 55)], DEFAULT_FILL).unwrap();
        assert_eq!(r.redacted.len(), orig.len());
    }

    #[test]
    fn blanks_only_the_range() {
        let orig = sample();
        let r = redact_chunk_aligned(&orig, &[(40, 55)], 0x00).unwrap();
        assert!(r.redacted[40..55].iter().all(|&b| b == 0));
        assert_eq!(&r.redacted[..40], &orig[..40]);
        assert_eq!(&r.redacted[55..], &orig[55..]);
    }

    #[test]
    fn mask_marks_only_overlapping_chunks() {
        // chunk_size = 20. Range [40,55) overlaps chunk 2 ([40,60)) only.
        let orig = sample();
        let r = redact_chunk_aligned(&orig, &[(40, 55)], DEFAULT_FILL).unwrap();
        let mut expected = vec![1u8; MAX_LEAVES];
        expected[2] = 0;
        assert_eq!(r.reveal_mask, expected);
    }

    #[test]
    fn range_spanning_chunk_boundary_marks_both() {
        // [55,65) straddles chunk 2 ([40,60)) and chunk 3 ([60,80)).
        let orig = sample();
        let r = redact_chunk_aligned(&orig, &[(55, 65)], DEFAULT_FILL).unwrap();
        assert_eq!(r.reveal_mask[2], 0);
        assert_eq!(r.reveal_mask[3], 0);
        assert_eq!(r.reveal_mask.iter().filter(|&&m| m == 0).count(), 2);
    }

    #[test]
    fn multiple_ranges() {
        let orig = sample();
        let r = redact_chunk_aligned(&orig, &[(0, 5), (300, 320)], DEFAULT_FILL).unwrap();
        assert_eq!(r.reveal_mask[0], 0); // [0,20)
        assert_eq!(r.reveal_mask[15], 0); // [300,320)
        assert_eq!(r.reveal_mask.iter().filter(|&&m| m == 0).count(), 2);
    }

    /// The load-bearing invariant: every REVEALED chunk hashes identically
    /// between the original and the redacted artifact, and every REDACTED chunk
    /// differs. This is exactly what `redaction_validity`'s binding check relies
    /// on, so if this holds the proof binds.
    #[test]
    fn revealed_chunks_hash_identically_redacted_chunks_differ() {
        let orig = sample();
        let r = redact_chunk_aligned(&orig, &[(40, 55), (200, 205)], 0x00).unwrap();

        let orig_tree = chunk_tree_from_bytes(&orig).unwrap();
        let red_tree = chunk_tree_from_bytes(&r.redacted).unwrap();

        for i in 0..MAX_LEAVES {
            if r.reveal_mask[i] == 1 {
                assert_eq!(
                    orig_tree.chunk_hashes_hex[i], red_tree.chunk_hashes_hex[i],
                    "revealed chunk {i} must be byte-identical (so it binds)"
                );
            } else {
                assert_ne!(
                    orig_tree.chunk_hashes_hex[i], red_tree.chunk_hashes_hex[i],
                    "redacted chunk {i} must differ (it was blanked)"
                );
            }
        }
    }

    #[test]
    fn rejects_empty_input() {
        assert_eq!(
            redact_chunk_aligned(b"", &[(0, 1)], DEFAULT_FILL),
            Err(RedactError::EmptyInput)
        );
    }

    #[test]
    fn rejects_no_ranges() {
        assert_eq!(
            redact_chunk_aligned(&sample(), &[], DEFAULT_FILL),
            Err(RedactError::NoRanges)
        );
    }

    #[test]
    fn rejects_inverted_range() {
        assert_eq!(
            redact_chunk_aligned(&sample(), &[(50, 50)], DEFAULT_FILL),
            Err(RedactError::InvertedRange((50, 50)))
        );
    }

    #[test]
    fn rejects_out_of_bounds() {
        let orig = sample();
        assert_eq!(
            redact_chunk_aligned(&orig, &[(300, 321)], DEFAULT_FILL),
            Err(RedactError::OutOfBounds((300, 321), 320))
        );
    }

    #[test]
    fn rejects_all_redacted() {
        let orig = sample();
        assert_eq!(
            redact_chunk_aligned(&orig, &[(0, 320)], DEFAULT_FILL),
            Err(RedactError::AllRedacted)
        );
    }

    #[test]
    fn short_input_one_byte_chunks() {
        // n = 5 < 16 ⇒ chunk_size = 1; 16 chunks, only first 5 hold bytes.
        let orig = vec![9u8; 5];
        let r = redact_chunk_aligned(&orig, &[(2, 3)], DEFAULT_FILL).unwrap();
        assert_eq!(r.redacted.len(), 5);
        assert_eq!(r.reveal_mask[2], 0);
        // exactly one chunk touched; the empty tail chunks stay revealed.
        assert_eq!(r.reveal_mask.iter().filter(|&&m| m == 0).count(), 1);
    }
}
