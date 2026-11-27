// SPDX-License-Identifier: Apache-2.0

//! Fingerprint profiles and per-item fingerprint sets (similarity companion,
//! `docs/rfcs/dataset-similarity.md`, "Fingerprint profiles"; RFC §2).
//!
//! Only `text/minhash-120` v1 is implemented. `image/pdq-256` stays gated, and
//! a header naming any other profile is rejected with
//! [`ContentError::UnknownFpProfile`] instead of being matched under a guessed
//! rule.
//!
//! What a fingerprint match means is class B (candidate retrieval): the
//! committer computed the fingerprint, and its relevance to human-recognizable
//! copying depends on measured recall and precision. Nothing here turns a
//! fingerprint into a class A statement.

use std::sync::OnceLock;

use icu_casemap::CaseMapper;
use unicode_normalization::UnicodeNormalization;
use unicode_properties::{GeneralCategoryGroup, UnicodeGeneralCategory};

use super::canon::{CanonProfile, TEXT_UNICODE_VERSION, UNICODE_NORMALIZATION_VERSION};
use super::commit::{
    empty_fp_set_root, fold_promoted_with, path_from_levels, promoted_levels,
    promoted_sibling_count,
};
use super::domains::{h, Domain, MINHASH_COEFFICIENTS_CONTEXT, MINHASH_SHINGLE_CONTEXT};
use super::error::{ContentError, Result};
use super::version::FpProfileEntry;

// `text/minhash-120` v1 classifies characters at Unicode 17.0.0 (RFC §0a rule
// 2). `unicode-properties` states its version, so check it at compile time like
// `text/utf8-nfc` does for `unicode-normalization`. ICU's case-folding data
// does not state a version; `icu_data_is_the_pinned_unicode_version` pins it
// by comparing ICU's character table with this one over every code point.
const _: () = assert!(
    unicode_properties::UNICODE_VERSION.0 == TEXT_UNICODE_VERSION.0 as u64
        && unicode_properties::UNICODE_VERSION.1 == TEXT_UNICODE_VERSION.1 as u64
        && unicode_properties::UNICODE_VERSION.2 == TEXT_UNICODE_VERSION.2 as u64,
    "unicode-properties implements a different Unicode version than text/minhash-120 v1 pins"
);

/// Exact `icu_casemap` version named in `implementation_id`; kept in step with
/// `Cargo.lock` by a test.
pub const ICU_CASEMAP_VERSION: &str = "2.2.0";

/// Exact `unicode-properties` version named in `implementation_id`.
pub const UNICODE_PROPERTIES_VERSION: &str = "0.1.4";

/// MinHash slots per fingerprint.
pub const MINHASH_SLOTS: usize = 120;
/// Bytes per `text/minhash-120` fingerprint (120 × `u32_be`).
pub const MINHASH_WIDTH: usize = MINHASH_SLOTS * 4;
/// LSH bands `b` for `text/minhash-120` v1.
pub const MINHASH_BANDS: u16 = 20;
/// Slots per band `r` for `text/minhash-120` v1.
pub const MINHASH_ROWS: u16 = 6;
/// Default threshold: `m ≥ 84` matching slots (Jaccard ≈ 0.7).
pub const MINHASH_DEFAULT_THRESHOLD: u32 = 84;
/// Tokens per segment window.
pub const SEGMENT_TOKENS: usize = 256;
/// Tokens between segment starts.
pub const SEGMENT_STRIDE: usize = 128;
/// Tokens per shingle; also the minimum item length that gets a fingerprint.
pub const SHINGLE_TOKENS: usize = 5;

const MERSENNE_61: u64 = (1 << 61) - 1;

/// An implemented fingerprint profile with its signed threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpProfile {
    /// `text/minhash-120` v1, `b = 20`, `r = 6`; `threshold` is the minimum
    /// number of matching slots, `1..=120`.
    TextMinHash120 {
        /// Matching-slot threshold.
        threshold: u32,
    },
}

impl FpProfile {
    /// `text/minhash-120` v1 at the default threshold.
    pub const fn text_minhash_120() -> Self {
        Self::TextMinHash120 {
            threshold: MINHASH_DEFAULT_THRESHOLD,
        }
    }

    /// `text/minhash-120` v1 at `threshold` matching slots.
    pub fn text_minhash_120_with_threshold(threshold: u32) -> Result<Self> {
        if threshold == 0 || threshold > MINHASH_SLOTS as u32 {
            return Err(ContentError::InvalidFpParams(
                "threshold must be 1..=120 slots",
            ));
        }
        Ok(Self::TextMinHash120 { threshold })
    }

    /// `fp_profile_id`.
    pub const fn id(self) -> &'static str {
        match self {
            Self::TextMinHash120 { .. } => "text/minhash-120",
        }
    }

    /// `fp_profile_version`.
    pub const fn version(self) -> u32 {
        1
    }

    /// Fingerprint width in bytes.
    pub const fn width(self) -> usize {
        match self {
            Self::TextMinHash120 { .. } => MINHASH_WIDTH,
        }
    }

    /// LSH bands `b`.
    pub const fn bands(self) -> u16 {
        match self {
            Self::TextMinHash120 { .. } => MINHASH_BANDS,
        }
    }

    /// Units per band `r`.
    pub const fn rows(self) -> u16 {
        match self {
            Self::TextMinHash120 { .. } => MINHASH_ROWS,
        }
    }

    /// The signed threshold, in the profile's unit.
    pub const fn threshold(self) -> u32 {
        match self {
            Self::TextMinHash120 { threshold } => threshold,
        }
    }

    /// `implementation_id` (§0a): sorted `name=version` pairs for every
    /// component whose behaviour reaches the fingerprint.
    pub fn implementation_id(self) -> String {
        let (u0, u1, u2) = TEXT_UNICODE_VERSION;
        format!(
            "icu_casemap={ICU_CASEMAP_VERSION};olympus-manifest={};unicode={u0}.{u1}.{u2};\
             unicode-normalization={UNICODE_NORMALIZATION_VERSION};\
             unicode-properties={UNICODE_PROPERTIES_VERSION}",
            env!("CARGO_PKG_VERSION")
        )
    }

    /// This profile's fingerprint-table row.
    pub fn entry(self) -> FpProfileEntry {
        FpProfileEntry {
            id: self.id().into(),
            version: self.version(),
            implementation_id: self.implementation_id(),
            bands: self.bands(),
            rows: self.rows(),
            threshold: self.threshold(),
        }
    }

    /// Resolve an authenticated table row to the profile it names.
    ///
    /// The band and row counts are part of the v1 definition (they fix which
    /// slots form a band key), so a row carrying any others is rejected, not
    /// reinterpreted. `implementation_id` is not compared: any conforming
    /// implementation may have computed the fingerprints (§0a rule 1).
    pub fn from_entry(e: &FpProfileEntry) -> Result<Self> {
        match (e.id.as_str(), e.version) {
            ("text/minhash-120", 1) => {
                if e.bands != MINHASH_BANDS || e.rows != MINHASH_ROWS {
                    return Err(ContentError::InvalidFpParams(
                        "text/minhash-120 v1 requires b = 20, r = 6",
                    ));
                }
                Self::text_minhash_120_with_threshold(e.threshold)
            }
            (id, v) => Err(ContentError::UnknownFpProfile(format!("{id}@{v}"))),
        }
    }

    /// Whether the profile fingerprints items committed under `canon`. A text
    /// profile applies to text items only; an item outside every profile's
    /// domain is committed exactly and counted as unfingerprinted.
    pub fn applies_to(self, canon: CanonProfile) -> bool {
        self.applies_to_profile_id(canon.id(), canon.version())
    }

    /// [`FpProfile::applies_to`] for a canonicalization-table row, which is
    /// all a verifier holds. The builder and the verifier share this rule.
    pub fn applies_to_profile_id(self, profile_id: &str, profile_version: u32) -> bool {
        match self {
            Self::TextMinHash120 { .. } => (profile_id, profile_version) == ("text/utf8-nfc", 1),
        }
    }

    /// Segment fingerprints of a canonical item, in segment order. An item
    /// with fewer than five tokens yields none.
    pub fn fingerprints(self, canonical: &[u8]) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::TextMinHash120 { .. } => {
                let text = std::str::from_utf8(canonical).map_err(|_| ContentError::InvalidUtf8)?;
                let normalized = normalize_text(text);
                let tokens: Vec<&str> = tokenize(&normalized);
                Ok(minhash_segments(&tokens)
                    .into_iter()
                    .map(|f| f.to_vec())
                    .collect())
            }
        }
    }

    /// Query side: canonicalize the claimant's own copy under the text
    /// profile, then fingerprint it exactly as the committer did.
    pub fn fingerprints_of_work(self, raw: &[u8]) -> Result<Vec<Vec<u8>>> {
        match self {
            Self::TextMinHash120 { .. } => {
                self.fingerprints(&CanonProfile::TextUtf8Nfc.canonicalize(raw)?)
            }
        }
    }

    /// Distance in the profile's unit: matching slots for MinHash.
    pub fn similarity(self, a: &[u8], b: &[u8]) -> Result<u32> {
        self.check_width(a)?;
        self.check_width(b)?;
        match self {
            Self::TextMinHash120 { .. } => Ok(a
                .chunks_exact(4)
                .zip(b.chunks_exact(4))
                .filter(|(x, y)| x == y)
                .count() as u32),
        }
    }

    /// `band_value(F, β)`: slots `[β·r, (β+1)·r)` of `F`, each `u32_be`.
    pub fn band_value(self, fp: &[u8], band: u16) -> Result<Vec<u8>> {
        self.check_width(fp)?;
        if band >= self.bands() {
            return Err(ContentError::InvalidFpParams("band index out of range"));
        }
        let r = usize::from(self.rows()) * 4;
        let start = usize::from(band) * r;
        Ok(fp[start..start + r].to_vec())
    }

    pub(crate) fn check_width(self, fp: &[u8]) -> Result<()> {
        if fp.len() == self.width() {
            Ok(())
        } else {
            Err(ContentError::FingerprintWidth {
                expected: self.width(),
                got: fp.len(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// text/minhash-120 v1
// ---------------------------------------------------------------------------

/// Normalization: Unicode 17.0.0 NFKC, then full case folding, then every
/// maximal run of characters outside categories L* and N* becomes one U+0020,
/// then trim.
///
/// Combining marks (M*) are outside L* and N*, so they separate tokens; so
/// does nothing in unspaced scripts, where a whole run of letters is one
/// token. Both follow from the v1 definition and are recorded as open
/// questions in the similarity companion.
pub fn normalize_text(text: &str) -> String {
    let nfkc: String = text.nfkc().collect();
    let folded = CaseMapper::new().fold_string(&nfkc);
    let mut out = String::with_capacity(folded.len());
    let mut gap = false;
    for c in folded.chars() {
        if is_letter_or_number(c) {
            if gap && !out.is_empty() {
                out.push(' ');
            }
            gap = false;
            out.push(c);
        } else {
            gap = true;
        }
    }
    out
}

fn is_letter_or_number(c: char) -> bool {
    matches!(
        c.general_category_group(),
        GeneralCategoryGroup::Letter | GeneralCategoryGroup::Number
    )
}

/// Tokens of normalized text: split on U+0020. Normalized text has no empty
/// tokens; the empty string has none.
pub fn tokenize(normalized: &str) -> Vec<&str> {
    if normalized.is_empty() {
        Vec::new()
    } else {
        normalized.split(' ').collect()
    }
}

/// Segment windows over `tokens`: segment `k` is tokens
/// `[128·k, min(128·k + 256, n))`, for the smallest number of segments that
/// covers every token. So `n ≤ 256` is one segment, and the last window of a
/// longer item may be shorter than 256 (but never shorter than 129). Fewer
/// than five tokens: no segment.
pub fn segments<'a, 'b>(tokens: &'a [&'b str]) -> Vec<&'a [&'b str]> {
    segment_ranges(tokens.len())
        .into_iter()
        .map(|r| &tokens[r])
        .collect()
}

/// Token ranges of the segments of an `n`-token item (see [`segments`]).
fn segment_ranges(n: usize) -> Vec<std::ops::Range<usize>> {
    if n < SHINGLE_TOKENS {
        return Vec::new();
    }
    let count = if n <= SEGMENT_TOKENS {
        1
    } else {
        1 + (n - SEGMENT_TOKENS).div_ceil(SEGMENT_STRIDE)
    };
    (0..count)
        .map(|k| {
            let start = k * SEGMENT_STRIDE;
            start..n.min(start + SEGMENT_TOKENS)
        })
        .collect()
}

/// `(a_i, b_i)` for `i ∈ [0, 120)`: `u64_be` values read in order from the
/// output stream of `derive_key(MINHASH_COEFFICIENTS_CONTEXT, "")` (whose
/// first 32 bytes are that `derive_key` value), each reduced mod `2^61 − 1`.
/// For each slot, `a_i` is the next nonzero reduced value (zeros are skipped),
/// then `b_i` is the next value, zero allowed.
pub(crate) fn minhash_coefficients() -> &'static [(u64, u64); MINHASH_SLOTS] {
    static COEFFS: OnceLock<[(u64, u64); MINHASH_SLOTS]> = OnceLock::new();
    COEFFS.get_or_init(|| {
        let mut xof = blake3::Hasher::new_derive_key(MINHASH_COEFFICIENTS_CONTEXT).finalize_xof();
        let mut next = || {
            let mut b = [0u8; 8];
            xof.fill(&mut b);
            u64::from_be_bytes(b) % MERSENNE_61
        };
        let mut out = [(0u64, 0u64); MINHASH_SLOTS];
        for slot in &mut out {
            let a = loop {
                let v = next();
                if v != 0 {
                    break v;
                }
            };
            *slot = (a, next());
        }
        out
    })
}

/// `v mod (2^61 − 1)` for `v = a·x + b` with `a`, `x`, `b` already reduced
/// mod `2^61 − 1`, by folding the high bits instead of dividing.
#[inline]
fn mod_m61(v: u128) -> u64 {
    // With P = 2^61 − 1 and v ≤ (P − 1)² + (P − 1) < P·2^61: v >> 61 ≤ P − 1
    // and v & P ≤ P, so one fold gives r ≤ 2P − 1 and one subtraction ends.
    let p = u128::from(MERSENNE_61);
    let r = ((v & p) + (v >> 61)) as u64;
    if r >= MERSENNE_61 {
        r - MERSENNE_61
    } else {
        r
    }
}

/// `x` for every shingle of `tokens`, in order: shingle `i` is tokens
/// `[i, i + 5)` joined with U+0020, and
/// `x = u64_be(derive_key(MINHASH_SHINGLE_CONTEXT, shingle)[0..8]) mod (2^61 − 1)`.
/// Computed once per item; overlapping segments share them.
fn shingle_values(tokens: &[&str]) -> Vec<u64> {
    let base = blake3::Hasher::new_derive_key(MINHASH_SHINGLE_CONTEXT);
    let mut shingle = String::new();
    tokens
        .windows(SHINGLE_TOKENS)
        .map(|window| {
            shingle.clear();
            for (i, t) in window.iter().enumerate() {
                if i > 0 {
                    shingle.push(' ');
                }
                shingle.push_str(t);
            }
            let d = base.clone().update(shingle.as_bytes()).finalize();
            let head: [u8; 8] = d.as_bytes()[..8].try_into().expect("8 bytes");
            u64::from_be_bytes(head) % MERSENNE_61
        })
        .collect()
}

/// The 480-byte MinHash of one segment (at least five tokens). Slot `i` is the
/// minimum over the segment's shingles of `((a_i·x + b_i) mod (2^61 − 1)) mod 2^32`.
pub fn minhash(segment: &[&str]) -> [u8; MINHASH_WIDTH] {
    assert!(
        segment.len() >= SHINGLE_TOKENS,
        "a segment always has at least one shingle"
    );
    minhash_of_values(&shingle_values(segment))
}

/// MinHash over precomputed shingle values (non-empty).
fn minhash_of_values(xs: &[u64]) -> [u8; MINHASH_WIDTH] {
    encode_slots(&slot_minima(xs))
}

/// Per-slot minima of `(a_i·x + b_i) mod (2^61 − 1) mod 2^32` over `xs`
/// (`u64::MAX` in every slot when `xs` is empty).
fn slot_minima(xs: &[u64]) -> [u64; MINHASH_SLOTS] {
    let coeffs = minhash_coefficients();
    let mut slots = [u64::MAX; MINHASH_SLOTS];
    for &x in xs {
        let x = u128::from(x);
        for (slot, &(a, b)) in slots.iter_mut().zip(coeffs) {
            let v = mod_m61(u128::from(a) * x + u128::from(b));
            *slot = (*slot).min(v & 0xFFFF_FFFF);
        }
    }
    slots
}

/// Every segment's MinHash of an item, each shingle evaluated once.
///
/// Shingle `i` covers tokens `[i, i + 5)`, so a segment over tokens `[s, e)`
/// owns shingles `[s, e − 4)`. Neighbouring segments overlap by about half.
/// Cutting the shingle sequence at every segment boundary gives disjoint
/// pieces, and each segment is a run of whole pieces. Minimum is associative
/// and commutative, so the elementwise minimum of a segment's piece minima
/// equals the minimum over its shingles: the output is exactly
/// [`minhash`] of each segment, with each shingle's 120 slot values
/// computed once rather than once per segment that contains it.
fn minhash_segments(tokens: &[&str]) -> Vec<[u8; MINHASH_WIDTH]> {
    let windows: Vec<std::ops::Range<usize>> = segment_ranges(tokens.len())
        .into_iter()
        .map(|r| r.start..r.end - (SHINGLE_TOKENS - 1))
        .collect();
    if windows.is_empty() {
        return Vec::new();
    }
    let xs = shingle_values(tokens);
    let mut cuts: Vec<usize> = windows.iter().flat_map(|w| [w.start, w.end]).collect();
    cuts.sort_unstable();
    cuts.dedup();
    let pieces: Vec<[u64; MINHASH_SLOTS]> = cuts
        .windows(2)
        .map(|c| slot_minima(&xs[c[0]..c[1]]))
        .collect();
    windows
        .iter()
        .map(|w| {
            let first = cuts.binary_search(&w.start).expect("start is a cut");
            let last = cuts.binary_search(&w.end).expect("end is a cut");
            let mut slots = [u64::MAX; MINHASH_SLOTS];
            for piece in &pieces[first..last] {
                for (s, p) in slots.iter_mut().zip(piece) {
                    *s = (*s).min(*p);
                }
            }
            encode_slots(&slots)
        })
        .collect()
}

fn encode_slots(slots: &[u64; MINHASH_SLOTS]) -> [u8; MINHASH_WIDTH] {
    let mut out = [0u8; MINHASH_WIDTH];
    for (chunk, v) in out.chunks_exact_mut(4).zip(slots) {
        chunk.copy_from_slice(&(*v as u32).to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Fingerprint sets (RFC §2)
// ---------------------------------------------------------------------------

/// `fp_leaf = H_fp(u16_be(fp_profile_index) ‖ u32_be(segment_index) ‖ fingerprint)`.
pub fn fp_leaf(fp_profile_index: u16, segment_index: u32, fingerprint: &[u8]) -> [u8; 32] {
    h(
        Domain::Fp,
        &[
            &fp_profile_index.to_be_bytes(),
            &segment_index.to_be_bytes(),
            fingerprint,
        ],
    )
}

/// One committed segment fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FpEntry {
    /// Index into the version's fingerprint-profile table.
    pub fp_profile_index: u16,
    /// Segment index within the item, under that profile.
    pub segment_index: u32,
    /// The fingerprint bytes.
    pub fingerprint: Vec<u8>,
}

/// An item's fingerprint set in `(fp_profile_index, segment_index)` order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FpSet {
    entries: Vec<FpEntry>,
    /// `levels[0]` = leaves; empty for an empty set.
    levels: Vec<Vec<[u8; 32]>>,
}

impl FpSet {
    /// Sort into position order and build the tree. A repeated
    /// `(fp_profile_index, segment_index)` is rejected: one position holds
    /// one fingerprint.
    pub fn new(mut entries: Vec<FpEntry>) -> Result<Self> {
        entries.sort_by_key(|e| (e.fp_profile_index, e.segment_index));
        if entries.windows(2).any(|w| {
            (w[0].fp_profile_index, w[0].segment_index)
                == (w[1].fp_profile_index, w[1].segment_index)
        }) {
            return Err(ContentError::InvalidFpParams(
                "duplicate fingerprint position",
            ));
        }
        if u32::try_from(entries.len()).is_err() {
            return Err(ContentError::FieldTooLong("fingerprint set"));
        }
        let leaves: Vec<[u8; 32]> = entries
            .iter()
            .map(|e| fp_leaf(e.fp_profile_index, e.segment_index, &e.fingerprint))
            .collect();
        let levels = if leaves.is_empty() {
            Vec::new()
        } else {
            promoted_levels(leaves, Domain::FpNode)
        };
        Ok(Self { entries, levels })
    }

    /// Entries in position order.
    pub fn entries(&self) -> &[FpEntry] {
        &self.entries
    }

    /// `fp_set_root`.
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .map_or_else(empty_fp_set_root, |top| top[0])
    }

    /// Position of a segment fingerprint, if committed.
    pub fn position(&self, fp_profile_index: u16, segment_index: u32) -> Option<usize> {
        self.entries
            .binary_search_by_key(&(fp_profile_index, segment_index), |e| {
                (e.fp_profile_index, e.segment_index)
            })
            .ok()
    }

    /// Siblings for position `j`, bottom-up, promoted levels omitted.
    pub fn path(&self, j: usize) -> Vec<[u8; 32]> {
        path_from_levels(&self.levels, j)
    }
}

/// Fold a disclosed fingerprint at `(leaf_index, leaf_count)` to an
/// `fp_set_root`. The shape comes from the two indices, never from the path.
pub fn fp_set_root_from_path(
    fp_profile_index: u16,
    segment_index: u32,
    fingerprint: &[u8],
    leaf_index: u32,
    leaf_count: u32,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32]> {
    if leaf_index >= leaf_count {
        return Err(ContentError::FpPositionOutOfRange {
            j: leaf_index,
            n: leaf_count,
        });
    }
    let expected = promoted_sibling_count(u64::from(leaf_index), u64::from(leaf_count));
    if expected != siblings.len() {
        return Err(ContentError::FpPathLength {
            expected,
            got: siblings.len(),
        });
    }
    Ok(fold_promoted_with(
        fp_leaf(fp_profile_index, segment_index, fingerprint),
        u64::from(leaf_index),
        u64::from(leaf_count),
        siblings,
        Domain::FpNode,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::commit::promoted_path;

    fn words(n: usize, seed: &str) -> String {
        (0..n)
            .map(|i| format!("{seed}{}", i % 997))
            .collect::<Vec<_>>()
            .join(" ")
    }

    #[test]
    fn normalization_applies_nfkc_full_case_folding_and_letter_number_runs() {
        // NFKC: the ligature ﬁ decomposes; full (not simple) folding: ẞ -> ss.
        assert_eq!(normalize_text("ﬁne STRAẞE"), "fine strasse");
        assert_eq!(normalize_text("Straße"), normalize_text("STRASSE"));
        // Runs of punctuation/space/symbols collapse to one space; trimmed.
        assert_eq!(
            normalize_text("  Hello,\t—  world!!  42 "),
            "hello world 42"
        );
        // Numbers are kept, including non-ASCII digits after NFKC.
        assert_eq!(normalize_text("x ① ٣"), "x 1 ٣");
        // A combining mark that survives NFKC is outside L*/N*: it separates.
        assert_eq!(normalize_text("İx"), "i x");
        assert_eq!(normalize_text("—…"), "");
    }

    #[test]
    fn tokens_and_segment_windows_follow_the_rule() {
        assert!(tokenize("").is_empty());
        assert_eq!(tokenize("a b c"), vec!["a", "b", "c"]);
        let toks: Vec<String> = (0..1000).map(|i| i.to_string()).collect();
        let toks: Vec<&str> = toks.iter().map(String::as_str).collect();
        let shape = |n: usize| -> Vec<(usize, usize)> {
            segments(&toks[..n])
                .iter()
                .map(|s| {
                    let start: usize = s[0].parse().unwrap();
                    (start, start + s.len())
                })
                .collect()
        };
        assert_eq!(shape(4), vec![]);
        assert_eq!(shape(5), vec![(0, 5)]);
        assert_eq!(shape(256), vec![(0, 256)]);
        assert_eq!(shape(257), vec![(0, 256), (128, 257)]);
        assert_eq!(shape(384), vec![(0, 256), (128, 384)]);
        assert_eq!(shape(385), vec![(0, 256), (128, 384), (256, 385)]);
        for n in 5..1000 {
            let s = shape(n);
            assert_eq!(s.last().unwrap().1, n, "n={n}: last token uncovered");
            assert!(s.iter().all(|(a, b)| b - a >= SHINGLE_TOKENS.min(n)));
            assert!(s.iter().skip(1).all(|(a, b)| b - a > SEGMENT_STRIDE));
        }
    }

    #[test]
    fn coefficients_are_read_from_the_derive_key_output_stream() {
        // Pins the reading "the BLAKE3 XOF of derive_key(ctx, "")": the stream
        // starts with that derive_key value.
        let mut head = [0u8; 32];
        blake3::Hasher::new_derive_key(MINHASH_COEFFICIENTS_CONTEXT)
            .finalize_xof()
            .fill(&mut head);
        assert_eq!(head, blake3::derive_key(MINHASH_COEFFICIENTS_CONTEXT, b""));
        let first_a = u64::from_be_bytes(head[..8].try_into().unwrap()) % MERSENNE_61;
        let first_b = u64::from_be_bytes(head[8..16].try_into().unwrap()) % MERSENNE_61;
        let c = minhash_coefficients();
        if first_a != 0 {
            assert_eq!(c[0], (first_a, first_b));
        }
        assert!(c
            .iter()
            .all(|&(a, b)| a != 0 && a < MERSENNE_61 && b < MERSENNE_61));
    }

    /// Slot `i` recomputed with no shared code path: fresh `derive_key`
    /// calls, the definition's formula, and its own coefficient reader.
    fn naive_slot(segment: &[&str], i: usize) -> u32 {
        let mut stream = vec![0u8; 8 * 4 * MINHASH_SLOTS];
        blake3::Hasher::new_derive_key(MINHASH_COEFFICIENTS_CONTEXT)
            .finalize_xof()
            .fill(&mut stream);
        let mut vals = stream
            .chunks_exact(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()) % MERSENNE_61);
        let mut ab = Vec::new();
        while ab.len() <= i {
            let a = vals.by_ref().find(|v| *v != 0).unwrap();
            ab.push((a, vals.next().unwrap()));
        }
        let (a, b) = ab[i];
        segment
            .windows(5)
            .map(|w| {
                let d = blake3::derive_key(MINHASH_SHINGLE_CONTEXT, w.join(" ").as_bytes());
                let x = u64::from_be_bytes(d[..8].try_into().unwrap()) % MERSENNE_61;
                (((a as u128 * x as u128 + b as u128) % MERSENNE_61 as u128) % (1u128 << 32)) as u32
            })
            .min()
            .unwrap()
    }

    #[test]
    fn minhash_matches_a_naive_recomputation_of_the_definition() {
        let text = words(40, "w");
        let toks = tokenize(&text);
        let fp = minhash(&toks);
        for i in [0usize, 1, 59, 119] {
            let got = u32::from_be_bytes(fp[i * 4..i * 4 + 4].try_into().unwrap());
            assert_eq!(got, naive_slot(&toks, i), "slot {i}");
        }
    }

    #[test]
    fn mersenne_fold_equals_division_across_the_input_range() {
        let p = u128::from(MERSENNE_61);
        let max_v = (p - 1) * (p - 1) + (p - 1);
        let mut cases = vec![
            0,
            1,
            p - 1,
            p,
            p + 1,
            2 * p,
            2 * p - 1,
            (1 << 61) + 1,
            max_v,
        ];
        cases.extend(
            (1..64)
                .map(|k| (1u128 << (k + 58)) - 1)
                .filter(|v| *v <= max_v),
        );
        let mut s = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..10_000 {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let a = u128::from(s % MERSENNE_61);
            let x = u128::from(s.rotate_left(29) % MERSENNE_61);
            cases.push(a * x + u128::from(s.rotate_left(7) % MERSENNE_61));
        }
        for v in cases {
            assert_eq!(u128::from(mod_m61(v)), v % p, "v = {v}");
        }
    }

    #[test]
    fn shared_shingle_values_equal_per_segment_minhash() {
        let p = FpProfile::text_minhash_120();
        for n in [5usize, 6, 256, 257, 300, 640, 1001] {
            let text = words(n, "s");
            let normalized = normalize_text(&text);
            let toks = tokenize(&normalized);
            let per_segment: Vec<Vec<u8>> = segments(&toks)
                .iter()
                .map(|s| minhash(s).to_vec())
                .collect();
            assert_eq!(
                p.fingerprints(text.as_bytes()).unwrap(),
                per_segment,
                "n={n}"
            );
        }
    }

    fn shingles(tokens: &[&str]) -> std::collections::HashSet<String> {
        tokens.windows(5).map(|w| w.join(" ")).collect()
    }

    #[test]
    fn matching_slots_estimate_shingle_jaccard() {
        let p = FpProfile::text_minhash_120();
        let base: Vec<String> = (0..200).map(|i| format!("t{i}")).collect();
        for edits in [0usize, 4, 12, 30, 200] {
            let mut other = base.clone();
            for k in 0..edits {
                let at = (k * 37) % other.len();
                other[at] = format!("x{k}");
            }
            let a: Vec<&str> = base.iter().map(String::as_str).collect();
            let b: Vec<&str> = other.iter().map(String::as_str).collect();
            let (sa, sb) = (shingles(&a), shingles(&b));
            let j = sa.intersection(&sb).count() as f64 / sa.union(&sb).count() as f64;
            let m = p.similarity(&minhash(&a), &minhash(&b)).unwrap();
            // The estimator's standard error at J is sqrt(J(1-J)/120) ≤ 0.046;
            // allow 0.15 (> 3σ). Inputs are fixed, so this never flakes.
            assert!(
                (f64::from(m) / 120.0 - j).abs() < 0.15,
                "edits={edits}: m={m} J={j:.3}"
            );
        }
    }

    #[test]
    fn near_duplicates_pass_the_default_threshold_and_unrelated_text_does_not() {
        let p = FpProfile::text_minhash_120();
        let original = words(300, "w");
        let edited = original.replacen("w150", "changed", 1);
        let unrelated = words(300, "z");
        let fa = p.fingerprints(original.as_bytes()).unwrap();
        let fb = p.fingerprints(edited.as_bytes()).unwrap();
        let fc = p.fingerprints(unrelated.as_bytes()).unwrap();
        assert_eq!(fa.len(), 2);
        assert!(p.similarity(&fa[0], &fb[0]).unwrap() >= p.threshold());
        assert!(p.similarity(&fa[0], &fc[0]).unwrap() < 10);
        // Formatting and case changes are absorbed by normalization.
        let shouted = original.to_uppercase().replace(' ', " ,  ");
        assert_eq!(p.fingerprints(shouted.as_bytes()).unwrap(), fa);
    }

    #[test]
    fn short_and_invalid_items_get_no_fingerprint() {
        let p = FpProfile::text_minhash_120();
        assert!(p.fingerprints(b"one two three four").unwrap().is_empty());
        assert_eq!(p.fingerprints(b"one two three four five").unwrap().len(), 1);
        assert_eq!(p.fingerprints(&[0xff]), Err(ContentError::InvalidUtf8));
        assert_eq!(
            p.fingerprints_of_work(&[0xff]),
            Err(ContentError::InvalidUtf8)
        );
    }

    #[test]
    fn regression_pin_of_one_fingerprint() {
        // Pins this implementation's output so a dependency bump that changes
        // a fingerprint fails here. It proves stability, not correctness:
        // correctness is `minhash_matches_a_naive_recomputation_of_the_definition`.
        let fp = FpProfile::text_minhash_120()
            .fingerprints("The quick brown fox jumps over the lazy dog".as_bytes())
            .unwrap();
        assert_eq!(fp.len(), 1);
        assert_eq!(
            blake3::hash(&fp[0]).to_hex().as_str(),
            REGRESSION_PIN,
            "text/minhash-120 output changed: a new profile version is required"
        );
    }

    const REGRESSION_PIN: &str = "b8e66ac06324c656bab2405c0b328c26b2f9bc295686d2a12c2b0aea6b0f1276";

    #[test]
    fn table_rows_resolve_only_to_the_v1_definition() {
        let good = FpProfile::text_minhash_120().entry();
        assert_eq!(
            FpProfile::from_entry(&good),
            Ok(FpProfile::text_minhash_120())
        );
        let cases: Vec<(FpProfileEntry, ContentError)> = vec![
            (
                FpProfileEntry {
                    id: "image/pdq-256".into(),
                    ..good.clone()
                },
                ContentError::UnknownFpProfile("image/pdq-256@1".into()),
            ),
            (
                FpProfileEntry {
                    version: 2,
                    ..good.clone()
                },
                ContentError::UnknownFpProfile("text/minhash-120@2".into()),
            ),
            (
                FpProfileEntry {
                    bands: 19,
                    ..good.clone()
                },
                ContentError::InvalidFpParams("text/minhash-120 v1 requires b = 20, r = 6"),
            ),
            (
                FpProfileEntry {
                    rows: 5,
                    ..good.clone()
                },
                ContentError::InvalidFpParams("text/minhash-120 v1 requires b = 20, r = 6"),
            ),
            (
                FpProfileEntry {
                    threshold: 0,
                    ..good.clone()
                },
                ContentError::InvalidFpParams("threshold must be 1..=120 slots"),
            ),
            (
                FpProfileEntry {
                    threshold: 121,
                    ..good.clone()
                },
                ContentError::InvalidFpParams("threshold must be 1..=120 slots"),
            ),
        ];
        for (row, err) in cases {
            assert_eq!(FpProfile::from_entry(&row), Err(err));
        }
        // A different implementation_id is still the same profile.
        let other_impl = FpProfileEntry {
            implementation_id: "someone-else=1".into(),
            ..good
        };
        assert!(FpProfile::from_entry(&other_impl).is_ok());
    }

    #[test]
    fn fp_leaf_binds_profile_index_segment_and_bytes() {
        let f = vec![7u8; MINHASH_WIDTH];
        let l = fp_leaf(0, 0, &f);
        assert_ne!(l, fp_leaf(1, 0, &f), "fp_profile_index not bound");
        assert_ne!(l, fp_leaf(0, 1, &f), "segment_index not bound");
        let mut g = f.clone();
        g[MINHASH_WIDTH - 1] ^= 1;
        assert_ne!(l, fp_leaf(0, 0, &g), "fingerprint not bound");
        // Hand-computed preimage: u16_be ‖ u32_be ‖ bytes under H_fp.
        let mut m = vec![0, 2, 0, 0, 0, 3];
        m.extend_from_slice(&f);
        assert_eq!(fp_leaf(2, 3, &f), h(Domain::Fp, &[&m]));
    }

    #[test]
    fn fingerprint_set_paths_fold_for_every_position_and_size() {
        assert_eq!(FpSet::new(vec![]).unwrap().root(), empty_fp_set_root());
        for n in 1u32..=11 {
            let entries: Vec<FpEntry> = (0..n)
                .map(|i| FpEntry {
                    fp_profile_index: (i % 2) as u16,
                    segment_index: i,
                    fingerprint: vec![i as u8; MINHASH_WIDTH],
                })
                .collect();
            let set = FpSet::new(entries).unwrap();
            assert_ne!(set.root(), empty_fp_set_root());
            let leaves: Vec<_> = set
                .entries()
                .iter()
                .map(|e| fp_leaf(e.fp_profile_index, e.segment_index, &e.fingerprint))
                .collect();
            for j in 0..n {
                let e = &set.entries()[j as usize];
                let path = set.path(j as usize);
                assert_eq!(path, promoted_path(&leaves, j as usize, Domain::FpNode));
                assert_eq!(
                    fp_set_root_from_path(
                        e.fp_profile_index,
                        e.segment_index,
                        &e.fingerprint,
                        j,
                        n,
                        &path
                    ),
                    Ok(set.root()),
                    "n={n} j={j}"
                );
            }
        }
    }

    #[test]
    fn icu_data_is_the_pinned_unicode_version() {
        // ICU's data crates do not state a Unicode version. Compare ICU's
        // General_Category table (same data release as its case-folding data)
        // with unicode-properties, which is compile-time pinned to 17.0.0, over
        // every scalar value. A release built on another Unicode version
        // differs at least in which code points are assigned.
        use icu_properties::props::GeneralCategory as Icu;
        use icu_properties::CodePointMapData;
        use unicode_properties::GeneralCategory as Up;
        let icu = CodePointMapData::<Icu>::new();
        let mut mismatches = Vec::new();
        for c in (0u32..=0x10FFFF).filter_map(char::from_u32) {
            let g = icu.get(c);
            let icu_ln = matches!(
                g,
                Icu::UppercaseLetter
                    | Icu::LowercaseLetter
                    | Icu::TitlecaseLetter
                    | Icu::ModifierLetter
                    | Icu::OtherLetter
                    | Icu::DecimalNumber
                    | Icu::LetterNumber
                    | Icu::OtherNumber
            );
            let assigned_differs =
                (g == Icu::Unassigned) != (c.general_category() == Up::Unassigned);
            if assigned_differs || icu_ln != is_letter_or_number(c) {
                mismatches.push(c as u32);
            }
        }
        assert!(
            mismatches.is_empty(),
            "ICU data disagrees with Unicode 17.0.0 at {} code points, first {:X?}",
            mismatches.len(),
            &mismatches[..mismatches.len().min(8)]
        );
    }

    #[test]
    fn implementation_id_matches_locked_dependencies() {
        let lock = include_str!("../../../../Cargo.lock").replace("\r\n", "\n");
        for (name, v) in [
            ("icu_casemap", ICU_CASEMAP_VERSION),
            ("unicode-properties", UNICODE_PROPERTIES_VERSION),
        ] {
            assert!(
                lock.contains(&format!("name = \"{name}\"\nversion = \"{v}\"")),
                "Cargo.lock no longer locks {name} {v}; update the constant \
                 (and the profile version if output changes)"
            );
        }
        let id = FpProfile::text_minhash_120().implementation_id();
        let names: Vec<&str> = id
            .split(';')
            .map(|kv| kv.split('=').next().unwrap())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "implementation_id must be sorted by name");
    }
}
