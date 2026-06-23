//! PDF **word-run** segmentation core (ADR-0029 Phase B) — *increment 1*.
//!
//! Where [`crate::zk::segment::pdf_xref`] commits one hiding leaf per indirect
//! object, this commits one leaf per **word** inside a page content stream, so a
//! redaction can hide a single word/phrase instead of a whole object/page. This
//! module is the load-bearing core: a content-stream **word tokenizer** and a
//! **deterministic re-emit** whose revealed words recompute their committed leaf
//! byte-for-byte from the produced artifact (the property the Phase B prototype
//! validated against the real `olympus-crypto` leaf, 127/127).
//!
//! Scope of increment 1 (gated behind the `textrun-segmenter` feature, NOT wired
//! into ingest/dispatch, so no live `pdf-textrun` bundle is produced yet — the
//! offline verifiers + vectors + DB tag land with the `Segmenter` wiring):
//!   * Words come only from literal-string operands `(...)` of the text-show
//!     operators `Tj` / `TJ` / `'` / `"`. Hex strings `<...>` and dict operands
//!     are scanned and passed through verbatim (not word-sources) — documented,
//!     fail-soft.
//!   * Redaction here OMITS the redacted word's bytes (empty-blank). This is
//!     crypto-correct (revealed words round-trip) but reflows following text;
//!     the width-preserving `TJ` move (prototype-proven, needs font `/Widths`)
//!     is increment 2.
//!
//! Still TODO before promotion to a live format (tracked in
//! `docs/plans/visual-box-redaction.md`): the `Segmenter` impl that decodes a
//! page's content stream(s) out of the PDF container and rebuilds it (reusing the
//! `pdf_xref` machinery), width-preserving redaction, PDF-string escaping at word
//! boundaries, `TJ` kerning, CID/Type0 fonts, and both offline verifiers + the
//! cross-language vectors (ADR-0005 discipline).

#![cfg(feature = "textrun-segmenter")]

use std::collections::{BTreeMap, HashSet};

use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

use crate::zk::chunk::fr_to_hex;
use crate::zk::segment::pdf_xref::{
    extract_root_ref, logical_objects, rebuild_traditional_with_spans,
};
use crate::zk::segment::{
    variable_depth_fold_root, variable_geometry, Segment, SegmentError, SegmentFormat,
    SegmentManifest, SegmentSpan, Segmenter, MAX_INFLATE, MAX_REDACTION_SEGMENTS,
};

/// Scan a literal string starting at `open` (index of `(`). Returns the index
/// just past the matching `)`, handling `\`-escapes and balanced inner parens.
fn scan_literal_string(b: &[u8], open: usize) -> usize {
    let mut i = open + 1;
    let mut depth = 1usize;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2, // escape: skip the escaped byte (octal runs are still safe to skip 1)
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => i += 1,
        }
    }
    i
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00)
}

/// Byte ranges of literal-string operands that are **text-show** strings, in
/// stream order. A string is a show string iff the operand group it belongs to
/// is terminated by a `Tj` / `TJ` / `'` / `"` operator (PDF is postfix, so we
/// buffer pending literal strings and resolve them when the operator arrives).
fn show_string_ranges(b: &[u8]) -> Vec<(usize, usize)> {
    let mut shows = Vec::new();
    let mut pending: Vec<(usize, usize)> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if is_ws(c) {
            i += 1;
        } else if c == b'(' {
            let end = scan_literal_string(b, i);
            pending.push((i, end));
            i = end;
        } else if c == b'<' {
            if b.get(i + 1) == Some(&b'<') {
                // dict — skip to balanced ">>"
                let mut depth = 1usize;
                i += 2;
                while i + 1 < b.len() && depth > 0 {
                    if &b[i..i + 2] == b"<<" {
                        depth += 1;
                        i += 2;
                    } else if &b[i..i + 2] == b">>" {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            } else {
                // hex string — skip to '>'
                i += 1;
                while i < b.len() && b[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
        } else if c == b'/' {
            // name — skip to next ws/delimiter
            i += 1;
            while i < b.len()
                && !is_ws(b[i])
                && !matches!(b[i], b'(' | b'<' | b'[' | b']' | b'/' | b'{' | b'}' | b'%')
            {
                i += 1;
            }
        } else if matches!(c, b'[' | b']' | b'{' | b'}' | b')' | b'>') {
            i += 1; // stray delimiter / array bracket — operand-group neutral
        } else if c == b'\'' || c == b'"' {
            // single-char show operators
            for r in pending.drain(..) {
                shows.push(r);
            }
            i += 1;
        } else if c.is_ascii_digit() || matches!(c, b'+' | b'-' | b'.') {
            // number — skip the run
            i += 1;
            while i < b.len()
                && (b[i].is_ascii_digit() || matches!(b[i], b'+' | b'-' | b'.' | b'e' | b'E'))
            {
                i += 1;
            }
        } else if c.is_ascii_alphabetic() {
            // operator keyword — scan the run, resolve the operand group
            let s = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'*') {
                i += 1;
            }
            let op = &b[s..i];
            if op == b"Tj" || op == b"TJ" {
                for r in pending.drain(..) {
                    shows.push(r);
                }
            } else {
                pending.clear(); // any other operator ends the group without showing
            }
        } else {
            i += 1; // anything else — advance
        }
    }
    shows
}

/// Ordered word byte-ranges across all text-show strings. A word is a maximal
/// run of non-whitespace bytes inside a show string's content (between its
/// parens). Returned sorted, non-overlapping — the segment order.
pub(crate) fn word_ranges(content: &[u8]) -> Vec<(usize, usize)> {
    let mut words = Vec::new();
    for (s, e) in show_string_ranges(content) {
        // content of the literal string is between the outer parens
        let (cs, ce) = (s + 1, e.saturating_sub(1));
        let mut i = cs;
        while i < ce {
            if is_ws(content[i]) {
                i += 1;
                continue;
            }
            let ws = i;
            while i < ce && !is_ws(content[i]) {
                i += 1;
            }
            words.push((ws, i));
        }
    }
    words
}

/// Deterministic re-emit: copy `content` verbatim, OMITTING the bytes of any
/// word whose index is in `redacted`. Returns the new content and, per word, its
/// `Some((offset, len))` span in the output (`None` for redacted words). Revealed
/// words appear byte-identical, so their committed leaf recomputes from the span.
pub(crate) fn reemit(
    content: &[u8],
    words: &[(usize, usize)],
    redacted: &HashSet<usize>,
) -> (Vec<u8>, Vec<Option<(usize, usize)>>) {
    let mut out = Vec::with_capacity(content.len());
    let mut spans = vec![None; words.len()];
    let mut cur = 0usize;
    for (i, &(s, e)) in words.iter().enumerate() {
        out.extend_from_slice(&content[cur..s]); // verbatim structure before the word
        if !redacted.contains(&i) {
            spans[i] = Some((out.len(), e - s));
            out.extend_from_slice(&content[s..e]);
        }
        cur = e;
    }
    out.extend_from_slice(&content[cur..]);
    (out, spans)
}

// ── content-stream object layer (bridge to the PDF container) ──────────────────
//
// A page content stream is a PDF stream object `<<dict>>stream\n<bytes>\nendstream`
// whose bytes are usually `/FlateDecode`-compressed. To redact words we must
// decode it, blank words in the decoded content, and re-emit. Re-compression is
// non-deterministic, so the re-emit is UNCOMPRESSED — that also makes each word's
// bytes directly addressable by a byte span in the produced artifact (the V3
// bundle's `artifact_offset`/`artifact_length`).

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    h.windows(n.len()).position(|w| w == n)
}
fn rfind(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    h.windows(n.len()).rposition(|w| w == n)
}

/// `/FlateDecode` (incl. the `/Fl` abbreviation) present in the stream dict?
fn is_flate(dict: &[u8]) -> bool {
    find(dict, b"/FlateDecode").is_some() || find(dict, b"/Fl").is_some()
}

/// Inflate (zlib) into at most `*remaining` bytes, decrementing the shared
/// cumulative budget by the produced length; `None` on error or over-budget.
/// Threading ONE `remaining` across every content stream of a document bounds the
/// **cumulative** inflated bytes (audit A1-02) — a fresh per-call budget would let
/// many streams each inflate up to [`MAX_INFLATE`]. Mirrors
/// [`crate::zk::segment::pdf_xref`]'s `inflate_within`.
fn inflate(data: &[u8], remaining: &mut usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(data)
        .take(*remaining as u64 + 1)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() > *remaining {
        return None;
    }
    *remaining -= out.len();
    Some(out)
}

/// Decode a content-stream object body (`<<dict>>stream\n…\nendstream`) into its
/// content bytes. FlateDecode is inflated; an unfiltered stream is returned raw;
/// any other filter chain → `None` (not word-segmentable here — fail soft).
pub(crate) fn decode_content_stream(obj: &[u8], remaining: &mut usize) -> Option<Vec<u8>> {
    let s = find(obj, b"stream")?;
    let dict = &obj[..s];
    // stream data starts after `stream` + its EOL (CRLF or LF, per PDF §7.3.8).
    let mut ds = s + b"stream".len();
    if obj.get(ds) == Some(&b'\r') {
        ds += 1;
    }
    if obj.get(ds) == Some(&b'\n') {
        ds += 1;
    }
    let mut e = rfind(obj, b"endstream")?;
    // drop the single EOL that precedes `endstream`
    if e > ds && obj[e - 1] == b'\n' {
        e -= 1;
    }
    if e > ds && obj[e - 1] == b'\r' {
        e -= 1;
    }
    let raw = obj.get(ds..e)?;
    if is_flate(dict) {
        inflate(raw, remaining)
    } else if find(dict, b"/Filter").is_some() {
        None // some other / chained filter — skip (fail soft)
    } else {
        Some(raw.to_vec())
    }
}

/// Re-emit a content-stream object **body** carrying `content` UNCOMPRESSED
/// (filter dropped, `/Length` set). Returns `(body, data_offset)` where
/// `data_offset` is where `content` begins inside `body` — so a word at offset
/// `w` in `content` lands at `data_offset + w` in `body` (and, once the rebuild
/// places this body in the artifact, at `obj_artifact_offset + data_offset + w`).
///
/// Note: a content stream's dict is normally just `/Length` (+ `/Filter`), so
/// emitting a fresh `<< /Length N >>` is faithful for the common case; preserving
/// other dict keys is a follow-up if a producer puts extras here.
pub(crate) fn reemit_content_object(content: &[u8]) -> (Vec<u8>, usize) {
    let mut body = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    let data_offset = body.len();
    body.extend_from_slice(content);
    body.extend_from_slice(b"\nendstream");
    (body, data_offset)
}

// ── Segmenter: PDF content-stream word-run redaction ───────────────────────────

fn malformed(detail: impl Into<String>) -> SegmentError {
    SegmentError::Malformed {
        format: "pdf-textrun",
        detail: detail.into(),
    }
}

/// One page content-stream object decoded with its in-order word ranges. Objects
/// that don't decode (image/font streams, non-Flate filter chains) or carry no
/// text words are excluded. Emitted in obj-id ascending order (BTreeMap), so the
/// flattened word sequence — and thus each word's GLOBAL `segment_id` — is
/// deterministic across `extract` and `apply_redaction`.
struct ContentObj {
    obj_id: u32,
    generation: u16,
    content: Vec<u8>,
    words: Vec<(usize, usize)>,
}

fn content_objects(
    bodies: &BTreeMap<u32, (u16, Vec<u8>)>,
    remaining: &mut usize,
) -> Vec<ContentObj> {
    let mut out = Vec::new();
    for (&obj_id, (generation, body)) in bodies {
        if let Some(content) = decode_content_stream(body, remaining) {
            let words = word_ranges(&content);
            if !words.is_empty() {
                out.push(ContentObj {
                    obj_id,
                    generation: *generation,
                    content,
                    words,
                });
            }
        }
    }
    out
}

/// The ADR-0029 Phase B word-run [`Segmenter`]: one hiding leaf per text word in a
/// page content stream. Reuses the modern-PDF container parse + rebuild
/// ([`crate::zk::segment::pdf_xref`]); redaction blanks the selected words in the
/// decoded stream and re-emits it UNCOMPRESSED, so each revealed word becomes a
/// byte span in the produced artifact (the V3 bundle's `artifact_offset/length`).
///
/// Increment 3: empty-blank redaction (proven round-trip). Width-preserving `TJ`
/// moves (no reflow) and the offline verifiers + cross-language vectors are the
/// remaining promotion steps — see `docs/plans/visual-box-redaction.md`.
pub struct PdfTextRunSegmenter;

impl Segmenter for PdfTextRunSegmenter {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::PdfTextRun
    }

    fn extract(&self, bytes: &[u8], blind_secret: &[u8]) -> Result<SegmentManifest, SegmentError> {
        let bodies = logical_objects(bytes)?;
        let content_hash = blake3::hash(bytes);
        // One cumulative inflate budget for every content stream in this document
        // (audit A1-02); see `inflate`.
        let mut remaining = MAX_INFLATE;
        let objs = content_objects(&bodies, &mut remaining);
        // Enforce the segment cap on the cheap word COUNT BEFORE any Poseidon leaf
        // work, so a crafted PDF can't force millions of hash computations before
        // validation rejects it.
        let total_words: usize = objs.iter().map(|co| co.words.len()).sum();
        if total_words > MAX_REDACTION_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: total_words,
                max: MAX_REDACTION_SEGMENTS,
            });
        }
        let mut segments = Vec::with_capacity(total_words);
        let mut leaves = Vec::with_capacity(total_words);
        let mut gidx = 0u32;
        for co in &objs {
            for &(s, e) in &co.words {
                let id_be = gidx.to_be_bytes();
                let content = content_scalar(&id_be, &co.content[s..e]);
                let blinding = derive_blinding(blind_secret, content_hash.as_bytes(), &id_be);
                let leaf = redaction_leaf(&content, &blinding)
                    .map_err(|e| SegmentError::LeafComputationFailed(e.to_string()))?;
                leaves.push(leaf);
                segments.push(Segment {
                    segment_id: gidx,
                    label: None,
                    byte_offset: 0, // re-emit format: real span from apply_with_spans
                    byte_length: (e - s) as u64,
                    leaf_hex: fr_to_hex(leaf),
                });
                gidx += 1;
            }
        }
        // N < 2 surfaces as TooFewSegments → ingest routes to the chunk fallback.
        let root = variable_depth_fold_root(&leaves)?;
        let (tree_depth, max_leaves) = variable_geometry(segments.len());
        Ok(SegmentManifest {
            format: SegmentFormat::PdfTextRun,
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
        Ok(self
            .apply_redaction_with_spans(bytes, manifest, redacted_ids)?
            .0)
    }

    fn apply_redaction_with_spans(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
        for &id in redacted_ids {
            if !manifest.segments.iter().any(|s| s.segment_id == id) {
                return Err(SegmentError::UnknownSegment(id));
            }
        }
        let bodies = logical_objects(bytes)?;
        let root_ref = extract_root_ref(bytes);
        let redacted: HashSet<u32> = redacted_ids.iter().copied().collect();
        // One cumulative inflate budget across every content stream (audit A1-02).
        let mut remaining = MAX_INFLATE;

        // Re-emit each content object with its redacted words blanked; record each
        // REVEALED word's (obj_id, generation, offset within the new object body).
        let mut new_bodies = bodies.clone();
        let mut word_pos: BTreeMap<u32, (u32, u16, usize, usize)> = BTreeMap::new();
        let mut gidx = 0u32;
        for co in content_objects(&bodies, &mut remaining) {
            let base = gidx;
            let local_redacted: HashSet<usize> = (0..co.words.len())
                .filter(|li| redacted.contains(&(base + *li as u32)))
                .collect();
            let (red_content, content_spans) = reemit(&co.content, &co.words, &local_redacted);
            let (new_body, data_off) = reemit_content_object(&red_content);
            new_bodies.insert(co.obj_id, (co.generation, new_body));
            for (li, span) in content_spans.iter().enumerate() {
                if let Some((off, len)) = span {
                    word_pos.insert(
                        base + li as u32,
                        (co.obj_id, co.generation, data_off + off, *len),
                    );
                }
            }
            gidx += co.words.len() as u32;
        }

        // No object-level redaction — the content is already blanked in new_bodies.
        let (artifact, obj_spans) =
            rebuild_traditional_with_spans(&new_bodies, &HashSet::new(), root_ref.as_deref());
        let obj_off: BTreeMap<u32, u64> = obj_spans.iter().map(|&(id, off, _)| (id, off)).collect();

        let mut spans = Vec::with_capacity(manifest.segments.len());
        for seg in &manifest.segments {
            let span = match word_pos.get(&seg.segment_id) {
                // revealed word: its bytes sit at obj_header + body_offset in the artifact
                Some(&(obj_id, generation, body_off, len)) => {
                    let header_len = format!("{obj_id} {generation} obj\n").len();
                    let obj_artifact_off = *obj_off
                        .get(&obj_id)
                        .ok_or_else(|| malformed("rebuilt object missing from artifact"))?;
                    SegmentSpan {
                        segment_id: seg.segment_id,
                        artifact_offset: obj_artifact_off + header_len as u64 + body_off as u64,
                        artifact_length: len as u64,
                    }
                }
                // redacted word: bytes destroyed — leaf_hex is authoritative
                None => SegmentSpan {
                    segment_id: seg.segment_id,
                    artifact_offset: 0,
                    artifact_length: 0,
                },
            };
            spans.push(span);
        }
        Ok((artifact, spans))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

    const SECRET: &[u8] = &[0x5au8; 32];

    fn words_of<'a>(content: &'a [u8], ranges: &[(usize, usize)]) -> Vec<&'a [u8]> {
        ranges.iter().map(|&(s, e)| &content[s..e]).collect()
    }

    #[test]
    fn tokenizes_tj_words() {
        let c = b"BT /F1 12 Tf 72 720 Td (Hello SECRET World) Tj ET";
        let r = word_ranges(c);
        assert_eq!(words_of(c, &r), vec![&b"Hello"[..], b"SECRET", b"World"]);
    }

    #[test]
    fn tokenizes_tj_array_words_with_kerning() {
        // TJ array: string fragments split into words; kerning numbers ignored.
        let c = b"BT (Hel) [(lo Wor) -20 (ld)] TJ ET";
        // note: the lone (Hel) before '[' is its own pending group ended by TJ too
        let r = word_ranges(c);
        assert_eq!(words_of(c, &r), vec![&b"Hel"[..], b"lo", b"Wor", b"ld"]);
    }

    #[test]
    fn non_show_strings_are_not_words() {
        // a literal string that is NOT a Tj/TJ operand (here: followed by `Do`)
        // must not yield words.
        let c = b"BT (real text) Tj ET (not shown) /X Do";
        let r = word_ranges(c);
        assert_eq!(words_of(c, &r), vec![&b"real"[..], b"text"]);
    }

    #[test]
    fn escaped_parens_do_not_break_the_string() {
        let c = b"BT (a \\(b\\) c) Tj ET";
        let r = word_ranges(c);
        // words split on whitespace bytes; escaped parens stay inside their word
        assert_eq!(words_of(c, &r), vec![&b"a"[..], b"\\(b\\)", b"c"]);
    }

    #[test]
    fn reemit_roundtrips_revealed_words_against_the_real_leaf() {
        let c = b"BT /F1 12 Tf 72 720 Td (public ALPHA secret BETA tail) Tj ET";
        let words = word_ranges(c);
        let content_hash = blake3::hash(c);
        let leaf = |i: usize, bytes: &[u8]| {
            let id = (i as u32).to_be_bytes();
            let content = content_scalar(&id, bytes);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id);
            redaction_leaf(&content, &blinding).unwrap()
        };
        // INGEST: commit each word's real leaf.
        let committed: Vec<_> = words
            .iter()
            .enumerate()
            .map(|(i, &(s, e))| leaf(i, &c[s..e]))
            .collect();

        // redact the 2nd and 4th words ("ALPHA", "BETA")
        let redacted: HashSet<usize> = [1usize, 3].into_iter().collect();
        let (art, spans) = reemit(c, &words, &redacted);
        let (art2, _) = reemit(c, &words, &redacted);
        assert_eq!(art, art2, "re-emit is byte-deterministic");

        // ROUND-TRIP: every revealed word recomputes its committed leaf from its span.
        for (i, &(s, e)) in words.iter().enumerate() {
            if redacted.contains(&i) {
                assert!(spans[i].is_none(), "redacted word has no span");
                continue;
            }
            let (off, len) = spans[i].expect("revealed span");
            assert_eq!(&art[off..off + len], &c[s..e], "byte-exact recovery");
            assert_eq!(
                leaf(i, &art[off..off + len]),
                committed[i],
                "real leaf recomputes"
            );
        }
        // SECURITY: redacted words' plaintext is gone from the artifact.
        assert!(!art.windows(5).any(|w| w == b"ALPHA"));
        assert!(!art.windows(4).any(|w| w == b"BETA"));
        // and the produced stream is still a valid `(...) Tj` show op
        assert!(art.windows(2).any(|w| w == b"Tj"));
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn content_stream_decode_redact_reemit_roundtrips() {
        let text = b"BT /F1 12 Tf 72 720 Td (public ALPHA secret BETA tail) Tj ET";
        // a FlateDecode content-stream object body
        let comp = zlib(text);
        let mut obj = format!(
            "<< /Length {} /Filter /FlateDecode >>\nstream\n",
            comp.len()
        )
        .into_bytes();
        obj.extend_from_slice(&comp);
        obj.extend_from_slice(b"\nendstream");

        // decode → original content
        let mut rem = MAX_INFLATE;
        let content = decode_content_stream(&obj, &mut rem).expect("decode");
        assert_eq!(content, text);

        // tokenize, redact ALPHA(1)/BETA(3), re-emit content, wrap as a stream body
        let words = word_ranges(&content);
        let redacted: HashSet<usize> = [1usize, 3].into_iter().collect();
        let (red_content, content_spans) = reemit(&content, &words, &redacted);
        let (body, data_off) = reemit_content_object(&red_content);
        // the re-emitted (now unfiltered) body decodes back to the redacted content
        let mut rem2 = MAX_INFLATE;
        assert_eq!(
            decode_content_stream(&body, &mut rem2).unwrap(),
            red_content
        );

        // ROUND-TRIP at object-body level with the real leaf
        let content_hash = blake3::hash(text);
        let leaf = |i: usize, b: &[u8]| {
            let id = (i as u32).to_be_bytes();
            let c = content_scalar(&id, b);
            let bl = derive_blinding(SECRET, content_hash.as_bytes(), &id);
            redaction_leaf(&c, &bl).unwrap()
        };
        for (i, &(s, e)) in words.iter().enumerate() {
            if redacted.contains(&i) {
                continue;
            }
            let (off, len) = content_spans[i].unwrap();
            let body_off = data_off + off; // content offset → object-body offset
            assert_eq!(
                &body[body_off..body_off + len],
                &content[s..e],
                "word addressable in body"
            );
            assert_eq!(
                leaf(i, &body[body_off..body_off + len]),
                leaf(i, &content[s..e])
            );
        }
        // redacted plaintext is gone from the (now plaintext) body
        assert!(!body.windows(5).any(|w| w == b"ALPHA"));
        assert!(!body.windows(4).any(|w| w == b"BETA"));
    }

    #[test]
    fn unfiltered_stream_decodes_raw() {
        let obj = b"<< /Length 5 >>\nstream\nhello\nendstream";
        let mut rem = MAX_INFLATE;
        assert_eq!(decode_content_stream(obj, &mut rem).unwrap(), b"hello");
    }

    #[test]
    fn unknown_filter_is_skipped() {
        let obj = b"<< /Length 3 /Filter /DCTDecode >>\nstream\n???\nendstream";
        let mut rem = MAX_INFLATE;
        assert!(decode_content_stream(obj, &mut rem).is_none());
    }

    /// Minimal modern (xref-stream) PDF: catalog(1) → pages(2) → page(3) whose
    /// `/Contents` is a FlateDecode stream (4); the xref stream is obj 5. All
    /// direct objects.
    fn build_text_pdf(text: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.7\n");
        let off1 = buf.len();
        buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
        let off2 = buf.len();
        buf.extend_from_slice(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n");
        let off3 = buf.len();
        buf.extend_from_slice(
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n",
        );
        let comp = zlib(text);
        let off4 = buf.len();
        buf.extend_from_slice(
            format!(
                "4 0 obj\n<< /Length {} /Filter /FlateDecode >>\nstream\n",
                comp.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&comp);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        let off5 = buf.len();
        let mut rows: Vec<u8> = Vec::new();
        let push = |rows: &mut Vec<u8>, t: u8, f2: u32, f3: u16| {
            rows.push(t);
            rows.extend_from_slice(&f2.to_be_bytes());
            rows.extend_from_slice(&f3.to_be_bytes());
        };
        push(&mut rows, 0, 0, 65535);
        push(&mut rows, 1, off1 as u32, 0);
        push(&mut rows, 1, off2 as u32, 0);
        push(&mut rows, 1, off3 as u32, 0);
        push(&mut rows, 1, off4 as u32, 0);
        push(&mut rows, 1, off5 as u32, 0);
        let xref = zlib(&rows);
        buf.extend_from_slice(
            format!(
                "5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R /Length {} /Filter /FlateDecode >>\nstream\n",
                xref.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&xref);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        buf.extend_from_slice(format!("startxref\n{off5}\n%%EOF\n").as_bytes());
        buf
    }

    #[test]
    fn segmenter_extract_redact_roundtrip_on_a_real_pdf() {
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td (public ALPHA secret BETA tail) Tj ET");
        let m = PdfTextRunSegmenter.extract(&pdf, SECRET).unwrap();
        assert_eq!(m.format, SegmentFormat::PdfTextRun);
        assert_eq!(m.segments.len(), 5, "five words in the one content stream");
        // segment_ids are the global word indices 0..5
        assert_eq!(
            m.segments.iter().map(|s| s.segment_id).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        // the persisted leaves fold to the stored root.
        assert_eq!(m.recompute_root().unwrap(), m.original_root_hex);

        // redact word #1 (ALPHA) and #3 (BETA)
        let (artifact, spans) = PdfTextRunSegmenter
            .apply_redaction_with_spans(&pdf, &m, &[1, 3])
            .unwrap();
        // the rebuilt artifact is a valid traditional-xref PDF the walker can read
        assert!(crate::zk::pdf_objects::extract_object_spans(&artifact).is_ok());
        assert_eq!(spans.len(), m.segments.len());

        let content_hash = blake3::hash(&pdf);
        for seg in &m.segments {
            let span = spans
                .iter()
                .find(|s| s.segment_id == seg.segment_id)
                .unwrap();
            if seg.segment_id == 1 || seg.segment_id == 3 {
                assert_eq!(
                    span.artifact_length, 0,
                    "redacted word has no recoverable span"
                );
                continue;
            }
            // REVEALED: slice the span and recompute the committed real leaf.
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
            let word = &artifact[s..e];
            let id_be = seg.segment_id.to_be_bytes();
            let content = content_scalar(&id_be, word);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, seg.leaf_hex,
                "revealed word {} recomputes its leaf from the artifact span",
                seg.segment_id
            );
        }
        // redacted plaintext is gone from the artifact
        assert!(!artifact.windows(5).any(|w| w == b"ALPHA"));
        assert!(!artifact.windows(4).any(|w| w == b"BETA"));
    }
}
