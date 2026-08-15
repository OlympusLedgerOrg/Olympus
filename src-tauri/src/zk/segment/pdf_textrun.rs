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
//! **RFC-0001 (accepted 2026-08-02) landed the container commitment here.** The
//! leaf set is now a *partition of the artifact* rather than words alone:
//!
//!   * **word** — one leaf per word inside a text-show operand. Redactable.
//!   * **skeleton** — one leaf per content object, over its whole logical body
//!     with the word spans and the `/Length` value elided, encoded as
//!     length-prefixed runs. Binds every operator, coordinate, dictionary entry,
//!     and inter-word byte.
//!   * **object** — one leaf per non-content object, the same primitive
//!     `pdf_xref` uses over the same bytes. Binds images, fonts, everything else.
//!
//! Before that, everything except words was committed by **nothing**, and no
//! verifier-side check could have fixed it — a verifier cannot constrain bytes
//! the commitment never covered. That is why both offline verifiers reject the
//! tag today.
//!
//! Hex `<...>` operands are word sources too, as of the same RFC. They used to be
//! skipped, which made them an uncommitted text channel: a producer could re-show
//! "redacted" text through `<48656c6c6f> Tj` that no leaf covered and no span
//! inspected. Their destruction token is a same-length run of ASCII `0` — valid
//! hex, no reflow.
//!
//! Ids are two ranges: words `0..W-1`, containers `W..N-1`. The redactable set is
//! therefore a contiguous prefix, so the not-redactable guard is a bound check
//! rather than a per-row kind lookup a call site could forget.
//!
//! A redacted literal word's bytes become the fixed [`REDACTED_WORD_TOKEN`]
//! rather than being omitted: crypto-correct (revealed words round-trip) but it
//! still reflows following text. The placeholder also gives every redacted word a
//! real, non-degenerate artifact span, so a "were the redacted bytes destroyed"
//! check has something to inspect.
//!
//! **Live since PR #1547.** Both offline verifiers accept `pdf-textrun` against
//! vectors generated from this producer, and `textrun-segmenter` is a default
//! feature — so `granularity=word` on `POST /ingest/files` now commits at word
//! granularity instead of silently falling back to the object scheme. The
//! default granularity is still object; word is opt-in per request.
//!
//! **Known limitations are quality issues, not soundness issues** — none of them
//! affects what the commitment covers, and a bundle that verifies still
//! verifies:
//!   * **Redaction reflows text.** A redacted word becomes a fixed-width token,
//!     so following text on the line shifts. The width-preserving `TJ` move is
//!     prototype-proven, but it is **not** a redaction-time fix: the skeleton
//!     commits every non-word byte verbatim, so an adjustment inserted during
//!     redaction breaks the skeleton leaf — asserted by
//!     `tests::a_width_compensating_kern_breaks_the_skeleton_leaf`. Preserving
//!     width means committing an adjustment slot per word at ingest, i.e. a
//!     versioned format change; see
//!     `docs/rfcs/0000-width-preserving-redaction.md`.
//!   * PDF-string escaping at word boundaries and CID/Type0 fonts are untested.
//!     A document whose text does not tokenize yields no words, and `extract`
//!     refuses so the caller falls back to the object scheme.
//!   * **Run-block grouping for the segment cap** (ADR-0029 B-4) is still open:
//!     a document whose words plus containers exceed [`MAX_REDACTION_SEGMENTS`]
//!     is refused here and falls back to the object scheme, rather than
//!     committing coarser word *blocks* that would keep sub-page granularity.
//!     Multi-page selection — B-4's other half — needs no per-page id space: ids
//!     stay global and `describe_segments` reports each word's 1-based `page`,
//!     which the producer UI filters on.

#![cfg(feature = "textrun-segmenter")]

use std::collections::{BTreeMap, HashSet};

use olympus_crypto::redaction::redaction_leaf_for_segment;

use crate::zk::chunk::fr_to_hex;
use crate::zk::pdf_describe::{resolve_pages, SegmentDescription, WORD_TEXT_CHARS};
use crate::zk::pdf_syntax::dict_region;
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

/// Which string syntax a word came from. The two carry different destruction
/// tokens, because a hex string's content must stay valid hex after redaction
/// (RFC-0001 "Hex-string operands become word sources").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum WordKind {
    /// A whitespace-delimited word inside a literal `( … )` operand.
    Literal,
    /// A whole hex `< … >` operand. Hex has no internal whitespace structure, so
    /// the entire string is one word — RFC-0001 Q1 keeps this coarse rather than
    /// decoding glyph runs, which would need font `/Encoding` interpretation
    /// ported byte-exactly into both offline verifiers.
    Hex,
}

/// Byte ranges of string operands that are **text-show** strings, in stream
/// order, with the syntax each came from. A string is a show string iff the
/// operand group it belongs to is terminated by a `Tj` / `TJ` / `'` / `"`
/// operator (PDF is postfix, so we buffer pending strings and resolve them when
/// the operator arrives).
///
/// Hex operands are word sources as of RFC-0001. Before that they were skipped,
/// which made them an **uncommitted text channel**: a producer could re-show
/// "redacted" text through `<48656c6c6f> Tj`, which no leaf covered and no span
/// inspected.
fn show_string_ranges(b: &[u8]) -> Vec<(usize, usize, WordKind)> {
    let mut shows = Vec::new();
    let mut pending: Vec<(usize, usize, WordKind)> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        let c = b[i];
        if is_ws(c) {
            i += 1;
        } else if c == b'(' {
            let end = scan_literal_string(b, i);
            pending.push((i, end, WordKind::Literal));
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
                // hex string — scan to '>' and offer it as a show-string operand.
                let open = i;
                i += 1;
                while i < b.len() && b[i] != b'>' {
                    i += 1;
                }
                // An unterminated hex string runs to EOF; `i` is then past the
                // end, so clamp rather than producing a range outside `b`.
                i = (i + 1).min(b.len());
                pending.push((open, i, WordKind::Hex));
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

/// Ordered word byte-ranges across all text-show strings, each with its kind.
///
/// Inside a **literal** operand a word is a maximal run of non-whitespace bytes.
/// A **hex** operand contributes its whole content as one word. Ranges are the
/// word's own bytes — the enclosing delimiters are never included, so redaction
/// can overwrite a word without disturbing the string's framing.
///
/// Returned in stream order, non-overlapping — this is the word segment order.
pub(crate) fn word_ranges(content: &[u8]) -> Vec<(usize, usize, WordKind)> {
    let mut words = Vec::new();
    for (s, e, kind) in show_string_ranges(content) {
        // The operand's content sits between its delimiters, for both syntaxes.
        let (cs, ce) = (s + 1, e.saturating_sub(1));
        if cs >= ce {
            continue; // empty operand — nothing to commit or redact
        }
        match kind {
            WordKind::Hex => words.push((cs, ce, WordKind::Hex)),
            WordKind::Literal => {
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
                    words.push((ws, i, WordKind::Literal));
                }
            }
        }
    }
    words
}

/// The bytes that replace a redacted word of `kind`, given its original length.
///
/// A literal word becomes the fixed [`REDACTED_WORD_TOKEN`]. A hex word cannot —
/// `REDACTED` is not valid hex — so it becomes a run of ASCII `0` of the **same
/// length**: valid hex, length-preserving (no reflow), and unambiguously
/// destroyed. Both verifiers check the redacted span holds exactly this.
pub(crate) fn destruction_token(kind: WordKind, original_len: usize) -> Vec<u8> {
    match kind {
        WordKind::Literal => REDACTED_WORD_TOKEN.to_vec(),
        WordKind::Hex => vec![b'0'; original_len],
    }
}

/// Fixed placeholder written into the literal string in place of a redacted
/// word's bytes. Plain ASCII letters only — never `(`, `)`, or `\` — so it can
/// never disturb the enclosing literal string's escaping and the re-emit stays
/// a verbatim byte-copy on either side of it.
pub(crate) const REDACTED_WORD_TOKEN: &[u8] = b"REDACTED";

// The token must re-tokenise as EXACTLY ONE word, and that is load-bearing for
// the container commitment, not just for tidiness.
//
// A skeleton leaf is committed at ingest over the original content and must
// reproduce from the redacted artifact, where the verifier re-derives word spans
// by running `word_ranges` over the redacted bytes — so it re-tokenises the token
// itself. A single whitespace byte inside it would split one committed word into
// two derived words, change the run count, and make every skeleton leaf for that
// object irreproducible. A paren would break the enclosing literal string's
// framing instead.
//
// Compile-time rather than a test: this is a property of the constant, so a bad
// edit should not build. Without it the failure surfaces far away, as an
// unexplained leaf mismatch during verification.
const _: () = {
    let t = REDACTED_WORD_TOKEN;
    assert!(!t.is_empty(), "REDACTED_WORD_TOKEN must not be empty");
    let mut i = 0;
    while i < t.len() {
        assert!(
            !matches!(
                t[i],
                b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00 | b'(' | b')' | b'\\'
            ),
            "REDACTED_WORD_TOKEN must be a single unescaped word: no whitespace \
             (it would split into two derived words and break skeleton reproduction) \
             and no literal-string metacharacter"
        );
        i += 1;
    }
};

/// Deterministic re-emit: copy `content` verbatim, REPLACING the bytes of any
/// word whose index is in `redacted` with [`REDACTED_WORD_TOKEN`]. Returns the
/// new content and, per word (in the same order as `words`), its
/// `(offset, len)` span in the output — the token's span for a redacted word,
/// the word's own (byte-identical) span for a revealed one. Revealed words'
/// committed leaf recomputes from their span; a redacted word's span lets a
/// downstream check confirm the region actually holds the destroyed-content
/// token rather than leftover plaintext.
pub(crate) fn reemit(
    content: &[u8],
    words: &[(usize, usize, WordKind)],
    redacted: &HashSet<usize>,
) -> (Vec<u8>, Vec<(usize, usize)>) {
    let mut out = Vec::with_capacity(content.len());
    let mut spans = Vec::with_capacity(words.len());
    let mut cur = 0usize;
    for (i, &(s, e, kind)) in words.iter().enumerate() {
        out.extend_from_slice(&content[cur..s]); // verbatim structure before the word
        if redacted.contains(&i) {
            let token = destruction_token(kind, e - s);
            spans.push((out.len(), token.len()));
            out.extend_from_slice(&token);
        } else {
            spans.push((out.len(), e - s));
            out.extend_from_slice(&content[s..e]);
        }
        cur = e;
    }
    out.extend_from_slice(&content[cur..]);
    (out, spans)
}

/// Encode a **skeleton preimage**: the length-prefixed sequence of the runs
/// between `elided` spans within `body` (RFC-0001 "Skeleton leaves").
///
/// `elided` must be sorted, non-overlapping, and within `body`. For `K` elided
/// spans there are always exactly `K + 1` runs, so the run count pins the
/// elision count structurally.
///
/// Deliberately **not** a byte string with in-band elision markers. With a marker
/// byte, a content stream legitimately containing that byte raises a collision
/// question whose answer runs through the bundle's *global* segment count — a
/// subtle, non-local argument, in court evidence. Here no byte value is reserved,
/// so the question does not arise. Committing each run's *length* additionally
/// pins elision *positions*, so a word span cannot be slid along the stream
/// without changing the leaf.
/// Returns `None` if `elided` is not sorted, non-overlapping, and in range,
/// rather than panicking on the slice. The precondition used to be documented
/// only, which is fine for the producer — both callers build the list themselves
/// — but this is one of the two primitives that gets ported byte-exactly into the
/// offline verifiers, where the elision list is derived from attacker-supplied
/// artifact bytes. A panic there is a denial of service; a `None` is a rejection.
pub(crate) fn skeleton_preimage(body: &[u8], elided: &[(usize, usize)]) -> Option<Vec<u8>> {
    let mut prev_end = 0usize;
    for &(s, e) in elided {
        if s < prev_end || e < s || e > body.len() {
            return None;
        }
        prev_end = e;
    }
    let mut out = Vec::with_capacity(body.len() + 4 * (elided.len() + 1));
    let push_run = |out: &mut Vec<u8>, run: &[u8]| {
        // u32 big-endian length prefix, matching the framing discipline the leaf
        // primitives use elsewhere (ADR-0005). A run longer than u32::MAX is
        // impossible here: MAX_INFLATE bounds every decoded content stream.
        out.extend_from_slice(&(run.len() as u32).to_be_bytes());
        out.extend_from_slice(run);
    };
    let mut cur = 0usize;
    for &(s, e) in elided {
        push_run(&mut out, &body[cur..s]);
        cur = e;
    }
    push_run(&mut out, &body[cur..]);
    Some(out)
}

/// Byte range of the `/Length` **value** inside a canonical re-emitted content
/// object body, i.e. the digits after `/Length ` in `<< /Length N >>`.
///
/// Elided from the skeleton because it is *not invariant under redaction* — a
/// destruction token of a different length changes the payload size and so the
/// value. That is the same non-invariance that rules out a flat residue leaf. The
/// verifier recomputes it from the artifact instead, which is strictly stronger
/// than committing it: a recomputed check cannot be satisfied by a
/// stale-but-signed value.
pub(crate) fn length_value_span(body: &[u8]) -> Option<(usize, usize)> {
    // `/Length1`, `/Length2`, `/Length3` are real keys (font-descriptor streams)
    // and share the prefix, so a bare substring match would stop on the `1`,
    // consume it as the value, and leave the real `/Length` un-elided. A PDF name
    // ends at whitespace or a delimiter; require one.
    //
    // Unreachable from the producer today — every caller passes a canonical
    // `reemit_content_object` body that contains exactly `<< /Length N >>`. It
    // stops being unreachable when this is ported into the offline verifiers,
    // which run it against arbitrary artifact bodies, and a mismatch there is a
    // cross-language divergence rather than a local bug.
    let mut from = 0usize;
    let after_key = loop {
        let hit = from + find(&body[from..], b"/Length")?;
        let after = hit + b"/Length".len();
        match body.get(after) {
            Some(&c) if is_ws(c) || matches!(c, b'/' | b'[' | b']' | b'<' | b'>' | b'(' | b')') => {
                break after
            }
            // A `/Length` at the very end of the body has no value to elide.
            None => return None,
            _ => from = after,
        }
    };
    let mut i = after_key;
    while i < body.len() && is_ws(body[i]) {
        i += 1;
    }
    let start = i;
    while i < body.len() && body[i].is_ascii_digit() {
        i += 1;
    }
    (i > start).then_some((start, i))
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
    words: Vec<(usize, usize, WordKind)>,
}

impl ContentObj {
    /// This object's skeleton preimage (RFC-0001).
    ///
    /// Computed over the **canonical re-emitted body**, not the original one.
    /// That distinction is load-bearing and easy to get backwards: redaction
    /// re-emits every content object uncompressed with a fresh `<< /Length N >>`
    /// dict, so a skeleton committed over the *original* body — typically
    /// `/FlateDecode`d, with a different dict — could never reproduce from the
    /// artifact. Committing the canonical form means ingest commits the shape the
    /// artifact will actually have.
    ///
    /// Elides the word spans and the `/Length` value, which are exactly the two
    /// things redaction can change; everything else is committed verbatim.
    fn skeleton(&self) -> Option<Vec<u8>> {
        let (body, data_off) = reemit_content_object(&self.content);
        let mut elided: Vec<(usize, usize)> = Vec::with_capacity(self.words.len() + 1);
        // The `/Length` value lives in the dict, ahead of the stream data, so it
        // sorts first; the sort keeps that true rather than assuming it.
        if let Some(span) = length_value_span(&body) {
            elided.push(span);
        }
        for &(s, e, _) in &self.words {
            elided.push((data_off + s, data_off + e));
        }
        elided.sort_unstable();
        // Built here from in-range, non-overlapping spans, so `None` is
        // unreachable — but propagate rather than unwrap: a future change to how
        // `elided` is assembled should surface as a rejection, not a panic on the
        // ingest path.
        skeleton_preimage(&body, &elided)
    }
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
/// Increment 3: placeholder-token redaction (proven round-trip; every segment,
/// redacted or revealed, carries a real artifact span). Width-preserving `TJ`
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
        // Indexed once rather than scanned per object: both `objs` and `bodies`
        // are bounded only by MAX_REDACTION_SEGMENTS (2^16), and the input is
        // attacker-supplied, so a linear `find` inside the loop over `bodies`
        // would be ~2^32 comparisons on a PDF built entirely of content objects —
        // reachable *after* the cap check has already passed.
        let by_id: BTreeMap<u32, &ContentObj> = objs.iter().map(|co| (co.obj_id, co)).collect();
        // Enforce the segment cap on the cheap COUNT before any Poseidon leaf
        // work, so a crafted PDF can't force millions of hash computations before
        // validation rejects it. The count is now words plus one container leaf
        // per object, since the leaf set is a partition of the artifact.
        let total_words: usize = objs.iter().map(|co| co.words.len()).sum();
        // A document with no words has nothing this format can hide, so refuse and
        // let the caller fall back to the object scheme — which at least offers
        // whole-object redaction. This guard used to be implicit: no words meant
        // no leaves, and the fold rejected `N < 2`. Container leaves now clear that
        // bar on their own, so a textless PDF would otherwise commit as
        // `pdf-textrun` with zero redactable segments — strictly worse than the
        // object scheme it displaced.
        if total_words == 0 {
            return Err(SegmentError::Unsupported("pdf-textrun"));
        }
        let total = total_words.saturating_add(bodies.len());
        if total > MAX_REDACTION_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: total,
                max: MAX_REDACTION_SEGMENTS,
            });
        }
        let mut segments = Vec::with_capacity(total);
        let mut leaves = Vec::with_capacity(total);
        let mut gidx = 0u32;

        // ── Range 1: words, ids `0..W-1` ──────────────────────────────────────
        // Redactable, and deliberately a contiguous prefix (RFC-0001 Q3): "may
        // this id be hidden?" becomes `id < W`, a bound check rather than a
        // per-row kind lookup a future call site could forget to perform.
        for co in &objs {
            for &(s, e, _kind) in &co.words {
                let id_be = gidx.to_be_bytes();
                let leaf = redaction_leaf_for_segment(
                    &id_be,
                    &co.content[s..e],
                    blind_secret,
                    content_hash.as_bytes(),
                );
                leaves.push(leaf);
                segments.push(Segment {
                    segment_id: gidx,
                    label: None,
                    generation: 0,
                    byte_offset: 0, // re-emit format: real span from apply_with_spans
                    byte_length: (e - s) as u64,
                    leaf_hex: fr_to_hex(leaf),
                });
                gidx += 1;
            }
        }

        // ── Range 2: containers, ids `W..N-1` ─────────────────────────────────
        // One leaf per object, so every byte of every object is covered by
        // exactly one leaf. Without these the format commits words and says
        // nothing about the document they sit in — the gap RFC-0001 closes, and
        // the reason both offline verifiers refuse `pdf-textrun` today.
        for (&obj_id, (generation, body)) in &bodies {
            let preimage = match by_id.get(&obj_id) {
                Some(co) => co
                    .skeleton()
                    .ok_or_else(|| malformed("skeleton elision spans out of range"))?,
                // A non-content object is copied into the artifact verbatim, so
                // its leaf is the same primitive `pdf-xref-stream` uses over the
                // same bytes — reused rather than reimplemented, so the verifier
                // can reuse its span recovery too.
                None => body.clone(),
            };
            let id_be = gidx.to_be_bytes();
            let leaf = redaction_leaf_for_segment(
                &id_be,
                &preimage,
                blind_secret,
                content_hash.as_bytes(),
            );
            leaves.push(leaf);
            segments.push(Segment {
                segment_id: gidx,
                label: Some(if by_id.contains_key(&obj_id) {
                    format!("skeleton of object {obj_id}")
                } else {
                    format!("object {obj_id}")
                }),
                generation: *generation,
                byte_offset: 0,
                byte_length: preimage.len() as u64,
                leaf_hex: fr_to_hex(leaf),
            });
            gidx += 1;
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

        // Container leaves bind the document; they are not hideable. Because
        // words occupy `0..W-1` and containers `W..N-1` (RFC-0001 Q3), the guard
        // is a bound check against the word count rather than a per-row kind
        // lookup — one comparison that cannot be forgotten, in the same spirit as
        // the structural-object guard on the object formats.
        //
        // Derived from the MANIFEST, not from `bytes`. `bytes` and `manifest` are
        // independent arguments with no binding check between them, so computing
        // the boundary as `segments.len() - bodies.len()` would let a caller
        // supplying an artifact with fewer logical objects inflate the word count
        // until container ids passed the guard as words. The desync is caught
        // downstream, but a guard billed as the one comparison that cannot be
        // forgotten should not rest on an input it never validates.
        //
        // `extract` leaves `label` unset for words and always sets it for
        // containers, so the boundary is the first labelled segment — and the
        // prefix property is asserted rather than assumed, since it is the thing
        // that makes a bound check equivalent to a per-row kind test.
        let word_count = manifest
            .segments
            .iter()
            .position(|s| s.label.is_some())
            .unwrap_or(manifest.segments.len()) as u32;
        if manifest.segments[word_count as usize..]
            .iter()
            .any(|s| s.label.is_none())
        {
            return Err(malformed(
                "manifest segments are not partitioned into a word prefix and a container suffix",
            ));
        }
        if let Some(&id) = redacted_ids.iter().find(|&&id| id >= word_count) {
            return Err(SegmentError::StructuralObject {
                id,
                kind: "container leaf (skeleton/object) — binds the document, not hideable",
            });
        }

        // Re-emit each content object with its redacted words replaced by the
        // placeholder token; record EVERY word's (obj_id, generation, offset
        // within the new object body) — revealed words at their own bytes,
        // redacted words at the placeholder's bytes (`reemit`).
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
            for (li, &(off, len)) in content_spans.iter().enumerate() {
                word_pos.insert(
                    base + li as u32,
                    (co.obj_id, co.generation, data_off + off, len),
                );
            }
            gidx += co.words.len() as u32;
        }

        // No object-level redaction — the content is already blanked in new_bodies.
        let (artifact, obj_spans) =
            rebuild_traditional_with_spans(&new_bodies, &HashSet::new(), root_ref.as_deref())?;
        let obj_off: BTreeMap<u32, u64> = obj_spans.iter().map(|&(id, off, _)| (id, off)).collect();
        let obj_span: BTreeMap<u32, (u64, u64)> = obj_spans
            .iter()
            .map(|&(id, off, len)| (id, (off, len)))
            .collect();

        // Container segments come after the words, in obj-id ascending order, so
        // range 2 of the id sequence maps onto `new_bodies`' key order. Each one's
        // artifact span is its whole framed `N G obj … endobj` extent: the
        // verifier slices that, strips the framing, and either recomputes the
        // skeleton from it or takes the body as the object leaf.
        let container_at: BTreeMap<u32, u32> = new_bodies
            .keys()
            .enumerate()
            .map(|(i, &obj_id)| (word_count + i as u32, obj_id))
            .collect();

        let mut spans = Vec::with_capacity(manifest.segments.len());
        for seg in &manifest.segments {
            if let Some(&obj_id) = container_at.get(&seg.segment_id) {
                let &(off, len) = obj_span
                    .get(&obj_id)
                    .ok_or_else(|| malformed("container object missing from artifact"))?;
                spans.push(SegmentSpan {
                    segment_id: seg.segment_id,
                    artifact_offset: off,
                    artifact_length: len,
                });
                continue;
            }
            let span = match word_pos.get(&seg.segment_id) {
                // revealed word: its bytes sit at obj_header + body_offset in the
                // artifact. Redacted word: same, but body_off/len point at the
                // REDACTED_WORD_TOKEN placeholder rather than the original bytes
                // — the committed leaf_hex stays authoritative for a redacted
                // segment, but the span is now real (not a vacuous (0, 0)) so a
                // downstream check can confirm the region holds the placeholder.
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
                // Unreachable in normal operation: extract() and this method both
                // derive their word indexing from the same content_objects() walk
                // over the same input bytes, so every manifest segment_id has a
                // word_pos entry. Reject rather than emit a vacuous (0, 0) span —
                // that span is exactly the uninspectable-by-construction shape
                // this fix removes, so silently falling back to it here would
                // reopen the same gap on a future desync instead of failing closed.
                None => {
                    return Err(malformed(
                        "manifest segment missing from produced artifact spans",
                    ));
                }
            };
            spans.push(span);
        }
        Ok((artifact, spans))
    }
}

/// A word's decoded text for the producer UI, or `None` if it does not decode
/// to printable text.
///
/// A **literal** word carries PDF string escapes; a **hex** word is hex digit
/// pairs. Both are decoded here so the UI shows the glyphs the reader sees
/// rather than the source bytes. Presentation only — the leaf is over the raw
/// committed bytes either way.
///
/// The literal escapes are the full PDF set (ISO 32000-1 §7.3.4.2): `\n \r \t
/// \b \f` render as a space, `\ooo` is a 1–3 digit **octal** byte, and any
/// other escaped byte stands for itself (covering `\( \) \\`). Octal is not
/// optional decoration — a producer that emits `\101` for `A` is common, and
/// treating the digits as literal text would show the operator `101` where the
/// page reads `A`, which is exactly the misidentification this listing exists
/// to prevent.
///
/// `out` only ever receives `is_ascii_graphic()` bytes or a space, so it is pure
/// ASCII and `out.len()` is its character count.
fn word_text(bytes: &[u8], kind: WordKind) -> Option<String> {
    let mut out = String::new();
    let push = |out: &mut String, c: u8| {
        if c.is_ascii_graphic() || c == b' ' {
            out.push(c as char);
        }
    };
    match kind {
        WordKind::Literal => {
            let mut i = 0usize;
            while i < bytes.len() && out.len() < WORD_TEXT_CHARS {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    match bytes[i + 1] {
                        b'n' | b'r' | b't' | b'b' | b'f' => {
                            out.push(' ');
                            i += 2;
                        }
                        b'0'..=b'7' => {
                            // `\ooo`, 1 to 3 octal digits, high-order overflow
                            // ignored per the spec. Consume only the digits that
                            // are actually there — `\5` is legal.
                            let mut val: u32 = 0;
                            let mut j = i + 1;
                            while j < bytes.len()
                                && j - i <= 3
                                && bytes[j].is_ascii_digit()
                                && bytes[j] < b'8'
                            {
                                val = val * 8 + u32::from(bytes[j] - b'0');
                                j += 1;
                            }
                            push(&mut out, val as u8);
                            i = j;
                        }
                        // `\(`, `\)`, `\\` and any other escaped byte stands for
                        // itself. A `\`-newline line continuation lands here and
                        // contributes nothing, which is correct.
                        c => {
                            push(&mut out, c);
                            i += 2;
                        }
                    }
                } else {
                    push(&mut out, bytes[i]);
                    i += 1;
                }
            }
        }
        WordKind::Hex => {
            // Odd trailing digit is padded with `0` per the PDF spec; a
            // non-hex byte means this is not text we can show.
            let digits: Vec<u8> = bytes.iter().copied().filter(|b| !is_ws(*b)).collect();
            if !digits.iter().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            for pair in digits.chunks(2) {
                if out.len() >= WORD_TEXT_CHARS {
                    break;
                }
                let hi = (pair[0] as char).to_digit(16)?;
                let lo = pair
                    .get(1)
                    .map_or(0, |&b| (b as char).to_digit(16).unwrap_or(0));
                push(&mut out, (hi * 16 + lo) as u8);
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Describe every committed segment of a `pdf-textrun` document for the producer
/// UI (ADR-0029 Phase B-3, backend half).
///
/// **Presentation only** — recomputed on demand from the uploaded bytes, never
/// persisted, never part of the commitment (ADR-0029 §A), exactly like
/// [`crate::zk::pdf_describe`] for the object formats.
///
/// The id assignment here MUST match [`PdfTextRunSegmenter::extract`]'s: words
/// first in content-object then stream order, then one container per logical
/// object in obj-id-ascending order. That is why this function lives next to
/// `extract` rather than in `pdf_describe` — the two loops are meant to be read
/// together, and a change to one that misses the other silently mislabels every
/// row. The API layer additionally asserts the described id set equals the
/// committed set, so a drift fails closed instead of showing wrong text.
pub fn describe_segments(bytes: &[u8]) -> Result<Vec<SegmentDescription>, SegmentError> {
    let bodies = logical_objects(bytes)?;
    // One cumulative inflate budget across every content stream (audit A1-02).
    let mut remaining = MAX_INFLATE;
    let objs = content_objects(&bodies, &mut remaining);

    let dicts: BTreeMap<u32, &[u8]> = bodies
        .iter()
        .map(|(&id, (_generation, body))| (id, dict_region(body.as_slice())))
        .collect();
    let page_of = resolve_pages(&dicts);

    let by_id: BTreeMap<u32, &ContentObj> = objs.iter().map(|co| (co.obj_id, co)).collect();
    let total_words: usize = objs.iter().map(|co| co.words.len()).sum();
    let mut out = Vec::with_capacity(total_words + bodies.len());
    let mut gidx = 0u32;

    // ── Range 1: words, ids `0..W-1` ──────────────────────────────────────────
    for co in &objs {
        for &(s, e, kind) in &co.words {
            out.push(SegmentDescription {
                segment_id: gidx,
                kind: "word",
                redactable: true,
                obj_id: co.obj_id,
                page: page_of.get(&co.obj_id).copied(),
                text: word_text(&co.content[s..e], kind),
                byte_length: (e - s) as u64,
            });
            gidx += 1;
        }
    }

    // ── Range 2: containers, ids `W..N-1` ─────────────────────────────────────
    for (&obj_id, (_generation, body)) in &bodies {
        // `byte_length` is the committed preimage's length, matching what
        // `extract` records — for a skeleton that is the length-prefixed run
        // encoding, not the object body, and reporting the body here would
        // disagree with the manifest the UI is listing.
        let (kind, byte_length) = match by_id.get(&obj_id) {
            Some(co) => (
                "skeleton",
                co.skeleton()
                    .ok_or_else(|| malformed("skeleton elision spans out of range"))?
                    .len() as u64,
            ),
            None => ("object", body.len() as u64),
        };
        out.push(SegmentDescription {
            segment_id: gidx,
            kind,
            redactable: false,
            obj_id,
            page: page_of.get(&obj_id).copied(),
            text: None,
            byte_length,
        });
        gidx += 1;
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

    const SECRET: &[u8] = &[0x5au8; 32];

    fn words_of<'a>(content: &'a [u8], ranges: &[(usize, usize, WordKind)]) -> Vec<&'a [u8]> {
        ranges.iter().map(|&(s, e, _)| &content[s..e]).collect()
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
            .map(|(i, &(s, e, _))| leaf(i, &c[s..e]))
            .collect();

        // redact the 2nd and 4th words ("ALPHA", "BETA")
        let redacted: HashSet<usize> = [1usize, 3].into_iter().collect();
        let (art, spans) = reemit(c, &words, &redacted);
        let (art2, _) = reemit(c, &words, &redacted);
        assert_eq!(art, art2, "re-emit is byte-deterministic");

        // ROUND-TRIP: every revealed word recomputes its committed leaf from its
        // span; every redacted word's span is real and points at the placeholder.
        for (i, &(s, e, _)) in words.iter().enumerate() {
            let (off, len) = spans[i];
            if redacted.contains(&i) {
                assert_eq!(
                    &art[off..off + len],
                    REDACTED_WORD_TOKEN,
                    "redacted word's span holds the placeholder token"
                );
                continue;
            }
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
        for (i, &(s, e, _)) in words.iter().enumerate() {
            if redacted.contains(&i) {
                continue;
            }
            let (off, len) = content_spans[i];
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
        // RFC-0001: the leaf set is a PARTITION of the artifact, not just words.
        // Five words plus one container leaf per object (4 objects in this PDF —
        // the xref stream itself is not a logical object).
        assert_eq!(m.segments.len(), 9, "5 words + 4 container leaves");
        assert_eq!(
            m.segments.iter().map(|s| s.segment_id).collect::<Vec<_>>(),
            (0..9).collect::<Vec<_>>(),
            "ids stay a dense 0..N-1 sequence"
        );
        // Words occupy the contiguous prefix (RFC-0001 Q3), containers the rest.
        assert!(
            m.segments[..5].iter().all(|s| s.label.is_none()),
            "words carry no container label"
        );
        assert!(
            m.segments[5..]
                .iter()
                .all(|s| s.label.as_deref().is_some_and(
                    |l| l.starts_with("skeleton of object ") || l.starts_with("object ")
                )),
            "containers are labelled as skeleton/object leaves"
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
            // Container leaves are checked separately below — they reproduce from
            // a whole object span, not from a word's bytes.
            if seg.segment_id >= 5 {
                continue;
            }
            if seg.segment_id == 1 || seg.segment_id == 3 {
                let s = span.artifact_offset as usize;
                let e = s + span.artifact_length as usize;
                assert_eq!(
                    &artifact[s..e],
                    REDACTED_WORD_TOKEN,
                    "redacted word's real span holds the placeholder token"
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

        // ── The property RFC-0001 exists for ─────────────────────────────────
        // Every container leaf must recompute from the REDACTED artifact using
        // only bytes the verifier can re-derive. This is what makes the bundle
        // say "this artifact is the committed document with exactly these words
        // destroyed" rather than merely "these words hash to these leaves".
        //
        // A skeleton leaf is the load-bearing case: it was committed at ingest
        // over the ORIGINAL content, and it has to still reproduce after two
        // words changed length and `/Length` changed with them.
        let mut checked_skeleton = false;
        for seg in m.segments.iter().filter(|s| s.segment_id >= 5) {
            let span = spans
                .iter()
                .find(|s| s.segment_id == seg.segment_id)
                .unwrap();
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
            let framed = &artifact[s..e];
            // Strip the `N G obj\n … \nendobj` framing to reach the body, exactly
            // as the offline verifier does for `pdf-xref-stream`.
            let bo = find(framed, b"obj").unwrap() + 3;
            let eo = rfind(framed, b"endobj").unwrap();
            let body = {
                let (mut lo, mut hi) = (bo, eo);
                while lo < hi && is_ws(framed[lo]) {
                    lo += 1;
                }
                while hi > lo && is_ws(framed[hi - 1]) {
                    hi -= 1;
                }
                &framed[lo..hi]
            };

            // Re-derive the preimage from the artifact alone.
            let preimage = match decode_content_stream(body, &mut MAX_INFLATE.clone()) {
                Some(content) if !word_ranges(&content).is_empty() => {
                    checked_skeleton = true;
                    let words = word_ranges(&content);
                    let data_off = find(body, b"stream").unwrap() + b"stream\n".len();
                    let mut elided = vec![length_value_span(body).unwrap()];
                    for &(ws, we, _) in &words {
                        elided.push((data_off + ws, data_off + we));
                    }
                    elided.sort_unstable();
                    skeleton_preimage(body, &elided).unwrap()
                }
                _ => body.to_vec(),
            };

            let id_be = seg.segment_id.to_be_bytes();
            let content = content_scalar(&id_be, &preimage);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, seg.leaf_hex,
                "container leaf {} reproduces from the redacted artifact",
                seg.segment_id
            );
        }
        assert!(
            checked_skeleton,
            "the content object's skeleton leaf must have been exercised"
        );
    }

    #[test]
    fn a_skeleton_leaf_actually_binds_the_container() {
        // The reproduction test above would ALSO pass if `skeleton()` returned a
        // constant: ingest and the check run the same code over the same bytes,
        // so it proves agreement, not binding. This is the other direction —
        // mutate a byte that is neither a word nor the `/Length` value, and the
        // container leaf must stop reproducing.
        //
        // `72 720 Td` -> `72 700 Td` is a coordinate change: same word set, same
        // byte length, and it visibly moves the text on the page. Exactly the
        // edit the module header claims a skeleton catches.
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td (public secret) Tj ET");
        let m = PdfTextRunSegmenter.extract(&pdf, SECRET).unwrap();
        let (artifact, spans) = PdfTextRunSegmenter
            .apply_redaction_with_spans(&pdf, &m, &[1])
            .unwrap();

        let content_hash = blake3::hash(&pdf);
        let word_count = m.segments.iter().filter(|s| s.label.is_none()).count() as u32;
        let skeleton_seg = m
            .segments
            .iter()
            .find(|s| {
                s.label
                    .as_deref()
                    .is_some_and(|l| l.starts_with("skeleton of object "))
            })
            .expect("a skeleton leaf exists");
        assert!(skeleton_seg.segment_id >= word_count);
        let span = spans
            .iter()
            .find(|s| s.segment_id == skeleton_seg.segment_id)
            .unwrap();

        // Tamper INSIDE the committed object, on a non-word, non-/Length byte.
        let mut tampered = artifact.clone();
        let s = span.artifact_offset as usize;
        let e = s + span.artifact_length as usize;
        let rel = find(&tampered[s..e], b"720").expect("the Td coordinate is in this object");
        tampered[s + rel + 1] = b'0'; // 720 -> 700

        let recompute = |art: &[u8]| {
            let framed = &art[s..e];
            let bo = find(framed, b"obj").unwrap() + 3;
            let eo = rfind(framed, b"endobj").unwrap();
            let (mut lo, mut hi) = (bo, eo);
            while lo < hi && is_ws(framed[lo]) {
                lo += 1;
            }
            while hi > lo && is_ws(framed[hi - 1]) {
                hi -= 1;
            }
            let body = &framed[lo..hi];
            let content = decode_content_stream(body, &mut MAX_INFLATE.clone()).unwrap();
            let data_off = find(body, b"stream").unwrap() + b"stream\n".len();
            let mut elided = vec![length_value_span(body).unwrap()];
            for &(ws, we, _) in &word_ranges(&content) {
                elided.push((data_off + ws, data_off + we));
            }
            elided.sort_unstable();
            let preimage = skeleton_preimage(body, &elided).unwrap();
            let id_be = skeleton_seg.segment_id.to_be_bytes();
            let c = content_scalar(&id_be, &preimage);
            let bl = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            fr_to_hex(redaction_leaf(&c, &bl).unwrap())
        };

        // The untampered artifact still reproduces...
        assert_eq!(recompute(&artifact), skeleton_seg.leaf_hex);
        // ...and one moved coordinate breaks it. Without this the "binds every
        // operator, coordinate, dictionary entry" claim is untested.
        assert_ne!(
            recompute(&tampered),
            skeleton_seg.leaf_hex,
            "a moved Td coordinate must break the skeleton leaf"
        );
    }

    #[test]
    fn describe_segments_lines_up_with_the_committed_manifest() {
        // `describe_segments` reimplements `extract`'s two-range id walk. Word
        // ids are POSITIONAL, so a drift between the two would not drop rows —
        // it would slide every label onto the wrong word, and the UI would
        // cheerfully offer "redact `alpha`" for a checkbox wired to `beta`.
        // Assert the alignment against the manifest rather than trusting that
        // the two loops were kept in step.
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td (alpha beta) Tj ET");
        let m = PdfTextRunSegmenter.extract(&pdf, SECRET).unwrap();
        let d = describe_segments(&pdf).unwrap();

        // Same rows, same order, same committed lengths.
        assert_eq!(d.len(), m.segments.len());
        for (row, seg) in d.iter().zip(&m.segments) {
            assert_eq!(row.segment_id, seg.segment_id);
            assert_eq!(row.byte_length, seg.byte_length);
        }

        // The word rows carry the right text at the right ids — the off-by-one
        // this test exists to catch.
        let words: Vec<_> = d.iter().filter(|r| r.kind == "word").collect();
        assert_eq!(
            words.iter().map(|r| r.text.as_deref()).collect::<Vec<_>>(),
            [Some("alpha"), Some("beta")]
        );
        assert!(words.iter().all(|r| r.redactable));
        assert!(
            words.iter().all(|r| r.page == Some(1)),
            "words resolve to their page"
        );

        // `redactable` is exactly the RFC-0001 word prefix — the same boundary
        // `apply_redaction_with_spans` enforces, so the UI cannot offer a
        // container leaf the redact call will reject.
        let word_count = m.segments.iter().filter(|s| s.label.is_none()).count();
        assert_eq!(words.len(), word_count);
        assert!(
            d.iter()
                .all(|r| r.redactable == ((r.segment_id as usize) < word_count)),
            "redactable must be the id < W bound check, not a per-row guess"
        );

        // Containers describe themselves as such and never leak text.
        let containers: Vec<_> = d.iter().filter(|r| r.kind != "word").collect();
        assert!(!containers.is_empty());
        assert!(containers.iter().all(|r| r.text.is_none() && !r.redactable));
        assert_eq!(
            containers.iter().filter(|r| r.kind == "skeleton").count(),
            1,
            "exactly one content object, so exactly one skeleton row"
        );
    }

    #[test]
    fn describe_decodes_hex_words_and_literal_escapes() {
        // The UI shows glyphs, not source bytes: a hex operand is one word whose
        // committed bytes are hex digits, and a literal word can carry `\(`
        // escapes. Both must render as the text a reader would see, or the
        // operator picks the wrong word to hide.
        assert_eq!(
            word_text(b"48656c6c6f", WordKind::Hex).as_deref(),
            Some("Hello")
        );
        assert_eq!(
            word_text(b"a\\(b\\)c", WordKind::Literal).as_deref(),
            Some("a(b)c")
        );
        // Octal escapes. `\101` is `A`; decoding it as literal digits would show
        // the operator `101` where the page reads `A`. 1- and 2-digit forms are
        // legal too, and a digit outside the escape must stay a digit.
        assert_eq!(word_text(b"\\101", WordKind::Literal).as_deref(), Some("A"));
        assert_eq!(
            word_text(b"\\1012", WordKind::Literal).as_deref(),
            Some("A2"),
            "only three octal digits are consumed"
        );
        assert_eq!(
            word_text(b"\\1018", WordKind::Literal).as_deref(),
            Some("A8"),
            "8 is not an octal digit and ends the escape"
        );
        assert_eq!(
            word_text(b"\\63x", WordKind::Literal).as_deref(),
            Some("3x"),
            "a two-digit octal escape is legal"
        );
        // `\b` / `\f` are whitespace-ish controls, not the letters b and f.
        assert_eq!(
            word_text(b"a\\bb", WordKind::Literal).as_deref(),
            Some("a b")
        );
        // Not hex → no text rather than mojibake.
        assert_eq!(word_text(b"zz", WordKind::Hex), None);
    }

    #[test]
    fn a_width_compensating_kern_breaks_the_skeleton_leaf() {
        // Width-preserving redaction wants to follow a redacted word with a `TJ`
        // adjustment that buys back the advance its destruction token lost, so
        // the rest of the line does not reflow. RFC-0001's skeleton commits the
        // canonical body with ONLY the word spans and the `/Length` value elided
        // — every other byte verbatim — so an adjustment inserted at redaction
        // time lands inside a committed run and the skeleton stops reproducing.
        //
        // That makes the width-preserving move a FORMAT change, not a
        // redaction-time detail. Asserted rather than argued: the module header
        // and `docs/plans/visual-box-redaction.md` both said the blocker was font
        // `/Widths`, which understated it.
        let content: &[u8] = b"BT /F1 12 Tf 72 720 Td [(public) 0 (secret)] TJ ET";

        // Exactly what `ContentObj::skeleton` does, over whatever content it is
        // handed — so the control and the variant are measured the same way.
        let skeleton_of = |c: &[u8]| -> Vec<u8> {
            let (body, data_off) = reemit_content_object(c);
            let mut elided = vec![length_value_span(&body).expect("a canonical /Length")];
            for &(s, e, _) in &word_ranges(c) {
                elided.push((data_off + s, data_off + e));
            }
            elided.sort_unstable();
            skeleton_preimage(&body, &elided).expect("in-range elision spans")
        };
        let committed = skeleton_of(content);

        // Control: today's fixed-token redaction. `secret` (6 bytes) becomes
        // `REDACTED` (8), so the body and its `/Length` both change — and the
        // skeleton still reproduces, because both are elided. Without this leg
        // the test below would not distinguish "kerning breaks it" from
        // "redaction breaks it".
        let words = word_ranges(content);
        let secret = words
            .iter()
            .position(|&(s, e, _)| &content[s..e] == b"secret")
            .expect("the word to redact");
        let (redacted, _) = reemit(content, &words, &HashSet::from([secret]));
        assert!(find(&redacted, REDACTED_WORD_TOKEN).is_some());
        assert_eq!(
            skeleton_of(&redacted),
            committed,
            "the shipped fixed-token redaction must still reproduce the skeleton"
        );

        // The variant: the same redaction plus the compensating adjustment a
        // `/Widths`-driven implementation would emit into the `TJ` array.
        let close = find(&redacted, b"(REDACTED)").expect("the token's array element")
            + b"(REDACTED)".len();
        let mut kerned = redacted.clone();
        kerned.splice(close..close, b" -1234".iter().copied());
        // The tokenizer still sees the same two words, so the difference is not
        // an accidental change to the word set — it is the adjustment bytes
        // landing in a committed skeleton run.
        assert_eq!(
            words_of(&kerned, &word_ranges(&kerned)),
            [&b"public"[..], REDACTED_WORD_TOKEN]
        );
        assert_ne!(
            skeleton_of(&kerned),
            committed,
            "a width-compensating TJ adjustment must break the skeleton leaf — \
             which is why width preservation needs the adjustment slot committed \
             at ingest, not inserted at redaction time"
        );
    }

    #[test]
    fn length_value_span_does_not_match_length1() {
        // `/Length1` / `/Length2` are real font-descriptor keys sharing the
        // prefix. A bare substring match stops on the `1` and elides that digit,
        // leaving the real `/Length` committed — which would diverge the moment
        // this is ported into the offline verifiers over arbitrary bodies.
        let body = b"<< /Length1 42 /Length 7 >>stream\nabc\nendstream";
        let (s, e) = length_value_span(body).expect("finds the real /Length");
        assert_eq!(&body[s..e], b"7");

        // Order-independent: the real key first still resolves to the real value.
        let other = b"<< /Length 7 /Length1 42 >>";
        let (s2, e2) = length_value_span(other).unwrap();
        assert_eq!(&other[s2..e2], b"7");

        // A prefix-only match with no true `/Length` is not a match at all.
        assert!(length_value_span(b"<< /Length1 42 >>").is_none());
    }

    #[test]
    fn skeleton_preimage_rejects_malformed_elision_lists() {
        // Ported into the verifiers this runs on attacker-supplied bytes, where a
        // panic is a denial of service rather than a rejection.
        let body = b"abcdefghij";
        assert!(
            skeleton_preimage(body, &[(2, 4), (3, 6)]).is_none(),
            "overlapping"
        );
        assert!(
            skeleton_preimage(body, &[(6, 8), (2, 4)]).is_none(),
            "unsorted"
        );
        assert!(
            skeleton_preimage(body, &[(2, 99)]).is_none(),
            "out of range"
        );
        assert!(skeleton_preimage(body, &[(5, 3)]).is_none(), "inverted");
        assert!(
            skeleton_preimage(body, &[(2, 4), (4, 6)]).is_some(),
            "abutting is fine"
        );
    }

    #[test]
    fn hex_show_strings_are_words_and_redact_to_valid_hex() {
        // Before RFC-0001 a hex operand was skipped entirely: no leaf covered it
        // and no span inspected it, so a producer could re-show "redacted" text
        // through `<48656c6c6f> Tj`. That was documented as fail-soft; measured
        // against a redaction claim it was a bypass.
        let c = b"BT /F1 12 Tf <48656c6c6f> Tj (plain word) Tj ET";
        let words = word_ranges(c);
        let kinds: Vec<WordKind> = words.iter().map(|&(_, _, k)| k).collect();
        assert_eq!(
            kinds,
            vec![WordKind::Hex, WordKind::Literal, WordKind::Literal],
            "the whole hex string is one word; the literal splits on whitespace"
        );
        assert_eq!(&c[words[0].0..words[0].1], b"48656c6c6f");

        // Its destruction token must stay valid hex AND the same length, so the
        // string cannot reflow and cannot become unparseable.
        let redacted: HashSet<usize> = [0usize].into_iter().collect();
        let (art, spans) = reemit(c, &words, &redacted);
        let (off, len) = spans[0];
        assert_eq!(&art[off..off + len], b"0000000000");
        assert_eq!(len, 10, "length-preserving: no reflow");
        assert!(!art.windows(10).any(|w| w == b"48656c6c6f"));
    }

    #[test]
    fn container_leaves_are_not_redactable() {
        // They bind the document; hiding one would blank a whole object and, for
        // a skeleton, destroy the very thing that proves the container intact.
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td (alpha beta) Tj ET");
        let m = PdfTextRunSegmenter.extract(&pdf, SECRET).unwrap();
        let first_container = 2u32; // 2 words → ids 0,1 are words; 2.. are containers
        let err = PdfTextRunSegmenter
            .apply_redaction_with_spans(&pdf, &m, &[first_container])
            .unwrap_err();
        assert!(
            matches!(err, SegmentError::StructuralObject { id, .. } if id == first_container),
            "expected a structural-object rejection, got {err:?}"
        );
        // A word is still redactable — the guard is a bound, not a blanket ban.
        assert!(PdfTextRunSegmenter
            .apply_redaction_with_spans(&pdf, &m, &[0])
            .is_ok());
    }

    #[test]
    fn skeleton_preimage_pins_elision_positions_and_count() {
        // Two properties the length-prefixed run encoding buys over an in-band
        // marker byte (RFC-0001 Q2).
        let body = b"abcXXdefYYghi";
        // Sliding an elision along the body changes the leaf preimage...
        let a = skeleton_preimage(body, &[(3, 5), (8, 10)]).unwrap();
        let b = skeleton_preimage(body, &[(4, 6), (8, 10)]).unwrap();
        assert_ne!(a, b, "elision positions are pinned by the run lengths");
        // ...and so does changing how many there are.
        let c = skeleton_preimage(body, &[(3, 5)]).unwrap();
        assert_ne!(a, c, "elision count is pinned by the run count");

        // A body containing the byte an in-band marker would have used is not
        // special in any way — the question of marker collisions cannot arise.
        let with_nul = b"abc\x00def";
        assert_eq!(
            skeleton_preimage(with_nul, &[]).unwrap(),
            [&(with_nul.len() as u32).to_be_bytes()[..], with_nul].concat(),
            "no byte value is reserved"
        );
    }

    #[test]
    fn segment_document_word_granularity_selects_word_level_for_text_pdf() {
        // ADR-0029 Phase B (opt-in): a caller that requests `Word` granularity
        // routes a text-bearing PDF to the word-run segmenter through the shared
        // ingest entry point, not the object scheme — so a single word becomes
        // independently redactable.
        use crate::zk::segment::RedactionGranularity;
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td (alpha beta gamma) Tj ET");
        let m = crate::zk::segment::segment_document_with(&pdf, SECRET, RedactionGranularity::Word)
            .unwrap();
        assert_eq!(
            m.format,
            SegmentFormat::PdfTextRun,
            "Word granularity commits a text PDF at word granularity"
        );
        // 3 words + one container leaf per object (RFC-0001 partition).
        assert_eq!(m.segments.len(), 7, "3 words + 4 container leaves");
    }

    #[test]
    fn segment_document_default_granularity_stays_object_for_text_pdf() {
        // Default (`Object`) granularity is *not* auto-promoted to word-level even
        // for a text-bearing PDF — word-level is strictly opt-in (ADR-0029 B1,
        // revised). The same PDF that `Word` cuts into words commits as an object.
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td (alpha beta gamma) Tj ET");
        let m = crate::zk::segment::segment_document(&pdf, SECRET).unwrap();
        assert_ne!(
            m.format,
            SegmentFormat::PdfTextRun,
            "default granularity never auto-selects word-level"
        );
        assert_eq!(m.format, SegmentFormat::PdfXrefStream);
    }

    #[test]
    fn segment_document_word_granularity_falls_back_to_object_for_textless_pdf() {
        // Requesting `Word` on a PDF with no extractable text runs (< 2) fails
        // closed to the object scheme — opting into word-level never regresses a
        // PDF the object path already handled.
        use crate::zk::segment::RedactionGranularity;
        let pdf = build_text_pdf(b"BT /F1 12 Tf 72 720 Td ET");
        let m = crate::zk::segment::segment_document_with(&pdf, SECRET, RedactionGranularity::Word)
            .unwrap();
        assert_ne!(
            m.format,
            SegmentFormat::PdfTextRun,
            "no text runs → fall back to an object scheme"
        );
        // build_text_pdf is a modern (xref-stream) PDF, so the fallback is the
        // modern object segmenter.
        assert_eq!(m.format, SegmentFormat::PdfXrefStream);
    }
}
