//! Modern-PDF (PDF 1.5+) cross-reference-stream + object-stream segmenter
//! (ADR-0028).
//!
//! Where [`crate::zk::pdf_objects`] handles *traditional* `xref` tables with
//! in-place NUL-fill, this handles the compressed forms modern tooling emits:
//! **cross-reference streams** (a FlateDecode'd, optionally PNG-predicted binary
//! table) and **object streams** (`ObjStm` — many objects DEFLATE-packed into
//! one). Objects inside an `ObjStm` have no independent file byte range, so the
//! leaf binds each object's **logical body** (the trimmed bytes that *are* the
//! object's content) rather than a file span, and redaction rebuilds the PDF in
//! a normalised traditional-xref form with redacted bodies blanked (the
//! "container rebuild" model — ADR-0028 §2).
//!
//! Pure-Rust byte parsing + `flate2` (miniz_oxide backend) only — no renderer,
//! no native lib.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;

use olympus_crypto::redaction::{content_scalar, derive_blinding, redaction_leaf};

use crate::zk::chunk::fr_to_hex;
use crate::zk::segment::{
    variable_depth_fold_root, variable_geometry, Segment, SegmentError, SegmentFormat,
    SegmentManifest, SegmentSpan, Segmenter, MAX_INFLATE, MAX_REDACTION_SEGMENTS,
};

/// The modern-PDF [`Segmenter`].
pub struct ModernPdfSegmenter;

fn malformed(detail: impl Into<String>) -> SegmentError {
    SegmentError::Malformed {
        format: "pdf-xref-stream",
        detail: detail.into(),
    }
}

// ── tiny byte helpers ─────────────────────────────────────────────────────────

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c | 0x00)
}

/// Read a base-10 unsigned int starting at `i` (skipping leading whitespace).
/// Returns the value and the index just past the digits.
fn read_uint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    while i < b.len() && is_ws(b[i]) {
        i += 1;
    }
    let start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&b[start..i])
        .ok()?
        .parse::<u64>()
        .ok()
        .map(|v| (v, i))
}

/// FlateDecode (zlib) `data` into at most [`MAX_INFLATE`] bytes.
fn inflate(data: &[u8]) -> Result<Vec<u8>, SegmentError> {
    let mut out = Vec::new();
    let mut dec = flate2::read::ZlibDecoder::new(data).take(MAX_INFLATE as u64 + 1);
    dec.read_to_end(&mut out)
        .map_err(|e| malformed(format!("FlateDecode failed: {e}")))?;
    if out.len() > MAX_INFLATE {
        return Err(malformed("decompressed stream exceeds size cap"));
    }
    Ok(out)
}

// ── PDF dict scanning (minimal, key-directed) ─────────────────────────────────

/// Find the balanced `<< … >>` dictionary that begins at or after `from`.
/// Returns the slice between (and excluding) the outer `<<`/`>>`.
fn dict_slice(b: &[u8], from: usize) -> Option<(usize, usize)> {
    let open = find(&b[from..], b"<<")? + from;
    let mut depth = 0usize;
    let mut i = open;
    while i + 1 < b.len() {
        if &b[i..i + 2] == b"<<" {
            depth += 1;
            i += 2;
        } else if &b[i..i + 2] == b">>" {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return Some((open + 2, i - 2));
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Read the integer immediately following `/Key` in `dict`.
fn dict_int(dict: &[u8], key: &[u8]) -> Option<u64> {
    let pos = find(dict, key)? + key.len();
    read_uint(dict, pos).map(|(v, _)| v)
}

/// Read the `[ a b c … ]` integer array following `/Key` in `dict`.
fn dict_int_array(dict: &[u8], key: &[u8]) -> Option<Vec<u64>> {
    let mut i = find(dict, key)? + key.len();
    while i < dict.len() && is_ws(dict[i]) {
        i += 1;
    }
    if i >= dict.len() || dict[i] != b'[' {
        return None;
    }
    i += 1;
    let mut out = Vec::new();
    loop {
        while i < dict.len() && is_ws(dict[i]) {
            i += 1;
        }
        if i < dict.len() && dict[i] == b']' {
            break;
        }
        let (v, ni) = read_uint(dict, i)?;
        out.push(v);
        i = ni;
    }
    Some(out)
}

/// Read the `N G R` indirect reference following `/Key` (e.g. `/Root 1 0 R`),
/// returned as the raw `"N G R"` bytes for verbatim re-emission.
fn dict_ref(dict: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let pos = find(dict, key)? + key.len();
    let (n, i1) = read_uint(dict, pos)?;
    let (g, i2) = read_uint(dict, i1)?;
    // expect `R`
    let mut j = i2;
    while j < dict.len() && is_ws(dict[j]) {
        j += 1;
    }
    if j >= dict.len() || dict[j] != b'R' {
        return None;
    }
    Some(format!("{n} {g} R").into_bytes())
}

/// `true` if `/Key` is present in `dict`.
fn dict_has(dict: &[u8], key: &[u8]) -> bool {
    find(dict, key).is_some()
}

// ── object framing ────────────────────────────────────────────────────────────

/// Parse the indirect object whose header `N G obj` is at `header_off`. Returns
/// `(dict_or_body_start, end_of_object)` where the body is everything between
/// `obj` and the matching `endobj`. Handles a `stream … endstream` payload whose
/// bytes may themselves contain `endobj`.
fn object_body_span(b: &[u8], header_off: usize) -> Option<(usize, usize)> {
    // An attacker-controlled xref offset can exceed the file length; guard the
    // slice so it returns None (→ Malformed) instead of panicking.
    if header_off > b.len() {
        return None;
    }
    let region = &b[header_off..];
    let obj_kw = find(region, b"obj")? + b"obj".len();
    let stream_kw = find(region, b"stream");
    let first_endobj = find(region, b"endobj");
    let end_rel = match (stream_kw, first_endobj) {
        (Some(s), Some(e)) if s < e => {
            let after = s + b"stream".len();
            let es = find(&region[after..], b"endstream")?;
            let after_es = after + es + b"endstream".len();
            find(&region[after_es..], b"endobj").map(|r| after_es + r)?
        }
        (_, Some(e)) => e,
        _ => return None,
    };
    Some((header_off + obj_kw, header_off + end_rel))
}

/// Trim leading/trailing ASCII whitespace — the canonical logical body the leaf
/// binds, so framing whitespace introduced by re-serialisation is irrelevant.
fn trim_body(b: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = b.len();
    while s < e && is_ws(b[s]) {
        s += 1;
    }
    while e > s && is_ws(b[e - 1]) {
        e -= 1;
    }
    &b[s..e]
}

// ── cross-reference-stream parsing ─────────────────────────────────────────────

#[derive(Clone, Copy)]
enum XrefEntry {
    /// Free.
    Free,
    /// In file at `offset` with generation `gen` (type 1). The generation is
    /// preserved so the rebuilt PDF re-emits `N G obj` / `N G R` references
    /// faithfully for objects with a non-zero generation.
    Direct { offset: u64, generation: u16 },
    /// In object stream `stream_obj`, at `index` within it (type 2). Compressed
    /// objects are always generation 0 per the PDF spec.
    InStream { stream_obj: u32, index: u32 },
}

struct XrefStream {
    entries: BTreeMap<u32, XrefEntry>,
    /// `/Root` reference bytes (for the rebuilt trailer).
    root_ref: Option<Vec<u8>>,
    /// Structural objects that physically hold OTHER objects' bytes — every
    /// `/ObjStm` container (referenced as `stream_obj` by a type-2 entry) and the
    /// cross-reference-stream object(s) themselves. These are NOT document content
    /// and MUST be excluded from the committed segments and dropped from the
    /// rebuilt artifact: re-emitting an `/ObjStm` container verbatim would leak the
    /// plaintext of any redacted member packed inside its compressed stream
    /// (CRITICAL — the contained objects are committed/redacted standalone).
    container_ids: HashSet<u32>,
}

/// Reverse a PNG "up" predictor (predictor >= 10; row filter byte per row). Only
/// the common case is implemented; other predictors error → chunk fallback.
fn undo_png_predictor(data: &[u8], columns: usize) -> Result<Vec<u8>, SegmentError> {
    if columns == 0 {
        return Err(malformed("xref predictor /Columns is zero"));
    }
    // `0usize.is_multiple_of(row)` is true, so an EMPTY decoded stream would
    // otherwise pass the row-width check below with an arbitrarily large
    // `columns` and reach `vec![0u8; columns]` (multi-GB OOM). Reject it up front.
    if data.is_empty() {
        return Err(malformed("xref predictor on empty stream"));
    }
    // `columns` is attacker-controlled (the /Columns dict int). Bound it BEFORE
    // `columns + 1` so the add can't overflow usize (→ `row` wraps to 0 →
    // `data.chunks(0)` panic) and so `vec![0u8; columns]` can't over-allocate. A
    // predictor row can't be wider than the stream it filters.
    if columns > data.len() {
        return Err(malformed("xref predictor /Columns wider than the stream"));
    }
    let row = columns + 1; // 1 filter-tag byte + `columns` data bytes
    if !data.len().is_multiple_of(row) {
        return Err(malformed("xref predictor data not a multiple of row width"));
    }
    // `columns <= data.len() <= MAX_INFLATE` bounds this allocation.
    let mut prev = vec![0u8; columns];
    let mut out = Vec::with_capacity(data.len() / row * columns);
    for chunk in data.chunks(row) {
        let tag = chunk[0];
        let mut cur = chunk[1..].to_vec();
        match tag {
            0 => {} // None
            2 => {
                // Up: add the byte above.
                for i in 0..columns {
                    cur[i] = cur[i].wrapping_add(prev[i]);
                }
            }
            _ => return Err(malformed(format!("unsupported PNG predictor filter {tag}"))),
        }
        out.extend_from_slice(&cur);
        prev = cur;
    }
    Ok(out)
}

/// Parse the cross-reference stream whose indirect object header is at
/// `header_off`. Records in-use entries; follows `/Prev` (xref streams only).
fn parse_xref_stream(b: &[u8], header_off: usize) -> Result<XrefStream, SegmentError> {
    let mut entries: BTreeMap<u32, XrefEntry> = BTreeMap::new();
    let mut root_ref: Option<Vec<u8>> = None;
    let mut container_ids: HashSet<u32> = HashSet::new();
    // Bound TOTAL distinct xref entries — in-use AND free. A crafted /Index + tiny
    // /W (e.g. [1 0 0]) over a 64 MiB stream could otherwise insert ~64M entries
    // and amplify a ~64 KiB upload into GBs of map memory. Free entries MUST be
    // recorded (so a newer section's free shadows an older in-use one — /Prev
    // first-seen-wins), so they count toward the cap too. Generous slack over the
    // MAX_REDACTION_SEGMENTS content cap (free entries are cheap); `extract`
    // enforces the precise content limit on the committed bodies, and exceeding
    // this just routes to the chunk fallback. Bounded below MAX_INFLATE regardless.
    let entry_cap = MAX_REDACTION_SEGMENTS * 16;
    let mut next = Some(header_off);
    let mut visited: HashSet<usize> = HashSet::new();

    while let Some(off) = next {
        if !visited.insert(off) {
            break; // /Prev cycle guard
        }
        if off >= b.len() {
            return Err(malformed("xref offset past end of file"));
        }
        // The xref-stream object is structural, not content — record its obj id.
        if let Some((xn, _)) = read_uint(b, off) {
            container_ids.insert(xn as u32);
        }
        let (ds, de) = dict_slice(b, off).ok_or_else(|| malformed("xref stream: no dict"))?;
        let dict = &b[ds..de];
        if !dict_has(dict, b"/XRef") {
            return Err(malformed("startxref does not point at an /XRef stream"));
        }
        let w = dict_int_array(dict, b"/W")
            .filter(|w| w.len() == 3)
            .ok_or_else(|| malformed("xref stream: bad /W"))?;
        // A cross-reference field value fits in u64 (≤ 8 bytes); reject oversized
        // widths so `row = w0+w1+w2` can't overflow `usize` and produce an
        // out-of-bounds `&rec[..]` slice panic on the per-record reads below.
        if w.iter().any(|&x| x > 8) {
            return Err(malformed("xref stream: /W field width exceeds 8 bytes"));
        }
        let size = dict_int(dict, b"/Size").ok_or_else(|| malformed("xref stream: no /Size"))?;
        let index = dict_int_array(dict, b"/Index").unwrap_or_else(|| vec![0, size]);
        if root_ref.is_none() {
            root_ref = dict_ref(dict, b"/Root");
        }

        // The stream payload: from after `stream` + EOL up to `endstream`.
        let s_kw = find(&b[de..], b"stream")
            .ok_or_else(|| malformed("xref stream: no `stream`"))?
            + de
            + b"stream".len();
        // Skip the single EOL after `stream` (CRLF or LF).
        let mut payload_start = s_kw;
        if b.get(payload_start) == Some(&b'\r') {
            payload_start += 1;
        }
        if b.get(payload_start) == Some(&b'\n') {
            payload_start += 1;
        }
        let es = find(&b[payload_start..], b"endstream")
            .ok_or_else(|| malformed("xref stream: no `endstream`"))?
            + payload_start;
        let raw = &b[payload_start..es];
        let mut decoded = inflate(raw)?;
        if let Some(pred) = dict_int(dict, b"/Predictor").filter(|&p| p >= 10) {
            let _ = pred;
            let cols = dict_int(dict, b"/Columns").unwrap_or(1) as usize;
            decoded = undo_png_predictor(&decoded, cols)?;
        }

        let (w0, w1, w2) = (w[0] as usize, w[1] as usize, w[2] as usize);
        let row = w0 + w1 + w2;
        if row == 0 {
            return Err(malformed("xref stream: zero-width /W"));
        }
        let read_field = |bytes: &[u8], width: usize, default: u64| -> u64 {
            if width == 0 {
                return default;
            }
            bytes.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)
        };

        let mut cursor = 0usize;
        for sub in index.chunks(2) {
            if sub.len() != 2 {
                break;
            }
            let (start, count) = (sub[0] as u32, sub[1]);
            for k in 0..count {
                if cursor + row > decoded.len() {
                    return Err(malformed(
                        "xref stream: entries shorter than /Index implies",
                    ));
                }
                let rec = &decoded[cursor..cursor + row];
                cursor += row;
                let f1 = read_field(&rec[0..w0], w0, 1); // type defaults to 1 when W[0]==0
                let f2 = read_field(&rec[w0..w0 + w1], w1, 0);
                let f3 = read_field(&rec[w0 + w1..row], w2, 0);
                let obj_id = start + k as u32;
                // First-seen wins (latest section parsed first), like the
                // traditional walker's `/Prev` precedence.
                if entries.contains_key(&obj_id) {
                    continue;
                }
                let entry = match f1 {
                    // type 1: f2 = byte offset, f3 = generation.
                    1 => XrefEntry::Direct {
                        offset: f2,
                        generation: f3 as u16,
                    },
                    2 => {
                        // The ObjStm that physically holds this object is a
                        // structural container — never committed/re-emitted.
                        container_ids.insert(f2 as u32);
                        XrefEntry::InStream {
                            stream_obj: f2 as u32,
                            index: f3 as u32,
                        }
                    }
                    _ => XrefEntry::Free,
                };
                // Count every distinct entry (incl. Free) toward the cap, and bail
                // before insert — this bounds map memory AND exits the record loop
                // for a flood of crafted entries.
                if entries.len() >= entry_cap {
                    return Err(SegmentError::TooManySegments {
                        found: entries.len() + 1,
                        max: MAX_REDACTION_SEGMENTS,
                    });
                }
                entries.insert(obj_id, entry);
            }
        }

        next = dict_int(dict, b"/Prev").map(|p| p as usize);
    }

    Ok(XrefStream {
        entries,
        root_ref,
        container_ids,
    })
}

// ── object-stream (ObjStm) decoding ───────────────────────────────────────────

/// Decode an `ObjStm` object at file `header_off` into `objnum -> body bytes`.
fn decode_objstm(b: &[u8], header_off: usize) -> Result<BTreeMap<u32, Vec<u8>>, SegmentError> {
    let (ds, de) = dict_slice(b, header_off).ok_or_else(|| malformed("ObjStm: no dict"))?;
    let dict = &b[ds..de];
    let n = dict_int(dict, b"/N").ok_or_else(|| malformed("ObjStm: no /N"))? as usize;
    // `/N` is read from the (uncompressed) dict and drives `Vec::with_capacity`
    // below; the MAX_INFLATE cap on the stream does NOT bound it. A single ObjStm
    // cannot legitimately hold more objects than the commitment capacity, so
    // reject an oversized count before allocating (else `/N 9999999999` → OOM).
    if n > MAX_REDACTION_SEGMENTS {
        return Err(malformed("ObjStm: /N exceeds segment capacity"));
    }
    let first = dict_int(dict, b"/First").ok_or_else(|| malformed("ObjStm: no /First"))? as usize;

    let s_kw = find(&b[de..], b"stream").ok_or_else(|| malformed("ObjStm: no `stream`"))?
        + de
        + b"stream".len();
    let mut payload_start = s_kw;
    if b.get(payload_start) == Some(&b'\r') {
        payload_start += 1;
    }
    if b.get(payload_start) == Some(&b'\n') {
        payload_start += 1;
    }
    let es = find(&b[payload_start..], b"endstream")
        .ok_or_else(|| malformed("ObjStm: no `endstream`"))?
        + payload_start;
    let decoded = inflate(&b[payload_start..es])?;
    if first > decoded.len() {
        return Err(malformed("ObjStm: /First past end of decoded stream"));
    }

    // Header: N pairs of (objnum, rel_offset).
    let mut pairs: Vec<(u32, usize)> = Vec::with_capacity(n);
    let mut i = 0usize;
    for _ in 0..n {
        let (objnum, i1) = read_uint(&decoded[..first], i)
            .ok_or_else(|| malformed("ObjStm: bad header objnum"))?;
        let (rel, i2) = read_uint(&decoded[..first], i1)
            .ok_or_else(|| malformed("ObjStm: bad header offset"))?;
        pairs.push((objnum as u32, rel as usize));
        i = i2;
    }

    let mut out = BTreeMap::new();
    for k in 0..pairs.len() {
        let (objnum, rel) = pairs[k];
        // `rel` is attacker-controlled; use checked_add so a near-usize::MAX value
        // can't wrap (release) or panic (debug) before the bounds check.
        let start = first
            .checked_add(rel)
            .ok_or_else(|| malformed("ObjStm: object offset overflow"))?;
        let end = if k + 1 < pairs.len() {
            first
                .checked_add(pairs[k + 1].1)
                .ok_or_else(|| malformed("ObjStm: object offset overflow"))?
        } else {
            decoded.len()
        };
        if start > decoded.len() || end > decoded.len() || start > end {
            return Err(malformed("ObjStm: object slice out of bounds"));
        }
        out.insert(objnum, trim_body(&decoded[start..end]).to_vec());
    }
    Ok(out)
}

// ── logical-object extraction (the leaf inputs) ────────────────────────────────

/// Parse a modern PDF into `obj_id -> (generation, trimmed logical body)` for
/// every in-use indirect object (type-1 directly in the file; type-2 inside an
/// ObjStm). Structural containers (ObjStm / xref stream) are excluded.
fn logical_objects(b: &[u8]) -> Result<BTreeMap<u32, (u16, Vec<u8>)>, SegmentError> {
    let sx = rfind(b, b"startxref").ok_or_else(|| malformed("no startxref"))?;
    let (xref_off, _) = read_uint(b, sx + b"startxref".len())
        .ok_or_else(|| malformed("no offset after startxref"))?;
    let xref = parse_xref_stream(b, xref_off as usize)?;

    // Cache decoded object streams so multiple type-2 objects in the same ObjStm
    // decode it once.
    let mut objstm_cache: BTreeMap<u32, BTreeMap<u32, Vec<u8>>> = BTreeMap::new();
    // obj_id -> (generation, trimmed logical body). Generation is preserved so the
    // rebuilt PDF re-emits `N G obj` faithfully (compressed ObjStm members are
    // always generation 0).
    let mut bodies: BTreeMap<u32, (u16, Vec<u8>)> = BTreeMap::new();

    for (&obj_id, entry) in &xref.entries {
        // Structural containers (the /ObjStm holding type-2 objects, the xref
        // stream itself) are NOT document content and must never be committed or
        // re-emitted — re-emitting an /ObjStm verbatim would carry a redacted
        // member's plaintext through inside its compressed stream (CRITICAL). The
        // contained objects are extracted standalone via their InStream entries.
        if xref.container_ids.contains(&obj_id) {
            continue;
        }
        match *entry {
            XrefEntry::Free => {}
            XrefEntry::Direct { offset, generation } => {
                let (s, e) = object_body_span(b, offset as usize)
                    .ok_or_else(|| malformed(format!("object {obj_id}: unframed at {offset}")))?;
                bodies.insert(obj_id, (generation, trim_body(&b[s..e]).to_vec()));
            }
            XrefEntry::InStream { stream_obj, index } => {
                let stream = match objstm_cache.entry(stream_obj) {
                    std::collections::btree_map::Entry::Occupied(e) => e.into_mut(),
                    std::collections::btree_map::Entry::Vacant(v) => {
                        let off = match xref.entries.get(&stream_obj) {
                            Some(XrefEntry::Direct { offset, .. }) => *offset as usize,
                            _ => {
                                return Err(malformed(format!(
                                    "ObjStm container {stream_obj} is not a direct object"
                                )))
                            }
                        };
                        v.insert(decode_objstm(b, off)?)
                    }
                };
                // `index` is positional within the ObjStm; map it to the objnum
                // via the header order (BTreeMap iteration is objnum-ascending,
                // but the ObjStm header order is authoritative). We keyed
                // `decode_objstm` by objnum, and `obj_id` IS that objnum, so look
                // up directly rather than by positional index.
                let _ = index;
                let body = stream.get(&obj_id).ok_or_else(|| {
                    malformed(format!("object {obj_id} absent from ObjStm {stream_obj}"))
                })?;
                bodies.insert(obj_id, (0, body.clone()));
            }
        }
    }
    if bodies.is_empty() {
        return Err(malformed("no in-use objects found"));
    }
    Ok(bodies)
}

// ── redaction rebuild (to traditional-xref) ────────────────────────────────────

/// Re-serialise `bodies` (obj_id → (generation, logical body)) as a normalised
/// traditional-xref PDF. Objects in `redacted` get a `null` body (content
/// destroyed; entry preserved). The output re-parses with the traditional
/// logical-body rule to the same revealed bodies, so revealed leaves recompute
/// (ADR-0028 §2). The xref is emitted as **sparse subsections** over the in-use
/// object numbers, so a sparse high obj-id (e.g. one object numbered 4 billion)
/// costs one subsection, not a multi-GB dense table.
fn rebuild_traditional(
    bodies: &BTreeMap<u32, (u16, Vec<u8>)>,
    redacted: &HashSet<u32>,
    root_ref: Option<&[u8]>,
) -> Vec<u8> {
    rebuild_traditional_with_spans(bodies, redacted, root_ref).0
}

/// Like [`rebuild_traditional`] but also returns each emitted object's output span
/// `(obj_id, artifact_offset, artifact_length)` covering its full
/// `N G obj … endobj` framing in the produced artifact (ADR-0030 §2a /§3
/// `pdf-xref-stream`): the verifier slices that span and locates
/// `inner = slice[find("obj")+3 .. rfind("endobj")]` to reconstruct the leaf.
fn rebuild_traditional_with_spans(
    bodies: &BTreeMap<u32, (u16, Vec<u8>)>,
    redacted: &HashSet<u32>,
    root_ref: Option<&[u8]>,
) -> (Vec<u8>, Vec<(u32, u64, u64)>) {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(b"%PDF-1.7\n");

    // obj_id -> (byte offset in `out`, generation). Sparse — only in-use objects.
    let mut offsets: BTreeMap<u32, (u64, u16)> = BTreeMap::new();
    // (obj_id, header offset) in emission order, to derive each object's span as
    // `[start, next_start)` (last ends at the xref offset) below.
    let mut starts: Vec<(u32, u64)> = Vec::with_capacity(bodies.len());
    for (&id, (generation, body)) in bodies {
        let start = out.len() as u64;
        offsets.insert(id, (start, *generation));
        starts.push((id, start));
        out.extend_from_slice(format!("{id} {generation} obj\n").as_bytes());
        if redacted.contains(&id) {
            out.extend_from_slice(b"null");
        } else {
            out.extend_from_slice(body);
        }
        out.extend_from_slice(b"\nendobj\n");
    }

    // /Size is one past the largest object number (PDF §7.5.4).
    let size = bodies
        .keys()
        .copied()
        .max()
        .map(|m| m as u64 + 1)
        .unwrap_or(1);

    let xref_off = out.len();
    out.extend_from_slice(b"xref\n");
    // Object 0 is always the free-list head, emitted as its own subsection. The
    // in-use objects follow as contiguous-run subsections (gaps are implicitly
    // free; our parser and standard readers treat unlisted numbers as free).
    out.extend_from_slice(b"0 1\n0000000000 65535 f \n");
    let ids: Vec<u32> = offsets.keys().copied().collect(); // sorted, all >= 1
    let mut i = 0;
    while i < ids.len() {
        let run_start = ids[i];
        let mut j = i;
        while j + 1 < ids.len() && ids[j + 1] == ids[j] + 1 {
            j += 1;
        }
        let run_len = j - i + 1;
        out.extend_from_slice(format!("{run_start} {run_len}\n").as_bytes());
        for &id in &ids[i..=j] {
            let (off, generation) = offsets[&id];
            out.extend_from_slice(format!("{off:010} {generation:05} n \n").as_bytes());
        }
        i = j + 1;
    }

    out.extend_from_slice(b"trailer\n<< /Size ");
    out.extend_from_slice(size.to_string().as_bytes());
    if let Some(r) = root_ref {
        out.extend_from_slice(b" /Root ");
        out.extend_from_slice(r);
    }
    out.extend_from_slice(b" >>\nstartxref\n");
    out.extend_from_slice(xref_off.to_string().as_bytes());
    out.extend_from_slice(b"\n%%EOF\n");

    // Object k spans [start_k, start_{k+1}); the last ends where the xref begins
    // (`xref_off`, captured before the xref table was written) — i.e. just past
    // its `\nendobj\n`. This is the full `N G obj … endobj` span the verifier locates.
    let mut spans = Vec::with_capacity(starts.len());
    for (i, &(id, start)) in starts.iter().enumerate() {
        let end = starts.get(i + 1).map_or(xref_off as u64, |&(_, s)| s);
        spans.push((id, start, end - start));
    }
    (out, spans)
}

// ── Segmenter impl ──────────────────────────────────────────────────────────────

/// Parse the modern PDF's logical objects, validate `redacted_ids` against the
/// committed manifest + the uploaded artifact, and resolve the `/Root` ref — the
/// shared prelude of [`ModernPdfSegmenter::apply_redaction`] and its spans variant.
#[allow(clippy::type_complexity)]
fn prepare_rebuild(
    bytes: &[u8],
    manifest: &SegmentManifest,
    redacted_ids: &[u32],
) -> Result<(BTreeMap<u32, (u16, Vec<u8>)>, HashSet<u32>, Option<Vec<u8>>), SegmentError> {
    let bodies = logical_objects(bytes)?;
    // Validate the redaction set against the committed manifest.
    for &id in redacted_ids {
        if !manifest.segments.iter().any(|s| s.segment_id == id) {
            return Err(SegmentError::UnknownSegment(id));
        }
        if !bodies.contains_key(&id) {
            return Err(malformed(format!(
                "object {id} present in manifest but not in the uploaded artifact"
            )));
        }
    }
    // The /Root ref for the rebuilt trailer.
    let sx = rfind(bytes, b"startxref").ok_or_else(|| malformed("no startxref"))?;
    let (xref_off, _) = read_uint(bytes, sx + b"startxref".len())
        .ok_or_else(|| malformed("no offset after startxref"))?;
    let xref = parse_xref_stream(bytes, xref_off as usize)?;
    let redacted: HashSet<u32> = redacted_ids.iter().copied().collect();
    Ok((bodies, redacted, xref.root_ref))
}

impl Segmenter for ModernPdfSegmenter {
    fn format(&self) -> SegmentFormat {
        SegmentFormat::PdfXrefStream
    }

    fn extract(&self, bytes: &[u8], blind_secret: &[u8]) -> Result<SegmentManifest, SegmentError> {
        let content_hash = blake3::hash(bytes);
        let bodies = logical_objects(bytes)?;
        if bodies.len() > MAX_REDACTION_SEGMENTS {
            return Err(SegmentError::TooManySegments {
                found: bodies.len(),
                max: MAX_REDACTION_SEGMENTS,
            });
        }
        let mut segments = Vec::with_capacity(bodies.len());
        let mut leaves = Vec::with_capacity(bodies.len());
        for (&obj_id, (_generation, body)) in &bodies {
            let id_be = obj_id.to_be_bytes();
            let content = content_scalar(&id_be, body);
            let blinding = derive_blinding(blind_secret, content_hash.as_bytes(), &id_be);
            let leaf_fr = redaction_leaf(&content, &blinding)
                .map_err(|e| SegmentError::LeafComputationFailed(e.to_string()))?;
            leaves.push(leaf_fr);
            segments.push(Segment {
                segment_id: obj_id,
                label: None,
                byte_offset: 0,
                byte_length: body.len() as u64,
                leaf_hex: fr_to_hex(leaf_fr),
            });
        }
        // ADR-0030 §1 variable-depth fold over the real logical-object leaves.
        // A PDF with a single in-use object (N=1) surfaces as `TooFewSegments`,
        // routing the ingest caller to the (non-redactable) chunk fallback.
        let root = variable_depth_fold_root(&leaves)?;
        let (tree_depth, max_leaves) = variable_geometry(segments.len());
        Ok(SegmentManifest {
            format: SegmentFormat::PdfXrefStream,
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
        let (bodies, redacted, root_ref) = prepare_rebuild(bytes, manifest, redacted_ids)?;
        Ok(rebuild_traditional(&bodies, &redacted, root_ref.as_deref()))
    }

    /// The output spans are the rebuilt traditional-xref PDF's per-object offsets
    /// (ADR-0030 §2a / §3 `pdf-xref-stream`): each span covers the full
    /// `N G obj … endobj` framing, which the verifier slices and locates
    /// `inner = slice[find("obj")+3 .. rfind("endobj")]` to reconstruct the leaf.
    fn apply_redaction_with_spans(
        &self,
        bytes: &[u8],
        manifest: &SegmentManifest,
        redacted_ids: &[u32],
    ) -> Result<(Vec<u8>, Vec<SegmentSpan>), SegmentError> {
        let (bodies, redacted, root_ref) = prepare_rebuild(bytes, manifest, redacted_ids)?;
        let (artifact, obj_spans) =
            rebuild_traditional_with_spans(&bodies, &redacted, root_ref.as_deref());
        let span_map: BTreeMap<u32, (u64, u64)> = obj_spans
            .into_iter()
            .map(|(id, off, len)| (id, (off, len)))
            .collect();
        let spans = manifest
            .segments
            .iter()
            .map(|s| {
                let &(offset, length) = span_map.get(&s.segment_id).ok_or_else(|| {
                    malformed(format!(
                        "object {} in the manifest is absent from the rebuilt artifact",
                        s.segment_id
                    ))
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
    use std::io::Write;

    const SECRET: &[u8] = &[0x5au8; 32];

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a minimal modern PDF: object 1 is a direct catalog, object 2 is an
    /// ObjStm packing objects 3 and 4, and the cross-reference is a /XRef stream
    /// (object 5) with /W [1 4 2] and no predictor. Returns the bytes.
    fn build_modern_pdf() -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"%PDF-1.7\n");

        // obj 1: catalog (direct).
        let off1 = buf.len();
        buf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n");

        // obj 2: ObjStm containing objects 3 and 4.
        let o3 = b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>".to_vec();
        let o4 = b"<< /Type /Page /Parent 3 0 R /Secret (classified) >>".to_vec();
        let first = format!("3 0 4 {} ", o3.len()); // header: objnum rel_off pairs
        let mut objstm_body = first.clone().into_bytes();
        let first_len = objstm_body.len();
        objstm_body.extend_from_slice(&o3);
        objstm_body.extend_from_slice(&o4);
        let objstm_compressed = zlib(&objstm_body);
        let off2 = buf.len();
        buf.extend_from_slice(
            format!(
                "2 0 obj\n<< /Type /ObjStm /N 2 /First {first_len} /Length {} /Filter /FlateDecode >>\nstream\n",
                objstm_compressed.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&objstm_compressed);
        buf.extend_from_slice(b"\nendstream\nendobj\n");

        // Cross-reference stream (obj 5), /W [1 4 2].
        // entries for objs 0..=5:
        //   0: free            (0, 0, 65535)
        //   1: direct off1     (1, off1, 0)
        //   2: direct off2     (1, off2, 0)
        //   3: in stream 2 #0  (2, 2, 0)
        //   4: in stream 2 #1  (2, 2, 1)
        //   5: direct off5     (1, off5, 0)   ← the xref stream itself
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
        push(&mut rows, 2, 2, 0);
        push(&mut rows, 2, 2, 1);
        push(&mut rows, 1, off5 as u32, 0);
        let xref_compressed = zlib(&rows);
        buf.extend_from_slice(
            format!(
                "5 0 obj\n<< /Type /XRef /Size 6 /W [1 4 2] /Root 1 0 R /Length {} /Filter /FlateDecode >>\nstream\n",
                xref_compressed.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&xref_compressed);
        buf.extend_from_slice(b"\nendstream\nendobj\n");

        buf.extend_from_slice(format!("startxref\n{off5}\n%%EOF\n").as_bytes());
        buf
    }

    #[test]
    fn extracts_content_objects_excluding_structural_containers() {
        let pdf = build_modern_pdf();
        let m = ModernPdfSegmenter.extract(&pdf, SECRET).unwrap();
        assert_eq!(m.format, SegmentFormat::PdfXrefStream);
        // Content objects only: 1 (catalog), 3 & 4 (unpacked from the ObjStm).
        // The /ObjStm container (obj 2) and the xref-stream object (obj 5) are
        // structural and MUST NOT be committed as redactable segments — otherwise
        // redacting a packed object would leak via the verbatim container.
        let ids: Vec<u32> = m.segments.iter().map(|s| s.segment_id).collect();
        assert_eq!(ids, vec![1, 3, 4]);
        assert_eq!(m.recompute_root().unwrap(), m.original_root_hex);
    }

    #[test]
    fn logical_body_of_objstm_object_is_its_content() {
        let pdf = build_modern_pdf();
        let bodies = logical_objects(&pdf).unwrap();
        assert_eq!(
            bodies.get(&4).map(|(_gen, b)| b.as_slice()),
            Some(b"<< /Type /Page /Parent 3 0 R /Secret (classified) >>".as_slice())
        );
    }

    #[test]
    fn redaction_rebuilds_and_revealed_leaves_recompute() {
        let pdf = build_modern_pdf();
        let m = ModernPdfSegmenter.extract(&pdf, SECRET).unwrap();
        let content_hash = blake3::hash(&pdf);
        // Redact object 4 (the Page with the secret), which lives in the ObjStm.
        let redacted_artifact = ModernPdfSegmenter.apply_redaction(&pdf, &m, &[4]).unwrap();

        // SECURITY (the assertion that would have caught the container leak): the
        // redacted plaintext must be ABSENT from the output bytes, and no /ObjStm
        // or /XRef container may survive to carry it through compressed.
        assert!(
            find(&redacted_artifact, b"(classified)").is_none(),
            "redacted plaintext must not appear in the artifact"
        );
        assert!(
            find(&redacted_artifact, b"/ObjStm").is_none(),
            "the ObjStm container (which packed the secret) must be dropped"
        );
        assert!(
            find(&redacted_artifact, b"/XRef").is_none(),
            "the xref-stream container must be dropped (rebuilt as traditional xref)"
        );

        // The rebuilt artifact is a traditional-xref PDF the traditional walker
        // can read; re-extract its logical bodies and check revealed leaves.
        let spans = crate::zk::pdf_objects::extract_object_spans(&redacted_artifact)
            .expect("rebuilt PDF parses as traditional xref");
        let mut rebuilt: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
        for s in &spans {
            let body = trim_body(&redacted_artifact[s.byte_start..s.byte_end]);
            // Strip the `N G obj` / `endobj` framing the traditional span includes.
            let inner = {
                let obj_kw = find(body, b"obj").unwrap() + b"obj".len();
                let endo = rfind(body, b"endobj").unwrap();
                trim_body(&body[obj_kw..endo]).to_vec()
            };
            rebuilt.insert(s.obj_id, inner);
        }
        for seg in &m.segments {
            let id_be = seg.segment_id.to_be_bytes();
            let body = rebuilt
                .get(&seg.segment_id)
                .expect("object survives rebuild");
            if seg.segment_id == 4 {
                assert_eq!(body.as_slice(), b"null", "redacted object body destroyed");
                continue;
            }
            let content = content_scalar(&id_be, body);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, seg.leaf_hex,
                "revealed object {} leaf recomputes",
                seg.segment_id
            );
        }
    }

    #[test]
    fn spans_locate_revealed_object_leaves() {
        // ADR-0030 §2a/§3 `pdf-xref-stream`: each span covers the full
        // `N G obj … endobj` framing in the rebuilt traditional-xref PDF; the
        // verifier slices it, takes `inner = slice[find("obj")+3 .. rfind("endobj")]`,
        // trims with the pinned whitespace set, and recomputes the committed leaf.
        let pdf = build_modern_pdf();
        let m = ModernPdfSegmenter.extract(&pdf, SECRET).unwrap();
        let content_hash = blake3::hash(&pdf);
        let (artifact, spans) = ModernPdfSegmenter
            .apply_redaction_with_spans(&pdf, &m, &[4])
            .unwrap();
        assert_eq!(spans.len(), m.segments.len());
        for (seg, span) in m.segments.iter().zip(&spans) {
            assert_eq!(span.segment_id, seg.segment_id);
            let s = span.artifact_offset as usize;
            let e = s + span.artifact_length as usize;
            let slice = &artifact[s..e];
            let obj_kw = find(slice, b"obj").expect("obj keyword in span") + b"obj".len();
            let endo = rfind(slice, b"endobj").expect("endobj keyword in span");
            let inner = trim_body(&slice[obj_kw..endo]);
            if seg.segment_id == 4 {
                assert_eq!(inner, b"null", "redacted object body is the null token");
                continue;
            }
            let id_be = seg.segment_id.to_be_bytes();
            let content = content_scalar(&id_be, inner);
            let blinding = derive_blinding(SECRET, content_hash.as_bytes(), &id_be);
            let leaf = fr_to_hex(redaction_leaf(&content, &blinding).unwrap());
            assert_eq!(
                leaf, seg.leaf_hex,
                "revealed object {} leaf recomputes from artifact span",
                seg.segment_id
            );
        }
    }

    #[test]
    fn unknown_segment_id_rejected() {
        let pdf = build_modern_pdf();
        let m = ModernPdfSegmenter.extract(&pdf, SECRET).unwrap();
        assert!(matches!(
            ModernPdfSegmenter.apply_redaction(&pdf, &m, &[999]),
            Err(SegmentError::UnknownSegment(999))
        ));
    }

    #[test]
    fn traditional_xref_pdf_is_not_handled_here() {
        // A traditional-xref PDF has no /XRef stream → this segmenter errors
        // (the ingest two-try uses the traditional segmenter for those).
        let trad = b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\nxref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n30\n%%EOF\n";
        assert!(ModernPdfSegmenter.extract(trad, SECRET).is_err());
    }

    // ── DoS-guard regressions (attacker-controlled parser inputs) ──────────────

    #[test]
    fn objstm_huge_n_is_rejected_before_allocating() {
        // /N drives Vec::with_capacity; an oversized count must error, not OOM.
        // The /N cap is checked before the stream is even read.
        let obj =
            b"0 0 obj\n<< /Type /ObjStm /N 9999999999 /First 4 >>\nstream\n\nendstream\nendobj\n";
        assert!(matches!(
            decode_objstm(obj, 0),
            Err(SegmentError::Malformed { .. })
        ));
    }

    #[test]
    fn xref_oversized_w_width_is_rejected() {
        // /W field width > 8 would overflow `row` and OOB-slice; reject it.
        let obj = b"0 0 obj\n<< /Type /XRef /W [99 1 1] /Size 1 >>\nstream\n\nendstream\nendobj\n";
        assert!(matches!(
            parse_xref_stream(obj, 0),
            Err(SegmentError::Malformed { .. })
        ));
    }

    #[test]
    fn predictor_on_empty_stream_is_rejected() {
        // Empty data + huge /Columns previously passed `0.is_multiple_of(row)` and
        // hit `vec![0u8; columns]` (multi-GB OOM). Must error instead.
        assert!(undo_png_predictor(b"", 9_999_999_999).is_err());
        assert!(undo_png_predictor(&[], 1).is_err());
    }

    #[test]
    fn objstm_offset_overflow_is_rejected() {
        // A header offset near usize::MAX must not wrap/panic in the slice math.
        let header = format!("1 {} ", u64::MAX); // objnum 1, rel = u64::MAX
        let first = header.len();
        let mut body = header.into_bytes();
        body.extend_from_slice(b"x");
        let compressed = zlib(&body);
        let mut obj = format!(
            "0 0 obj\n<< /Type /ObjStm /N 1 /First {first} /Length {} /Filter /FlateDecode >>\nstream\n",
            compressed.len()
        )
        .into_bytes();
        obj.extend_from_slice(&compressed);
        obj.extend_from_slice(b"\nendstream\nendobj\n");
        assert!(matches!(
            decode_objstm(&obj, 0),
            Err(SegmentError::Malformed { .. })
        ));
    }

    #[test]
    fn out_of_bounds_xref_offset_does_not_panic() {
        // A Direct offset past EOF must surface as a None/Err, never a slice panic.
        assert!(object_body_span(b"%PDF-1.7\n", 9999).is_none());
    }

    #[test]
    fn rebuild_preserves_generation_and_uses_sparse_xref() {
        // A direct object with a NON-ZERO generation must re-emit as `N G obj`
        // (not `N 0 obj`), and a SPARSE high object number must not allocate a
        // dense table (a dense `vec![0; max_id+1]` would OOM here).
        let mut bodies: BTreeMap<u32, (u16, Vec<u8>)> = BTreeMap::new();
        bodies.insert(1, (0, b"<< /Type /Catalog >>".to_vec()));
        bodies.insert(7, (3, b"<< /Note (keep) >>".to_vec())); // gen 3
        bodies.insert(4_000_000_000, (0, b"<< /Note (huge id) >>".to_vec()));
        let redacted: HashSet<u32> = HashSet::new();
        let out = rebuild_traditional(&bodies, &redacted, Some(b"1 0 R"));

        assert!(
            find(&out, b"7 3 obj").is_some(),
            "non-zero generation must be re-emitted"
        );
        assert!(find(&out, b"7 0 obj").is_none());
        // /Size = max obj number + 1.
        assert!(find(&out, b"/Size 4000000001").is_some());
        // Re-parses as a valid traditional-xref PDF (sparse subsections).
        let spans = crate::zk::pdf_objects::extract_object_spans(&out)
            .expect("sparse-xref rebuild parses traditionally");
        let ids: Vec<u32> = spans.iter().map(|s| s.obj_id).collect();
        assert_eq!(ids, vec![1, 7, 4_000_000_000]);
        assert_eq!(spans.iter().find(|s| s.obj_id == 7).unwrap().generation, 3);
    }

    #[test]
    fn predictor_huge_columns_does_not_overflow() {
        // /Columns near usize::MAX previously overflowed `columns + 1` → row 0 →
        // `chunks(0)` panic. Must error instead.
        assert!(undo_png_predictor(b"some data bytes", usize::MAX).is_err());
        assert!(undo_png_predictor(b"abc", 1_000_000).is_err());
    }

    // NOTE: the `entry_cap` total-entry DoS guard (`MAX_REDACTION_SEGMENTS * 16`)
    // is now too large (≈16.7M) to cross in a unit test without allocating that
    // many entries. The crafted-flood regression is subsumed by the MAX_INFLATE
    // (64 MiB) decoded-stream bound — a `/W [1 0 0]` row=1 stream can hold at most
    // ~64M records, and inflation past the cap errors first — exercised by the
    // other DoS-guard regressions above (oversized /W, huge /N, predictor bombs).
}
