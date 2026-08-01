//! Shared byte-level PDF syntax scanners.
//!
//! Extracted verbatim from [`crate::zk::pdf_describe`] when
//! [`crate::zk::pdf_placement`] needed the same primitives (ADR-0029 A.5-2);
//! keeping one copy is the "no duplicate parsing" discipline the redaction
//! modules already follow. **No behaviour change** — these are the same
//! scanners, only re-homed and made `pub(crate)`.
//!
//! Byte-level only: no PDF renderer, no pdfium, no rasterizer (the discipline
//! [`crate::zk::pdf_objects`] and `pdf_describe` establish). Every scanner is
//! fail-soft — an unparseable region yields `None`/empty, never a panic.

pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Find `key` at the **top level** (depth 1) of an object's dictionary, so a
/// key nested inside a sub-dictionary (`/Resources << /XObject << … >> >>`,
/// an inline `/DecodeParms`, etc.) cannot be mistaken for the object's own
/// attribute. Tracks `<< >>` dict nesting and skips `( )` literal strings (whose
/// bytes are not structural). Depth becomes 1 at the object's outer `<<`, so a
/// match at depth 1 is the object dict's own key. Returns the key's byte offset.
pub(crate) fn find_top_level(region: &[u8], key: &[u8]) -> Option<usize> {
    let mut depth: i32 = 0;
    let mut i = 0;
    while i < region.len() {
        match region[i] {
            // Literal string: skip to its balanced close, honoring escapes.
            b'(' => {
                i += 1;
                let mut d = 1u32;
                while i < region.len() && d > 0 {
                    match region[i] {
                        b'\\' => i += 2,
                        b'(' => {
                            d += 1;
                            i += 1;
                        }
                        b')' => {
                            d -= 1;
                            i += 1;
                        }
                        _ => i += 1,
                    }
                }
            }
            // Dict open / close (the doubled angle brackets; a single `<`/`>` is
            // a hex-string delimiter and does not change dict depth).
            b'<' if region.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
            }
            b'>' if region.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                i += 2;
            }
            _ => {
                if depth == 1 && region[i..].starts_with(key) {
                    return Some(i);
                }
                i += 1;
            }
        }
    }
    None
}

pub(crate) fn is_ws(b: u8) -> bool {
    b.is_ascii_whitespace() || b == 0
}

/// PDF name/keyword delimiter: whitespace or one of the structural delimiters.
pub(crate) fn is_delim(b: u8) -> bool {
    is_ws(b) || matches!(b, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'%')
}

/// The dictionary region of an object span: everything up to the `stream`
/// keyword (so a content stream's payload is excluded from key lookups), else
/// the whole span.
pub(crate) fn dict_region(span: &[u8]) -> &[u8] {
    match find(span, b"stream") {
        Some(s) => &span[..s],
        None => span,
    }
}

/// Read the `/Name` value immediately following the first occurrence of `key`
/// in `region` (e.g. `name_after(d, b"/Type") == Some("Page")`).
pub(crate) fn name_after(region: &[u8], key: &[u8]) -> Option<String> {
    let mut i = find_top_level(region, key)? + key.len();
    while i < region.len() && is_ws(region[i]) {
        i += 1;
    }
    if i >= region.len() || region[i] != b'/' {
        return None;
    }
    i += 1;
    let start = i;
    while i < region.len() && !is_delim(region[i]) {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&region[start..i])
        .ok()
        .map(str::to_owned)
}

/// Read the unsigned integer immediately following the first occurrence of
/// `key` (e.g. `int_after(d, b"/Width") == Some(800)`).
pub(crate) fn int_after(region: &[u8], key: &[u8]) -> Option<u64> {
    let mut i = find_top_level(region, key)? + key.len();
    while i < region.len() && is_ws(region[i]) {
        i += 1;
    }
    let start = i;
    while i < region.len() && region[i].is_ascii_digit() {
        i += 1;
    }
    if i == start {
        return None;
    }
    std::str::from_utf8(&region[start..i]).ok()?.parse().ok()
}

/// Read indirect-object ids referenced by `key`, handling both a single
/// `key N G R` and an array `key [N G R M G R …]`. Returns object numbers in
/// order (e.g. `/Kids [3 0 R 9 0 R]` → `[3, 9]`, `/Contents 4 0 R` → `[4]`).
pub(crate) fn refs_after(region: &[u8], key: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let Some(k) = find_top_level(region, key) else {
        return out;
    };
    let mut i = k + key.len();
    while i < region.len() && is_ws(region[i]) {
        i += 1;
    }
    // Bound the scan: a single ref ends at the first non-ref token; an array
    // ends at `]`.
    let array = i < region.len() && region[i] == b'[';
    if array {
        i += 1;
    }
    loop {
        while i < region.len() && is_ws(region[i]) {
            i += 1;
        }
        if i >= region.len() || (array && region[i] == b']') {
            break;
        }
        // Parse `N G R`.
        let ns = i;
        while i < region.len() && region[i].is_ascii_digit() {
            i += 1;
        }
        if i == ns {
            break; // not a number → end of this entry
        }
        let obj_num: u32 = match std::str::from_utf8(&region[ns..i])
            .ok()
            .and_then(|s| s.parse().ok())
        {
            Some(n) => n,
            None => break,
        };
        while i < region.len() && is_ws(region[i]) {
            i += 1;
        }
        // generation
        let gs = i;
        while i < region.len() && region[i].is_ascii_digit() {
            i += 1;
        }
        if i == gs {
            break;
        }
        while i < region.len() && is_ws(region[i]) {
            i += 1;
        }
        if i >= region.len() || region[i] != b'R' {
            break; // not a reference
        }
        i += 1;
        out.push(obj_num);
        if !array {
            break; // single ref consumed
        }
    }
    out
}

/// Read the numeric array following `key` — `/MediaBox [0 0 612 792]`,
/// `/Matrix [1 0 0 1 0 0]`. Accepts signed reals; a malformed element ends the
/// scan, so a truncated array yields the prefix it could read (callers check the
/// arity they need).
pub(crate) fn reals_after(region: &[u8], key: &[u8]) -> Vec<f32> {
    let mut out = Vec::new();
    let Some(k) = find_top_level(region, key) else {
        return out;
    };
    let mut i = k + key.len();
    while i < region.len() && is_ws(region[i]) {
        i += 1;
    }
    if i >= region.len() || region[i] != b'[' {
        return out;
    }
    i += 1;
    loop {
        while i < region.len() && is_ws(region[i]) {
            i += 1;
        }
        if i >= region.len() || region[i] == b']' {
            break;
        }
        let start = i;
        if matches!(region[i], b'+' | b'-') {
            i += 1;
        }
        while i < region.len() && (region[i].is_ascii_digit() || region[i] == b'.') {
            i += 1;
        }
        if i == start {
            break; // not a number → end of the numeric run
        }
        match std::str::from_utf8(&region[start..i])
            .ok()
            .and_then(|s| s.parse::<f32>().ok())
        {
            Some(v) if v.is_finite() => out.push(v),
            // A non-finite or unparseable element makes the whole array
            // untrustworthy for geometry; stop rather than emit a bogus rect.
            _ => break,
        }
    }
    out
}

/// The raw (still-encoded) payload between `stream` and `endstream` in an
/// object span, or `None` if the object carries no stream.
pub(crate) fn stream_payload(span: &[u8]) -> Option<&[u8]> {
    let s = find(span, b"stream")? + b"stream".len();
    // The byte(s) after `stream` are CRLF or LF before the payload.
    let mut start = s;
    if start < span.len() && span[start] == b'\r' {
        start += 1;
    }
    if start < span.len() && span[start] == b'\n' {
        start += 1;
    }
    let end = find(&span[start..], b"endstream").map(|e| start + e)?;
    Some(&span[start..end])
}

/// Decode a stream object's payload, inflating a single `/FlateDecode` filter
/// (the common case) and passing an unfiltered payload through.
///
/// Best-effort by design: image filters (`DCTDecode`, `CCITTFaxDecode`,
/// `JPXDecode`) and multi-filter chains yield `None` rather than a guess.
/// `cap` bounds the inflated size so a decompression bomb cannot blow memory —
/// callers pass what they actually need to read.
pub(crate) fn decoded_stream(span: &[u8], cap: u64) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let raw = stream_payload(span)?;
    match name_after(dict_region(span), b"/Filter") {
        None => Some(raw.to_vec()),
        Some(f) if f == "FlateDecode" || f == "Fl" => {
            let mut buf = Vec::new();
            flate2::read::ZlibDecoder::new(raw)
                .take(cap)
                .read_to_end(&mut buf)
                .ok()?;
            Some(buf)
        }
        Some(_) => None,
    }
}

/// Inflation cap for a content-stream **text preview** — only the first couple
/// hundred characters are ever shown, so a few KiB of decoded text is plenty.
pub(crate) const PREVIEW_INFLATE_CAP: u64 = 64 * 1024;

/// Inflation cap for a content stream being **walked** for geometry. Larger
/// than the preview cap (the walk must see every `Do` on the page, not just the
/// head of the stream) but still bounded, so a decompression bomb cannot exhaust
/// memory. A stream truncated at the cap simply yields the placements found in
/// the prefix — fail-soft, consistent with the rest of this module.
pub(crate) const CONTENT_INFLATE_CAP: u64 = 16 * 1024 * 1024;
