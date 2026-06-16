//! ADR-0029 Phase A1: object **classification + previews** for the redaction
//! producer UI.
//!
//! Today the producer lists committed PDF objects by id + byte size
//! (`#37 · 45592 bytes`). An end user cannot map "the source's name I must hide"
//! to "object #37". This module turns each committed indirect object into a
//! human **label** + **preview** so the UI can group the checklist by page and
//! type and show what each object actually is.
//!
//! **Presentation only.** Everything here is computed on demand from the
//! uploaded bytes and is **never persisted and never part of the commitment**:
//! labels/previews do not touch the hiding leaf, the manifest schema, or the
//! Merkle root (ADR-0029 §A). It reuses [`extract_object_spans`] so the
//! described object set is exactly the committed object set, in the same
//! obj-id-ascending order.
//!
//! Byte-level only — no PDF renderer, no pdfium, no rasterizer (same discipline
//! as [`crate::zk::pdf_objects`]). Content-stream text previews inflate a single
//! `/FlateDecode` filter (the common case) and otherwise fall back to the raw
//! payload; exotic filter chains yield no preview (fail soft, never wrong).

use std::collections::{BTreeMap, HashMap, HashSet};

use std::io::Read as _;

use serde::Serialize;

use crate::zk::pdf_objects::{extract_object_spans, PdfObjectError};

/// Max characters of extracted text returned as a content-stream preview.
const PREVIEW_CHARS: usize = 200;
/// Guard against a pathological / cyclic page tree.
const MAX_PAGE_TREE_DEPTH: usize = 64;

/// One classified, human-presentable PDF indirect object (ADR-0029 §A).
///
/// `kind` is a stable snake_case tag the frontend switches on; the optional
/// structural fields are populated per kind. Serialised camelCase for the JS
/// producer UI.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ObjectDescription {
    /// Indirect object id — identical to the committed `segment_id`.
    pub obj_id: u32,
    /// Raw byte length of the object span (header through `endobj`).
    pub byte_length: u64,
    /// Stable classification tag: `catalog` | `pages` | `page` |
    /// `content_stream` | `image` | `font` | `metadata` | `annotation` |
    /// `xobject_form` | `other`.
    pub kind: &'static str,
    /// Human label, e.g. `"Page 1 — text"`, `"Image 800×600 (DCTDecode)"`,
    /// `"Font: Helvetica"`.
    pub label: String,
    /// 1-based page number this object belongs to, if resolvable from the
    /// `/Pages → /Kids → /Page /Contents` tree. `None` for document-level
    /// objects (catalog, fonts, metadata) or an unresolvable tree.
    pub page: Option<u32>,
    /// Short extracted-text preview for content streams; `None` otherwise or
    /// when the stream uses a filter chain this v1 does not decode.
    pub preview: Option<String>,
    /// Image width in pixels (`/Width`), for `image` kind.
    pub width: Option<u64>,
    /// Image height in pixels (`/Height`), for `image` kind.
    pub height: Option<u64>,
    /// Stream `/Filter` name, for `image` kind (e.g. `DCTDecode`).
    pub filter: Option<String>,
    /// `/BaseFont` name, for `font` kind (e.g. `Helvetica`).
    pub base_font: Option<String>,
    /// Raw `/Type` name when `kind == "other"`, for display.
    pub type_name: Option<String>,
}

// ── Byte-slice helpers (local; mirror pdf_objects' private scanners) ──────────

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_ws(b: u8) -> bool {
    b.is_ascii_whitespace() || b == 0
}

/// PDF name/keyword delimiter: whitespace or one of the structural delimiters.
fn is_delim(b: u8) -> bool {
    is_ws(b) || matches!(b, b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | b'%')
}

/// The dictionary region of an object span: everything up to the `stream`
/// keyword (so a content stream's payload is excluded from key lookups), else
/// the whole span.
fn dict_region(span: &[u8]) -> &[u8] {
    match find(span, b"stream") {
        Some(s) => &span[..s],
        None => span,
    }
}

/// Read the `/Name` value immediately following the first occurrence of `key`
/// in `region` (e.g. `name_after(d, b"/Type") == Some("Page")`).
fn name_after(region: &[u8], key: &[u8]) -> Option<String> {
    let mut i = find(region, key)? + key.len();
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
fn int_after(region: &[u8], key: &[u8]) -> Option<u64> {
    let mut i = find(region, key)? + key.len();
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
fn refs_after(region: &[u8], key: &[u8]) -> Vec<u32> {
    let mut out = Vec::new();
    let Some(k) = find(region, key) else {
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

/// Extract a short printable preview from a content-stream **payload** (already
/// inflated). PDF text operators show `(literal)` / `[(a) -3 (b)] TJ` strings;
/// in a content stream `(...)` is always a string literal, so collecting the
/// balanced literals (honoring `\(`, `\)`, `\\`) yields the shown text.
fn preview_from_stream(payload: &[u8]) -> Option<String> {
    let mut out = String::new();
    let mut i = 0;
    while i < payload.len() && out.chars().count() < PREVIEW_CHARS {
        if payload[i] != b'(' {
            i += 1;
            continue;
        }
        // Scan a balanced literal string.
        i += 1;
        let mut depth = 1usize;
        while i < payload.len() && depth > 0 {
            match payload[i] {
                b'\\' => {
                    // Escaped char: take the next byte literally if printable.
                    if i + 1 < payload.len() {
                        let c = payload[i + 1];
                        match c {
                            b'n' | b'r' | b't' => out.push(' '),
                            b'(' | b')' | b'\\' => out.push(c as char),
                            _ if c.is_ascii_graphic() || c == b' ' => out.push(c as char),
                            _ => {}
                        }
                    }
                    i += 2;
                }
                b'(' => {
                    depth += 1;
                    out.push('(');
                    i += 1;
                }
                b')' => {
                    depth -= 1;
                    if depth > 0 {
                        out.push(')');
                    }
                    i += 1;
                }
                c => {
                    if c.is_ascii_graphic() || c == b' ' {
                        out.push(c as char);
                    }
                    i += 1;
                }
            }
        }
        out.push(' ');
    }
    let trimmed = out.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.is_empty() {
        return None;
    }
    let mut s: String = trimmed.chars().take(PREVIEW_CHARS).collect();
    if trimmed.chars().count() > PREVIEW_CHARS {
        s.push('…');
    }
    Some(s)
}

/// Inflate (if `/FlateDecode`) and preview a content-stream object's payload.
/// Best-effort: a non-Flate / chained filter yields `None` (fail soft).
fn content_stream_preview(span: &[u8]) -> Option<String> {
    let dict = dict_region(span);
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
    let raw = &span[start..end];

    match name_after(dict, b"/Filter") {
        None => preview_from_stream(raw),
        Some(f) if f == "FlateDecode" || f == "Fl" => {
            let z = flate2::read::ZlibDecoder::new(raw);
            let mut buf = Vec::new();
            // Cap inflation so a zip-bomb-y stream can't blow memory for a
            // mere preview; we only need the first PREVIEW_CHARS of text.
            match z.take(64 * 1024).read_to_end(&mut buf) {
                Ok(_) => preview_from_stream(&buf),
                Err(_) => None,
            }
        }
        // Image filters (DCTDecode/CCITTFax/JPXDecode) and multi-filter chains
        // are not text — no preview.
        Some(_) => None,
    }
}

/// Resolve 1-based page numbers by walking `Catalog → Pages → Kids` and map
/// each `/Page`'s own object id and its `/Contents` object id(s) to that page.
/// Fail-soft: anything unresolvable simply isn't in the returned map.
fn resolve_pages(dicts: &BTreeMap<u32, &[u8]>) -> HashMap<u32, u32> {
    let mut page_of: HashMap<u32, u32> = HashMap::new();

    // Catalog: the object with `/Type /Catalog`; take its `/Pages` root ref.
    let catalog = dicts
        .iter()
        .find(|(_, d)| name_after(d, b"/Type").as_deref() == Some("Catalog"));
    let Some(root) = catalog.and_then(|(_, d)| refs_after(d, b"/Pages").first().copied()) else {
        return page_of;
    };

    // DFS the page tree, assigning page numbers to `/Page` leaves in order.
    let mut next_page: u32 = 1;
    let mut visited: HashSet<u32> = HashSet::new();
    let mut stack: Vec<(u32, usize)> = vec![(root, 0)];
    while let Some((id, depth)) = stack.pop() {
        if depth > MAX_PAGE_TREE_DEPTH || !visited.insert(id) {
            continue;
        }
        let Some(dict) = dicts.get(&id) else { continue };
        match name_after(dict, b"/Type").as_deref() {
            Some("Pages") => {
                // Push kids in reverse so they pop in document order.
                let kids = refs_after(dict, b"/Kids");
                for kid in kids.into_iter().rev() {
                    stack.push((kid, depth + 1));
                }
            }
            Some("Page") => {
                let page = next_page;
                next_page += 1;
                page_of.insert(id, page);
                for c in refs_after(dict, b"/Contents") {
                    page_of.entry(c).or_insert(page);
                }
            }
            _ => {}
        }
    }
    page_of
}

/// Classify + label every committed indirect object of a traditional-xref PDF
/// (ADR-0029 §A). Returns descriptions in obj-id-ascending order — the same set
/// and order as the committed object manifest.
///
/// Errors only on a structurally unparseable PDF (propagated from
/// [`extract_object_spans`], e.g. a cross-reference-stream PDF); individual
/// objects that resist classification fall back to `kind == "other"`.
pub fn describe_objects(pdf_bytes: &[u8]) -> Result<Vec<ObjectDescription>, PdfObjectError> {
    let spans = extract_object_spans(pdf_bytes)?;

    // obj_id → span bytes (for dict + stream access) in ascending order.
    let span_bytes: BTreeMap<u32, &[u8]> = spans
        .iter()
        .map(|s| (s.obj_id, &pdf_bytes[s.byte_start..s.byte_end]))
        .collect();
    let dicts: BTreeMap<u32, &[u8]> = span_bytes
        .iter()
        .map(|(&id, &span)| (id, dict_region(span)))
        .collect();

    let page_of = resolve_pages(&dicts);
    // Content-stream object ids = every `/Page`'s `/Contents` target.
    let content_ids: HashSet<u32> = dicts
        .iter()
        .filter(|(_, d)| name_after(d, b"/Type").as_deref() == Some("Page"))
        .flat_map(|(_, d)| refs_after(d, b"/Contents"))
        .collect();

    let mut out = Vec::with_capacity(spans.len());
    for s in &spans {
        let span = span_bytes[&s.obj_id];
        let dict = dicts[&s.obj_id];
        let byte_length = (s.byte_end - s.byte_start) as u64;
        let page = page_of.get(&s.obj_id).copied();
        let ty = name_after(dict, b"/Type");
        let subtype = name_after(dict, b"/Subtype");

        let mut d = ObjectDescription {
            obj_id: s.obj_id,
            byte_length,
            kind: "other",
            label: String::new(),
            page,
            preview: None,
            width: None,
            height: None,
            filter: None,
            base_font: None,
            type_name: ty.clone(),
        };

        match (ty.as_deref(), subtype.as_deref()) {
            (Some("Catalog"), _) => {
                d.kind = "catalog";
                d.label = "Document catalog".into();
            }
            (Some("Pages"), _) => {
                d.kind = "pages";
                d.label = "Page tree".into();
            }
            (Some("Page"), _) => {
                d.kind = "page";
                d.label = match page {
                    Some(p) => format!("Page {p} (structure)"),
                    None => "Page (structure)".into(),
                };
            }
            (Some("Font"), _) => {
                d.kind = "font";
                d.base_font = name_after(dict, b"/BaseFont");
                d.label = match &d.base_font {
                    Some(b) => format!("Font: {b}"),
                    None => "Font".into(),
                };
            }
            (Some("Metadata"), _) => {
                d.kind = "metadata";
                d.label = "Document metadata (XMP)".into();
            }
            (Some("Annot"), _) => {
                d.kind = "annotation";
                d.label = "Annotation".into();
            }
            (Some("XObject"), Some("Image")) => {
                d.kind = "image";
                d.width = int_after(dict, b"/Width");
                d.height = int_after(dict, b"/Height");
                d.filter = name_after(dict, b"/Filter");
                let dims = match (d.width, d.height) {
                    (Some(w), Some(h)) => format!("{w}×{h}"),
                    _ => "image".into(),
                };
                d.label = match &d.filter {
                    Some(f) => format!("Image {dims} ({f})"),
                    None => format!("Image {dims}"),
                };
            }
            (Some("XObject"), Some("Form")) => {
                d.kind = "xobject_form";
                d.label = "Form XObject".into();
            }
            _ if content_ids.contains(&s.obj_id) => {
                d.kind = "content_stream";
                d.preview = content_stream_preview(span);
                d.label = match page {
                    Some(p) => format!("Page {p} — text"),
                    None => "Content stream — text".into(),
                };
            }
            (Some(t), _) => {
                d.kind = "other";
                d.label = format!("Object (/{t})");
            }
            (None, _) => {
                d.kind = "other";
                d.label = "Object".into();
            }
        }
        out.push(d);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid traditional-xref PDF (mirrors pdf_objects tests).
    fn build_pdf(bodies: &[&str]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = Vec::new();
        for (i, body) in bodies.iter().enumerate() {
            offsets.push(buf.len());
            buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            buf.extend_from_slice(body.as_bytes());
            buf.extend_from_slice(b"\nendobj\n");
        }
        let xref_off = buf.len();
        let n = bodies.len() + 1;
        buf.extend_from_slice(format!("xref\n0 {n}\n").as_bytes());
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets {
            buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
        buf.extend_from_slice(format!("trailer\n<< /Size {n} /Root 1 0 R >>\n").as_bytes());
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        buf
    }

    /// A document exercising every classified kind.
    fn rich_pdf() -> Vec<u8> {
        build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> /XObject << /Im0 6 0 R >> >> >>",
            "<< /Length 44 >>\nstream\nBT /F1 24 Tf 72 720 Td (Hello SECRET name) Tj ET\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Type /XObject /Subtype /Image /Width 800 /Height 600 /Filter /DCTDecode /Length 0 >>\nstream\n\nendstream",
            "<< /Type /Metadata /Subtype /XML /Length 0 >>\nstream\n\nendstream",
        ])
    }

    fn by_id(v: &[ObjectDescription], id: u32) -> &ObjectDescription {
        v.iter().find(|o| o.obj_id == id).expect("obj present")
    }

    #[test]
    fn classifies_each_object_kind() {
        let pdf = rich_pdf();
        let d = describe_objects(&pdf).unwrap();
        assert_eq!(d.len(), 7, "seven in-use objects");
        // Order is obj-id-ascending (same as the committed manifest).
        assert!(d.windows(2).all(|w| w[0].obj_id < w[1].obj_id));

        assert_eq!(by_id(&d, 1).kind, "catalog");
        assert_eq!(by_id(&d, 2).kind, "pages");
        assert_eq!(by_id(&d, 3).kind, "page");
        assert_eq!(by_id(&d, 4).kind, "content_stream");
        assert_eq!(by_id(&d, 5).kind, "font");
        assert_eq!(by_id(&d, 6).kind, "image");
        assert_eq!(by_id(&d, 7).kind, "metadata");
    }

    #[test]
    fn resolves_page_numbers_and_content_binding() {
        let d = describe_objects(&rich_pdf()).unwrap();
        // Page object and its content stream both bind to page 1.
        assert_eq!(by_id(&d, 3).page, Some(1));
        assert_eq!(by_id(&d, 4).page, Some(1));
        // Document-level objects have no page.
        assert_eq!(by_id(&d, 1).page, None);
        assert_eq!(by_id(&d, 5).page, None);
    }

    #[test]
    fn extracts_font_image_and_text_preview() {
        let d = describe_objects(&rich_pdf()).unwrap();
        assert_eq!(by_id(&d, 5).base_font.as_deref(), Some("Helvetica"));
        assert_eq!(by_id(&d, 5).label, "Font: Helvetica");

        let img = by_id(&d, 6);
        assert_eq!(img.width, Some(800));
        assert_eq!(img.height, Some(600));
        assert_eq!(img.filter.as_deref(), Some("DCTDecode"));
        assert_eq!(img.label, "Image 800×600 (DCTDecode)");

        // Uncompressed content stream → text preview of the shown string.
        let cs = by_id(&d, 4);
        assert_eq!(cs.label, "Page 1 — text");
        assert!(
            cs.preview
                .as_deref()
                .unwrap_or("")
                .contains("Hello SECRET name"),
            "preview was {:?}",
            cs.preview
        );
    }

    #[test]
    fn flate_compressed_content_stream_preview_inflates() {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write as _;
        let text = b"BT /F1 24 Tf 72 720 Td (Compressed body here) Tj ET";
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(text).unwrap();
        let comp = enc.finish().unwrap();

        // Hand-assemble so the stream body is the real zlib bytes.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.4\n");
        let mut offsets = Vec::new();
        let bodies: Vec<Vec<u8>> = vec![
            b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
            b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>".to_vec(),
            {
                let mut v = format!(
                    "<< /Length {} /Filter /FlateDecode >>\nstream\n",
                    comp.len()
                )
                .into_bytes();
                v.extend_from_slice(&comp);
                v.extend_from_slice(b"\nendstream");
                v
            },
        ];
        for (i, body) in bodies.iter().enumerate() {
            offsets.push(buf.len());
            buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            buf.extend_from_slice(body);
            buf.extend_from_slice(b"\nendobj\n");
        }
        let xref_off = buf.len();
        let n = bodies.len() + 1;
        buf.extend_from_slice(format!("xref\n0 {n}\n").as_bytes());
        buf.extend_from_slice(b"0000000000 65535 f \n");
        for off in &offsets {
            buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
        }
        buf.extend_from_slice(format!("trailer\n<< /Size {n} /Root 1 0 R >>\n").as_bytes());
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());

        let d = describe_objects(&buf).unwrap();
        let cs = by_id(&d, 4);
        assert_eq!(cs.kind, "content_stream");
        assert!(
            cs.preview
                .as_deref()
                .unwrap_or("")
                .contains("Compressed body here"),
            "inflated preview was {:?}",
            cs.preview
        );
    }

    #[test]
    fn unknown_type_falls_back_to_other() {
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R >>",
            "<< /Type /Bizarre /Foo 1 >>",
        ]);
        let d = describe_objects(&pdf).unwrap();
        let o = by_id(&d, 4);
        assert_eq!(o.kind, "other");
        assert_eq!(o.type_name.as_deref(), Some("Bizarre"));
        assert_eq!(o.label, "Object (/Bizarre)");
    }

    #[test]
    fn multi_page_numbers_ascend_in_document_order() {
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 5 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
            "<< /Length 20 >>\nstream\nBT (page one) Tj ET\nendstream",
            "<< /Type /Page /Parent 2 0 R /Contents 6 0 R >>",
            "<< /Length 20 >>\nstream\nBT (page two) Tj ET\nendstream",
        ]);
        let d = describe_objects(&pdf).unwrap();
        assert_eq!(by_id(&d, 3).page, Some(1));
        assert_eq!(by_id(&d, 4).page, Some(1));
        assert_eq!(by_id(&d, 5).page, Some(2));
        assert_eq!(by_id(&d, 6).page, Some(2));
    }

    #[test]
    fn cross_reference_stream_pdf_propagates_error() {
        // Same unsupported-PDF surface as extract_objects (no panic).
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"%PDF-1.5\n");
        let xref_off = buf.len();
        buf.extend_from_slice(
            b"7 0 obj\n<< /Type /XRef /Size 8 /W [1 2 1] /Root 1 0 R >>\nstream\n",
        );
        buf.extend_from_slice(&[0u8; 16]);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        assert!(describe_objects(&buf).is_err());
    }
}
