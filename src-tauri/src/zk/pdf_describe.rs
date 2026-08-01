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
//! Merkle root (ADR-0029 §A). It reuses the *same* extraction the matching
//! segmenter committed with — [`extract_object_spans`] for `pdf-object`,
//! [`logical_objects`] for `pdf-xref-stream` — so the described object set is
//! exactly the committed object set, in the same obj-id-ascending order.
//!
//! Both PDF object schemes are supported (ADR-0029 Phase A.5): classification
//! reads only an object's own dictionary and optional stream payload, which is
//! format-agnostic, so the two entry points differ solely in how they recover
//! each object's committed bytes.
//!
//! Byte-level only — no PDF renderer, no pdfium, no rasterizer (same discipline
//! as [`crate::zk::pdf_objects`]). Content-stream text previews inflate a single
//! `/FlateDecode` filter (the common case) and otherwise fall back to the raw
//! payload; exotic filter chains yield no preview (fail soft, never wrong).

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::zk::pdf_objects::{extract_object_spans, PdfObjectError};
use crate::zk::pdf_placement::{compute_placements, Placement};
use crate::zk::pdf_syntax::{
    decoded_stream, dict_region, int_after, name_after, refs_after, PREVIEW_INFLATE_CAP,
};
use crate::zk::segment::pdf_xref::logical_objects;
use crate::zk::segment::SegmentError;

/// Max characters of extracted text returned as a content-stream preview.
const PREVIEW_CHARS: usize = 200;
/// Guard against a pathological / cyclic page tree.
const MAX_PAGE_TREE_DEPTH: usize = 64;

/// One classified, human-presentable PDF indirect object (ADR-0029 §A).
///
/// `kind` is a stable snake_case tag the frontend switches on; the optional
/// structural fields are populated per kind. Serialised camelCase for the JS
/// producer UI.
// Not `Eq`: `placements` carries f32 page geometry.
#[derive(Debug, Clone, Serialize, PartialEq)]
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
    /// Where this object paints, in PDF user space (ADR-0029 A.5-2) — the input
    /// to the producer UI's drag-box hit-test. Empty for document-level objects
    /// that have no position, or when the geometry could not be resolved (the
    /// UI then falls back to the object checklist). An image painted more than
    /// once has one entry per paint.
    pub placements: Vec<Placement>,
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
///
/// The inflation is capped at [`PREVIEW_INFLATE_CAP`] so a decompression bomb
/// can't blow memory for a mere preview — only the first [`PREVIEW_CHARS`] of
/// text are ever shown.
fn content_stream_preview(span: &[u8]) -> Option<String> {
    preview_from_stream(&decoded_stream(span, PREVIEW_INFLATE_CAP)?)
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
/// [`extract_object_spans`], e.g. a cross-reference-stream PDF — use
/// [`describe_objects_xref_stream`] for those); individual objects that resist
/// classification fall back to `kind == "other"`.
pub fn describe_objects(pdf_bytes: &[u8]) -> Result<Vec<ObjectDescription>, PdfObjectError> {
    let spans = extract_object_spans(pdf_bytes)?;

    // obj_id → span bytes (for dict + stream access) in ascending order. For the
    // traditional scheme the committed region is the whole `N G obj … endobj`
    // span, so it is both the classification input and the reported byte length.
    let regions: BTreeMap<u32, &[u8]> = spans
        .iter()
        .map(|s| (s.obj_id, &pdf_bytes[s.byte_start..s.byte_end]))
        .collect();

    Ok(describe_regions(&regions))
}

/// Classify + label every committed indirect object of a **modern** PDF — one
/// with a cross-reference stream, whose objects may live inside object streams
/// (ADR-0028). The `pdf-xref-stream` counterpart of [`describe_objects`], added
/// for ADR-0029 Phase A.5 so the producer UI labels modern PDFs instead of
/// falling back to raw object numbers.
///
/// The classification itself is format-agnostic — it reads the object's own
/// dictionary — so both schemes share [`describe_regions`]. The only difference
/// is how the per-object bytes are recovered: [`extract_object_spans`] for the
/// traditional scheme, [`logical_objects`] for this one.
///
/// The reported `byte_length` is the **logical body** length, matching what
/// `ModernPdfSegmenter::extract` commits as the segment's `byte_length` (the
/// body between `obj` and `endobj`, trimmed) — not the framed span, which the
/// modern scheme never commits. Returns descriptions in obj-id-ascending order,
/// the same set and order as the committed object manifest.
///
/// Errors only on a structurally unparseable modern PDF (propagated from
/// [`logical_objects`]); individual objects that resist classification fall back
/// to `kind == "other"`.
pub fn describe_objects_xref_stream(
    pdf_bytes: &[u8],
) -> Result<Vec<ObjectDescription>, SegmentError> {
    let bodies = logical_objects(pdf_bytes)?;

    // `logical_objects` yields owned bodies (an object-stream member is decoded,
    // so it has no slice in the original file); borrow them for classification.
    let regions: BTreeMap<u32, &[u8]> = bodies
        .iter()
        .map(|(&id, (_generation, body))| (id, body.as_slice()))
        .collect();

    Ok(describe_regions(&regions))
}

/// Classify + label a set of PDF indirect objects given each one's committed
/// byte region, in obj-id-ascending order.
///
/// The shared core of [`describe_objects`] and [`describe_objects_xref_stream`].
/// A region is whatever the format commits for that object — the framed
/// `N G obj … endobj` span for `pdf-object`, the trimmed logical body for
/// `pdf-xref-stream`. Both carry the object's dictionary followed by an optional
/// `stream … endstream` payload, which is all the classification reads, and both
/// report `byte_length` as the region's own length so it matches the manifest.
///
/// Infallible: an object that resists classification degrades to `kind ==
/// "other"` rather than failing the whole listing (a partial listing would hide
/// objects the operator then could not select to redact).
fn describe_regions(regions: &BTreeMap<u32, &[u8]>) -> Vec<ObjectDescription> {
    let dicts: BTreeMap<u32, &[u8]> = regions
        .iter()
        .map(|(&id, &region)| (id, dict_region(region)))
        .collect();

    let page_of = resolve_pages(&dicts);
    // Content-stream object ids = every `/Page`'s `/Contents` target.
    let content_ids: HashSet<u32> = dicts
        .iter()
        .filter(|(_, d)| name_after(d, b"/Type").as_deref() == Some("Page"))
        .flat_map(|(_, d)| refs_after(d, b"/Contents"))
        .collect();
    // Where each object paints (ADR-0029 A.5-2). Computed once for the whole
    // document because a form XObject can be drawn from several pages.
    let mut placements = compute_placements(regions, &dicts, &page_of);

    let mut out = Vec::with_capacity(regions.len());
    for (&obj_id, &span) in regions {
        let dict = dicts[&obj_id];
        let byte_length = span.len() as u64;
        let page = page_of.get(&obj_id).copied();
        let ty = name_after(dict, b"/Type");
        let subtype = name_after(dict, b"/Subtype");

        let mut d = ObjectDescription {
            obj_id,
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
            placements: placements.remove(&obj_id).unwrap_or_default(),
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
            _ if content_ids.contains(&obj_id) => {
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
    out
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
    fn scope_aware_parsing_ignores_nested_dict_keys() {
        // The page's /Resources nests `/Type /Font` and an image's
        // `/Subtype /Image /Width 999` BEFORE the page's own top-level
        // `/Type /Page`. Naive first-occurrence parsing would misclassify the
        // page as a font (and break page resolution); scope-aware (depth-1)
        // parsing must read only the page's own attributes.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Resources << /Font << /F1 << /Type /Font /Subtype /Type1 >> >> /XObject << /Im << /Subtype /Image /Width 999 /Height 999 >> >> >> /Type /Page /Contents 4 0 R >>",
            "<< /Length 10 >>\nstream\nBT (x) Tj ET\nendstream",
        ]);
        let d = describe_objects(&pdf).unwrap();
        let page = by_id(&d, 3);
        assert_eq!(
            page.kind, "page",
            "nested /Type /Font must not win over the page's own /Type /Page"
        );
        assert_eq!(page.page, Some(1), "page resolution must still work");
        assert_eq!(
            page.width, None,
            "nested /Width must not leak onto the page"
        );
        // The content stream still binds to page 1.
        assert_eq!(by_id(&d, 4).kind, "content_stream");
        assert_eq!(by_id(&d, 4).page, Some(1));
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

    // ── ADR-0029 Phase A.5: modern (cross-reference-stream) PDFs ──────────────

    fn zlib(data: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a modern PDF from the **same object bodies** as [`build_pdf`], so
    /// the two schemes can be compared object-for-object. `objstm_ids` are packed
    /// into an object stream (exercising the type-2 path); the rest stay direct.
    /// Two extra objects are appended — the ObjStm container and the /XRef stream
    /// — which are structural and must never appear in the described set.
    fn build_modern_pdf(bodies: &[&str], objstm_ids: &[u32]) -> Vec<u8> {
        let n = bodies.len() as u32;
        let objstm_id = n + 1;
        let xref_id = n + 2;

        let mut buf: Vec<u8> = b"%PDF-1.7\n".to_vec();
        let mut direct: BTreeMap<u32, usize> = BTreeMap::new();
        let mut packed: Vec<(u32, &str)> = Vec::new();

        for (i, body) in bodies.iter().enumerate() {
            let id = i as u32 + 1;
            if objstm_ids.contains(&id) {
                packed.push((id, body));
                continue;
            }
            direct.insert(id, buf.len());
            buf.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
            buf.extend_from_slice(body.as_bytes());
            buf.extend_from_slice(b"\nendobj\n");
        }

        // ObjStm: a `objnum rel_offset` header, then the member bodies.
        let mut header = String::new();
        let mut payload: Vec<u8> = Vec::new();
        for (id, body) in &packed {
            header.push_str(&format!("{id} {} ", payload.len()));
            payload.extend_from_slice(body.as_bytes());
        }
        let mut objstm_body = header.into_bytes();
        let first = objstm_body.len();
        objstm_body.extend_from_slice(&payload);
        let objstm_z = zlib(&objstm_body);
        let objstm_off = buf.len();
        buf.extend_from_slice(
            format!(
                "{objstm_id} 0 obj\n<< /Type /ObjStm /N {} /First {first} /Length {} \
                 /Filter /FlateDecode >>\nstream\n",
                packed.len(),
                objstm_z.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&objstm_z);
        buf.extend_from_slice(b"\nendstream\nendobj\n");

        // /XRef stream with /W [1 4 2]: type, field2 (offset | stream objnum),
        // field3 (generation | index in stream).
        let xref_off = buf.len();
        let mut rows: Vec<u8> = Vec::new();
        let push = |rows: &mut Vec<u8>, t: u8, f2: u32, f3: u16| {
            rows.push(t);
            rows.extend_from_slice(&f2.to_be_bytes());
            rows.extend_from_slice(&f3.to_be_bytes());
        };
        push(&mut rows, 0, 0, 65535);
        for id in 1..=n {
            match direct.get(&id) {
                Some(&off) => push(&mut rows, 1, off as u32, 0),
                None => {
                    let idx = packed
                        .iter()
                        .position(|(p, _)| *p == id)
                        .expect("packed member") as u16;
                    push(&mut rows, 2, objstm_id, idx);
                }
            }
        }
        push(&mut rows, 1, objstm_off as u32, 0);
        push(&mut rows, 1, xref_off as u32, 0);
        let xref_z = zlib(&rows);
        buf.extend_from_slice(
            format!(
                "{xref_id} 0 obj\n<< /Type /XRef /Size {} /W [1 4 2] /Root 1 0 R /Length {} \
                 /Filter /FlateDecode >>\nstream\n",
                xref_id + 1,
                xref_z.len()
            )
            .as_bytes(),
        );
        buf.extend_from_slice(&xref_z);
        buf.extend_from_slice(b"\nendstream\nendobj\n");
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        buf
    }

    /// The object bodies of [`rich_pdf`], indexable by `obj_id - 1`, so tests can
    /// assert against the exact bytes a scheme committed.
    fn rich_bodies() -> [&'static str; 7] {
        [
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> /XObject << /Im0 6 0 R >> >> >>",
            "<< /Length 44 >>\nstream\nBT /F1 24 Tf 72 720 Td (Hello SECRET name) Tj ET\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            "<< /Type /XObject /Subtype /Image /Width 800 /Height 600 /Filter /DCTDecode /Length 0 >>\nstream\n\nendstream",
            "<< /Type /Metadata /Subtype /XML /Length 0 >>\nstream\n\nendstream",
        ]
    }

    /// Object ids packed into the fixture's object stream. Stream objects must be
    /// direct (a PDF stream cannot live inside an ObjStm), so these are the three
    /// non-stream objects.
    const RICH_MODERN_OBJSTM_IDS: &[u32] = &[2, 3, 5];

    /// The same logical document as [`rich_pdf`], stored the modern way, with the
    /// non-stream objects (page tree, page, font) packed into an object stream.
    fn rich_modern_pdf() -> Vec<u8> {
        build_modern_pdf(&rich_bodies(), RICH_MODERN_OBJSTM_IDS)
    }

    #[test]
    fn classifies_each_object_kind_on_a_modern_pdf() {
        let d = describe_objects_xref_stream(&rich_modern_pdf()).unwrap();

        assert_eq!(by_id(&d, 1).kind, "catalog");
        // Packed inside the ObjStm — the type-2 path classifies identically.
        assert_eq!(by_id(&d, 2).kind, "pages");
        assert_eq!(by_id(&d, 3).kind, "page");
        assert_eq!(by_id(&d, 3).page, Some(1));
        assert_eq!(by_id(&d, 5).kind, "font");
        assert_eq!(by_id(&d, 5).base_font.as_deref(), Some("Helvetica"));

        // Direct stream objects.
        assert_eq!(by_id(&d, 4).kind, "content_stream");
        assert_eq!(by_id(&d, 4).page, Some(1));
        assert!(by_id(&d, 4)
            .preview
            .as_deref()
            .is_some_and(|p| p.contains("SECRET")));
        assert_eq!(by_id(&d, 6).kind, "image");
        assert_eq!(by_id(&d, 6).width, Some(800));
        assert_eq!(by_id(&d, 6).height, Some(600));
        assert_eq!(by_id(&d, 7).kind, "metadata");
    }

    #[test]
    fn modern_describe_excludes_structural_containers() {
        // The ObjStm (8) and the /XRef stream (9) are not document content and are
        // never committed, so they must not be offered as redactable objects.
        let d = describe_objects_xref_stream(&rich_modern_pdf()).unwrap();
        let ids: Vec<u32> = d.iter().map(|o| o.obj_id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn modern_and_traditional_describe_identically() {
        // Phase A.5's core claim: the *classification* is format-agnostic, so the
        // same logical document describes the same way under either scheme.
        let trad = describe_objects(&rich_pdf()).unwrap();
        let modern = describe_objects_xref_stream(&rich_modern_pdf()).unwrap();

        assert_eq!(trad.len(), modern.len());
        for (t, m) in trad.iter().zip(modern.iter()) {
            assert_eq!(t.obj_id, m.obj_id);
            assert_eq!(t.kind, m.kind, "kind differs for #{}", t.obj_id);
            assert_eq!(t.label, m.label, "label differs for #{}", t.obj_id);
            assert_eq!(t.page, m.page, "page differs for #{}", t.obj_id);
            assert_eq!(t.preview, m.preview, "preview differs for #{}", t.obj_id);
            assert_eq!(t.width, m.width);
            assert_eq!(t.height, m.height);
            assert_eq!(t.filter, m.filter);
            assert_eq!(t.base_font, m.base_font);
            assert_eq!(t.type_name, m.type_name);
        }
    }

    #[test]
    fn byte_length_matches_each_scheme_s_committed_region() {
        // Deliberately NOT equal across schemes: `pdf-object` commits the framed
        // `N G obj … endobj` span, `pdf-xref-stream` commits the trimmed logical
        // body. Each reports what its own manifest pins, so the UI's size bars
        // stay consistent with the committed segment.
        let trad = describe_objects(&rich_pdf()).unwrap();
        let modern = describe_objects_xref_stream(&rich_modern_pdf()).unwrap();

        let body = |id: u32| rich_bodies()[id as usize - 1];

        // Object 1 is stored directly, so its body is delimited by `endobj`.
        assert_eq!(by_id(&modern, 1).byte_length, body(1).len() as u64);
        // The framed span carries `1 0 obj\n` + `\n` + `endobj`, so it is strictly
        // longer than the body it wraps.
        assert!(by_id(&trad, 1).byte_length > by_id(&modern, 1).byte_length);

        // Objects 2/3/5 live *inside* the ObjStm, where members are concatenated
        // with no delimiter — their lengths come from the header's relative-offset
        // arithmetic, not from an `endobj`. Cover both arms of it: a middle member
        // bounded by the next member's offset (2, 3) and the last member bounded by
        // the end of the decoded stream (5). Without these, an off-by-one or an
        // over-eager trim on the type-2 path would drift a committed segment's
        // reported size silently.
        for id in RICH_MODERN_OBJSTM_IDS {
            assert_eq!(
                by_id(&modern, *id).byte_length,
                body(*id).len() as u64,
                "ObjStm member #{id} byte_length"
            );
        }
    }

    #[test]
    fn traditional_pdf_is_rejected_by_the_modern_describe() {
        // Fail closed rather than mislabel: a classic xref table is not an xref
        // stream, so the modern entry point must error instead of guessing. The
        // endpoint picks the entry point from the committed manifest format.
        assert!(describe_objects_xref_stream(&rich_pdf()).is_err());
    }

    #[test]
    fn malformed_modern_pdf_propagates_error() {
        let mut pdf = rich_modern_pdf();
        // Point startxref at a garbage offset: the xref stream can no longer be
        // parsed, so no object set can be recovered.
        let sx = pdf
            .windows(9)
            .rposition(|w| w == b"startxref")
            .expect("startxref present");
        pdf.truncate(sx);
        pdf.extend_from_slice(b"startxref\n999999999\n%%EOF\n");
        assert!(describe_objects_xref_stream(&pdf).is_err());
    }
}
