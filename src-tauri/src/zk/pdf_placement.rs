// SPDX-License-Identifier: Apache-2.0

//! ADR-0029 Phase A.5-2: **where on the page** each committed object paints.
//!
//! [`crate::zk::pdf_describe`] answers *what* an object is ("Image 800×600").
//! This module answers *where it is*, so the producer UI can render a page,
//! let the user drag a box, and resolve that box to the object ids underneath
//! it — instead of asking them to guess object numbers.
//!
//! Placements are rectangles in **PDF user space**: origin bottom-left, y
//! upwards, in points. The frontend maps them to canvas coordinates; nothing
//! here knows about pixels.
//!
//! **Presentation only, like the rest of A.5.** Geometry is recomputed on demand
//! from the uploaded bytes and is never persisted, never re-ingested, and never
//! touches a hiding leaf, the manifest, or the Merkle root (ADR-0029 §A). A
//! renderer can mislead a human; it cannot change what is committed or cut. The
//! redaction request re-validates every selected id against the committed
//! manifest regardless of what geometry was shown.
//!
//! **Byte-level only** — no PDF renderer, no pdfium, no rasterizer (the
//! discipline of [`crate::zk::pdf_objects`]). We interpret just enough of the
//! content-stream graphics model to know where a `Do` lands: the CTM, `q`/`Q`
//! nesting, and form-XObject recursion. Everything else is skipped.
//!
//! Fail-soft throughout: an object whose geometry cannot be resolved simply gets
//! no placement, and the UI falls back to the object checklist. A *missing*
//! placement costs the user a nicety; a *wrong* one would mislead them about
//! what a box covers, so every uncertain case yields nothing rather than a guess.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Serialize;

use crate::zk::pdf_syntax::{
    decoded_stream, dict_region, find_top_level, is_delim, is_ws, name_after, reals_after,
    refs_after, CONTENT_INFLATE_CAP,
};

/// Deepest form-XObject nesting followed. Forms can legally nest; a cyclic or
/// pathological document must not recurse without bound.
const MAX_FORM_DEPTH: usize = 8;
/// Cap on placements reported for one object. A tiled background image can be
/// painted thousands of times; the UI only needs enough rects to hit-test, and
/// an unbounded list would bloat the response.
const MAX_PLACEMENTS_PER_OBJECT: usize = 64;
/// Guard against a pathological `/Parent` chain when inheriting `/MediaBox`.
const MAX_PARENT_DEPTH: usize = 64;
/// Deepest `q` nesting tracked. Beyond this the stream is not something we can
/// model faithfully, so the walk stops rather than report drifting geometry.
const MAX_GRAPHICS_STACK: usize = 64;

/// A 2-D affine transform in PDF's `[a b c d e f]` order.
type Matrix = [f32; 6];

const IDENTITY: Matrix = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];

/// Where one object paints, in PDF user space (origin bottom-left, y up).
///
/// An object can have several placements — an image painted twice, a form drawn
/// on two pages. Serialised camelCase for the producer UI.
#[derive(Debug, Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Placement {
    /// 1-based page this rectangle is on.
    pub page: u32,
    /// Left edge (points from the page's left).
    pub x: f32,
    /// **Bottom** edge (points from the page's bottom — PDF user space, not
    /// screen space).
    pub y: f32,
    /// Width in points.
    pub w: f32,
    /// Height in points.
    pub h: f32,
}

/// `m × n` — apply `m`, then `n`. This is the order the `cm` operator wants:
/// the operand matrix is concatenated *onto* the current transform.
fn mul(m: Matrix, n: Matrix) -> Matrix {
    [
        m[0] * n[0] + m[1] * n[2],
        m[0] * n[1] + m[1] * n[3],
        m[2] * n[0] + m[3] * n[2],
        m[2] * n[1] + m[3] * n[3],
        m[4] * n[0] + m[5] * n[2] + n[4],
        m[4] * n[1] + m[5] * n[3] + n[5],
    ]
}

fn apply(m: Matrix, x: f32, y: f32) -> (f32, f32) {
    (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5])
}

/// The axis-aligned bounding box of the rectangle `(x0,y0)-(x1,y1)` under `m`.
///
/// Returns `None` for a degenerate or non-finite result (a zero-scale CTM, or
/// arithmetic that overflowed): a zero-area rect can't be hit-tested and a
/// non-finite one would serialise as `null`/`NaN` into the API response.
fn transform_rect(rect: [f32; 4], m: Matrix, page: u32) -> Option<Placement> {
    let [x0, y0, x1, y1] = rect;
    let corners = [
        apply(m, x0, y0),
        apply(m, x1, y0),
        apply(m, x0, y1),
        apply(m, x1, y1),
    ];
    if corners
        .iter()
        .any(|(x, y)| !x.is_finite() || !y.is_finite())
    {
        return None;
    }
    let (mut x0, mut y0) = corners[0];
    let (mut x1, mut y1) = corners[0];
    for &(x, y) in &corners[1..] {
        x0 = x0.min(x);
        y0 = y0.min(y);
        x1 = x1.max(x);
        y1 = y1.max(y);
    }
    let (w, h) = (x1 - x0, y1 - y0);
    if w <= 0.0 || h <= 0.0 {
        return None;
    }
    Some(Placement {
        page,
        x: x0,
        y: y0,
        w,
        h,
    })
}

// ── dictionary navigation ─────────────────────────────────────────────────────

/// The `<< … >>` region that is `key`'s value inside `region`, following one
/// indirect reference (`/Resources 9 0 R`) through `regions` if needed.
///
/// Returns the slice **including** the outer `<<`/`>>` so the result can be fed
/// straight back in for the next level of nesting.
fn dict_value<'a>(
    region: &'a [u8],
    key: &[u8],
    regions: &BTreeMap<u32, &'a [u8]>,
) -> Option<&'a [u8]> {
    let start = find_top_level(region, key)? + key.len();
    let mut i = start;
    while i < region.len() && is_ws(region[i]) {
        i += 1;
    }
    // Indirect: `/Resources 9 0 R` → resolve the target object's dictionary.
    if i < region.len() && region[i].is_ascii_digit() {
        let id = *refs_after(region, key).first()?;
        return regions.get(&id).map(|r| dict_region(r));
    }
    // Direct: scan the balanced `<< … >>`.
    if region.get(i..i + 2) != Some(b"<<") {
        return None;
    }
    let open = i;
    let mut depth = 0i32;
    while i < region.len() {
        match region[i] {
            b'(' => {
                // A literal string's bytes are not structural.
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
            b'<' if region.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
            }
            b'>' if region.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                i += 2;
                if depth == 0 {
                    return Some(&region[open..i]);
                }
            }
            _ => i += 1,
        }
    }
    None
}

/// The `/Name → object id` entries at the top level of an XObject dictionary
/// (`<< /Im0 6 0 R /Fm1 7 0 R >>`).
fn name_to_ref(region: &[u8]) -> HashMap<Vec<u8>, u32> {
    let mut out = HashMap::new();
    let mut depth = 0i32;
    let mut i = 0;
    while i < region.len() {
        match region[i] {
            b'<' if region.get(i + 1) == Some(&b'<') => {
                depth += 1;
                i += 2;
            }
            b'>' if region.get(i + 1) == Some(&b'>') => {
                depth -= 1;
                i += 2;
            }
            b'/' if depth == 1 => {
                let ns = i + 1;
                let mut e = ns;
                while e < region.len() && !is_delim(region[e]) {
                    e += 1;
                }
                let name = region[ns..e].to_vec();
                // `refs_after` needs the key including its slash.
                if let Some(&id) = refs_after(region, &region[i..e]).first() {
                    out.insert(name, id);
                }
                i = e.max(i + 1);
            }
            _ => i += 1,
        }
    }
    out
}

/// A page's `/MediaBox`, inheriting through the `/Parent` chain as the PDF spec
/// requires (most real documents declare it once on the root `/Pages`).
fn media_box(page_id: u32, dicts: &BTreeMap<u32, &[u8]>) -> Option<[f32; 4]> {
    let mut id = page_id;
    let mut seen = HashSet::new();
    for _ in 0..MAX_PARENT_DEPTH {
        if !seen.insert(id) {
            return None; // cyclic /Parent chain
        }
        let dict = dicts.get(&id)?;
        let mb = reals_after(dict, b"/MediaBox");
        if mb.len() >= 4 {
            let (x0, y0) = (mb[0].min(mb[2]), mb[1].min(mb[3]));
            let (x1, y1) = (mb[0].max(mb[2]), mb[1].max(mb[3]));
            if x1 > x0 && y1 > y0 {
                return Some([x0, y0, x1 - x0, y1 - y0]);
            }
            return None; // declared but degenerate — don't invent a page size
        }
        id = *refs_after(dict, b"/Parent").first()?;
    }
    None
}

// ── content-stream walking ────────────────────────────────────────────────────

/// Read a PDF name token starting at `/`. Returns the name (without the slash)
/// and the index just past it.
fn read_name(b: &[u8], at: usize) -> (&[u8], usize) {
    let start = at + 1;
    let mut i = start;
    while i < b.len() && !is_delim(b[i]) {
        i += 1;
    }
    (&b[start..i], i.max(at + 1))
}

/// Read a numeric token. Returns `None` for a malformed number (which is then
/// skipped rather than treated as zero — a bogus operand would silently corrupt
/// the CTM).
fn read_number(b: &[u8], at: usize) -> (Option<f32>, usize) {
    let mut i = at;
    if matches!(b[i], b'+' | b'-') {
        i += 1;
    }
    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
        i += 1;
    }
    let v = std::str::from_utf8(&b[at..i])
        .ok()
        .and_then(|s| s.parse::<f32>().ok())
        .filter(|v| v.is_finite());
    (v, i.max(at + 1))
}

/// Skip a balanced `( … )` literal string, honouring backslash escapes.
fn skip_literal_string(b: &[u8], at: usize) -> usize {
    let mut i = at + 1;
    let mut depth = 1u32;
    while i < b.len() && depth > 0 {
        match b[i] {
            b'\\' => i += 2,
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

/// Skip an inline image (`BI … ID <binary> EI`).
///
/// This matters for correctness, not just speed: the bytes between `ID` and `EI`
/// are raw image data that can contain anything — including the sequence `Do` —
/// so a scanner that walked through them could hallucinate a paint operation.
fn skip_inline_image(b: &[u8], at: usize) -> usize {
    let Some(id) = b[at..].windows(2).position(|w| w == b"ID") else {
        return b.len();
    };
    let mut i = at + id + 2;
    // `EI` is delimited by whitespace on both sides; scan for that, not a bare
    // `EI` which could occur inside the binary payload.
    while i + 2 < b.len() {
        if b[i].is_ascii_whitespace()
            && &b[i + 1..i + 3] == b"EI"
            && b.get(i + 3).is_none_or(|&c| is_ws(c) || is_delim(c))
        {
            return i + 3;
        }
        i += 1;
    }
    b.len()
}

/// Everything the walk needs that doesn't change as it recurses.
struct Ctx<'a> {
    regions: &'a BTreeMap<u32, &'a [u8]>,
    dicts: &'a BTreeMap<u32, &'a [u8]>,
    out: BTreeMap<u32, Vec<Placement>>,
}

impl Ctx<'_> {
    fn record(&mut self, obj_id: u32, p: Placement) {
        let slot = self.out.entry(obj_id).or_default();
        if slot.len() < MAX_PLACEMENTS_PER_OBJECT {
            slot.push(p);
        }
    }
}

/// Interpret `content` far enough to locate every `Do`, recording where each
/// painted XObject lands.
///
/// `xobjects` maps the resource names visible in this stream to object ids;
/// `active` carries the form-XObject ids currently on the recursion stack so a
/// form that draws itself terminates.
fn walk(
    content: &[u8],
    page: u32,
    ctm: Matrix,
    xobjects: &HashMap<Vec<u8>, u32>,
    ctx: &mut Ctx,
    active: &mut HashSet<u32>,
    depth: usize,
) {
    let mut stack: Vec<Matrix> = Vec::new();
    let mut ctm = ctm;
    let mut nums: Vec<f32> = Vec::new();
    let mut last_name: Option<Vec<u8>> = None;
    let mut i = 0;

    while i < content.len() {
        let b = content[i];
        if is_ws(b) {
            i += 1;
            continue;
        }
        match b {
            b'%' => {
                while i < content.len() && content[i] != b'\n' && content[i] != b'\r' {
                    i += 1;
                }
            }
            b'(' => i = skip_literal_string(content, i),
            // Hex string or dictionary — neither contributes an operand we use.
            b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b')' => i += 1,
            b'/' => {
                let (name, ni) = read_name(content, i);
                last_name = Some(name.to_vec());
                i = ni;
            }
            b'+' | b'-' | b'.' | b'0'..=b'9' => {
                let (v, ni) = read_number(content, i);
                if let Some(v) = v {
                    nums.push(v);
                }
                i = ni;
            }
            _ => {
                let start = i;
                while i < content.len() && !is_ws(content[i]) && !is_delim(content[i]) {
                    i += 1;
                }
                let op = &content[start..i.max(start + 1)];
                match op {
                    b"q" => {
                        if stack.len() >= MAX_GRAPHICS_STACK {
                            return; // unmodellable nesting — stop, don't drift
                        }
                        stack.push(ctm);
                    }
                    b"Q" => {
                        if let Some(prev) = stack.pop() {
                            ctm = prev;
                        }
                    }
                    b"cm" if nums.len() >= 6 => {
                        let m: Matrix = nums[nums.len() - 6..].try_into().unwrap_or(IDENTITY);
                        ctm = mul(m, ctm);
                    }
                    b"BI" => i = skip_inline_image(content, i),
                    b"Do" => {
                        if let Some(id) =
                            last_name.as_deref().and_then(|n| xobjects.get(n)).copied()
                        {
                            paint(id, page, ctm, ctx, active, depth);
                        }
                    }
                    _ => {}
                }
                // Operands belong to the operator that just consumed them.
                nums.clear();
                last_name = None;
            }
        }
    }
}

/// Record where XObject `id` lands under `ctm`, recursing into it if it is a
/// form.
fn paint(id: u32, page: u32, ctm: Matrix, ctx: &mut Ctx, active: &mut HashSet<u32>, depth: usize) {
    let Some(&span) = ctx.regions.get(&id) else {
        return;
    };
    let dict = dict_region(span);

    match name_after(dict, b"/Subtype").as_deref() {
        // `Do` paints an image into the **unit square**; the CTM places it. That
        // makes the transformed unit square exactly the area it covers.
        Some("Image") => {
            if let Some(p) = transform_rect([0.0, 0.0, 1.0, 1.0], ctm, page) {
                ctx.record(id, p);
            }
            return;
        }
        Some("Form") => {}
        // An XObject with no or an unrecognised `/Subtype` is malformed. Its
        // extent is unknowable, and a wrong rect is worse than none.
        _ => return,
    }

    // A form's own space is `/Matrix` (default identity) concatenated onto the
    // CTM in force where it was invoked.
    let m = reals_after(dict, b"/Matrix");
    let inner = if m.len() >= 6 {
        mul(m[..6].try_into().unwrap_or(IDENTITY), ctm)
    } else {
        ctm
    };

    // A form's extent is its `/BBox` (spec-required), NOT the unit square — a
    // form is a coordinate system, not an image. Without a usable `/BBox` the
    // form itself gets no rect, though we still recurse to place what it draws.
    let bbox = reals_after(dict, b"/BBox");
    if bbox.len() >= 4 {
        let rect = [
            bbox[0].min(bbox[2]),
            bbox[1].min(bbox[3]),
            bbox[0].max(bbox[2]),
            bbox[1].max(bbox[3]),
        ];
        if let Some(p) = transform_rect(rect, inner, page) {
            ctx.record(id, p);
        }
    }

    if depth >= MAX_FORM_DEPTH || !active.insert(id) {
        return; // too deep, or this form is already on the stack (cycle)
    }
    let resources = dict_value(dict, b"/Resources", ctx.regions)
        .and_then(|r| dict_value(r, b"/XObject", ctx.regions))
        .map(name_to_ref)
        .unwrap_or_default();

    if let Some(content) = decoded_stream(span, CONTENT_INFLATE_CAP) {
        walk(&content, page, inner, &resources, ctx, active, depth + 1);
    }
    active.remove(&id);
}

// ── entry point ───────────────────────────────────────────────────────────────

/// Resolve where every committed object paints.
///
/// * **Image / form XObjects** — one rect per `Do` that paints them, obtained by
///   transforming the unit square by the CTM in force at that operator.
/// * **Content streams** — their owning page's `/MediaBox`. Honest rather than
///   precise: redacting a content stream blanks the *whole* page, and the UI must
///   show that up front instead of implying a tighter region (this is the
///   over-redaction-is-surfaced rule, ADR-0029 §5).
/// * **Document-level objects** (catalog, page tree, fonts, metadata) — none;
///   they have no position on any page.
///
/// `regions`/`dicts`/`page_of` come from the caller's already-parsed object set,
/// so this adds no second parse of the document.
pub(crate) fn compute_placements(
    regions: &BTreeMap<u32, &[u8]>,
    dicts: &BTreeMap<u32, &[u8]>,
    page_of: &HashMap<u32, u32>,
) -> BTreeMap<u32, Vec<Placement>> {
    let mut ctx = Ctx {
        regions,
        dicts,
        out: BTreeMap::new(),
    };

    for (&page_id, &dict) in dicts {
        if name_after(dict, b"/Type").as_deref() != Some("Page") {
            continue;
        }
        let Some(&page) = page_of.get(&page_id) else {
            continue; // page outside the resolvable /Pages tree
        };
        let box_ = media_box(page_id, ctx.dicts);

        // The page's content stream(s) cover the whole page.
        let content_ids = refs_after(dict, b"/Contents");
        if let Some([x, y, w, h]) = box_ {
            for cid in &content_ids {
                ctx.record(*cid, Placement { page, x, y, w, h });
            }
        }

        let xobjects = dict_value(dict, b"/Resources", regions)
            .and_then(|r| dict_value(r, b"/XObject", regions))
            .map(name_to_ref)
            .unwrap_or_default();
        if xobjects.is_empty() {
            continue; // nothing on this page can be placed by a `Do`
        }

        // PDF concatenates a page's content streams into one stream; a token can
        // legally straddle the boundary, so join before walking.
        let mut content = Vec::new();
        for cid in &content_ids {
            if let Some(part) = regions
                .get(cid)
                .and_then(|s| decoded_stream(s, CONTENT_INFLATE_CAP))
            {
                content.extend_from_slice(&part);
                content.push(b'\n');
            }
        }
        let mut active = HashSet::new();
        walk(
            &content,
            page,
            IDENTITY,
            &xobjects,
            &mut ctx,
            &mut active,
            0,
        );
    }

    ctx.out
}

#[cfg(test)]
mod tests {
    use crate::zk::pdf_describe::{describe_objects, ObjectDescription};

    /// Minimal traditional-xref PDF from raw object bodies (obj `i+1` = `bodies[i]`).
    fn build_pdf(bodies: &[&str]) -> Vec<u8> {
        let mut buf: Vec<u8> = b"%PDF-1.4\n".to_vec();
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
            buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        buf.extend_from_slice(format!("trailer\n<< /Size {n} /Root 1 0 R >>\n").as_bytes());
        buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
        buf
    }

    fn stream_obj(dict: &str, payload: &str) -> String {
        format!(
            "<< {dict} /Length {} >>\nstream\n{payload}\nendstream",
            payload.len()
        )
    }

    fn by_id(v: &[ObjectDescription], id: u32) -> &ObjectDescription {
        v.iter().find(|o| o.obj_id == id).expect("obj present")
    }

    /// `MediaBox` on the page, one image resource, caller-supplied content.
    fn image_page_pdf(content: &str) -> Vec<u8> {
        build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
             /Resources << /XObject << /Im0 5 0 R >> >> >>",
            &stream_obj("", content),
            &stream_obj(
                "/Type /XObject /Subtype /Image /Width 800 /Height 600 /Filter /DCTDecode",
                "",
            ),
        ])
    }

    fn assert_rect(p: &super::Placement, page: u32, x: f32, y: f32, w: f32, h: f32) {
        assert_eq!(p.page, page, "page");
        for (label, got, want) in [("x", p.x, x), ("y", p.y, y), ("w", p.w, w), ("h", p.h, h)] {
            assert!(
                (got - want).abs() < 0.01,
                "{label}: got {got}, want {want} (rect {p:?})"
            );
        }
    }

    #[test]
    fn image_placement_is_the_ctm_applied_to_the_unit_square() {
        let d = describe_objects(&image_page_pdf("q 200 0 0 100 50 600 cm /Im0 Do Q")).unwrap();
        let p = &by_id(&d, 5).placements;
        assert_eq!(p.len(), 1);
        assert_rect(&p[0], 1, 50.0, 600.0, 200.0, 100.0);
    }

    #[test]
    fn content_stream_placement_is_the_whole_page() {
        // Honest, not precise: redacting a content stream blanks the whole page,
        // so the UI must show that rather than imply a tighter region.
        let d = describe_objects(&image_page_pdf("q 10 0 0 10 0 0 cm /Im0 Do Q")).unwrap();
        let p = &by_id(&d, 4).placements;
        assert_eq!(p.len(), 1);
        assert_rect(&p[0], 1, 0.0, 0.0, 612.0, 792.0);
    }

    #[test]
    fn document_level_objects_have_no_placement() {
        let d = describe_objects(&image_page_pdf("q 10 0 0 10 0 0 cm /Im0 Do Q")).unwrap();
        // Catalog and page tree are structural — they are nowhere on a page.
        assert!(by_id(&d, 1).placements.is_empty());
        assert!(by_id(&d, 2).placements.is_empty());
    }

    #[test]
    fn an_image_painted_twice_yields_two_placements() {
        let d = describe_objects(&image_page_pdf(
            "q 20 0 0 20 0 0 cm /Im0 Do Q q 30 0 0 30 100 200 cm /Im0 Do Q",
        ))
        .unwrap();
        let p = &by_id(&d, 5).placements;
        assert_eq!(p.len(), 2);
        assert_rect(&p[0], 1, 0.0, 0.0, 20.0, 20.0);
        assert_rect(&p[1], 1, 100.0, 200.0, 30.0, 30.0);
    }

    #[test]
    fn q_restores_the_transform_so_paints_do_not_accumulate() {
        // Without an honoured `Q`, the second paint would inherit the first
        // translate and land at (150, 150) instead of (50, 50).
        let d = describe_objects(&image_page_pdf(
            "q 1 0 0 1 100 100 cm Q q 10 0 0 10 50 50 cm /Im0 Do Q",
        ))
        .unwrap();
        let p = &by_id(&d, 5).placements;
        assert_eq!(p.len(), 1);
        assert_rect(&p[0], 1, 50.0, 50.0, 10.0, 10.0);
    }

    #[test]
    fn concatenated_transforms_compose() {
        // `cm` concatenates: translate(100,100) then scale(2) → the unit square
        // lands at (100,100) with side 2, not at (200,200).
        let d =
            describe_objects(&image_page_pdf("1 0 0 1 100 100 cm 2 0 0 2 0 0 cm /Im0 Do")).unwrap();
        let p = &by_id(&d, 5).placements;
        assert_eq!(p.len(), 1);
        assert_rect(&p[0], 1, 100.0, 100.0, 2.0, 2.0);
    }

    /// Page → form XObject (obj 5) → image (obj 6).
    fn form_pdf(form_dict: &str, form_content: &str, page_content: &str) -> Vec<u8> {
        build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
             /Resources << /XObject << /Fm0 5 0 R >> >> >>",
            &stream_obj("", page_content),
            &stream_obj(form_dict, form_content),
            &stream_obj(
                "/Type /XObject /Subtype /Image /Width 10 /Height 10 /Filter /DCTDecode",
                "",
            ),
        ])
    }

    #[test]
    fn form_xobject_recursion_places_the_image_inside_it() {
        let pdf = form_pdf(
            "/Type /XObject /Subtype /Form /BBox [0 0 200 200] \
             /Resources << /XObject << /Im0 6 0 R >> >>",
            "q 50 0 0 50 0 0 cm /Im0 Do Q",
            "q 1 0 0 1 100 100 cm /Fm0 Do Q",
        );
        let d = describe_objects(&pdf).unwrap();

        // The form reports its /BBox under the invoking CTM…
        let form = &by_id(&d, 5).placements;
        assert_eq!(form.len(), 1);
        assert_rect(&form[0], 1, 100.0, 100.0, 200.0, 200.0);

        // …and the image inside it composes the form's placement with its own.
        let img = &by_id(&d, 6).placements;
        assert_eq!(img.len(), 1);
        assert_rect(&img[0], 1, 100.0, 100.0, 50.0, 50.0);
    }

    #[test]
    fn form_matrix_composes_with_the_invoking_transform() {
        let pdf = form_pdf(
            "/Type /XObject /Subtype /Form /BBox [0 0 10 10] /Matrix [2 0 0 2 5 5] \
             /Resources << /XObject << /Im0 6 0 R >> >>",
            "1 0 0 1 0 0 cm /Im0 Do",
            "1 0 0 1 100 0 cm /Fm0 Do",
        );
        let d = describe_objects(&pdf).unwrap();

        // BBox (0,0)-(10,10) × Matrix(scale 2, translate 5,5) → (5,5)-(25,25),
        // then the page's translate(100,0) → (105,5)-(125,25).
        assert_rect(&by_id(&d, 5).placements[0], 1, 105.0, 5.0, 20.0, 20.0);
        // The image's unit square under the same composed transform.
        assert_rect(&by_id(&d, 6).placements[0], 1, 105.0, 5.0, 2.0, 2.0);
    }

    #[test]
    fn a_self_drawing_form_terminates() {
        // Cyclic /XObject reference: the guard must stop the recursion rather
        // than blow the stack.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R \
             /Resources << /XObject << /Fm0 5 0 R >> >> >>",
            &stream_obj("", "/Fm0 Do"),
            &stream_obj(
                "/Type /XObject /Subtype /Form /BBox [0 0 10 10] \
                 /Resources << /XObject << /Fm0 5 0 R >> >>",
                "/Fm0 Do",
            ),
        ]);
        let d = describe_objects(&pdf).unwrap();
        // It still reports the paints it saw before the cycle was cut.
        assert!(!by_id(&d, 5).placements.is_empty());
    }

    #[test]
    fn inline_image_data_cannot_forge_a_paint() {
        // The bytes between `ID` and `EI` are raw image data and may contain
        // anything — here a `/Im0 Do` sequence. A scanner that walked through
        // them would invent a placement that is not in the page.
        let d = describe_objects(&image_page_pdf(
            "BI /W 2 /H 2 /BPC 8 /CS /G ID \x01/Im0 Do\x02 EI",
        ))
        .unwrap();
        assert!(
            by_id(&d, 5).placements.is_empty(),
            "a `Do` inside inline-image data must not be executed"
        );
    }

    #[test]
    fn a_do_inside_a_string_operand_is_not_a_paint() {
        let d = describe_objects(&image_page_pdf("BT (/Im0 Do) Tj ET")).unwrap();
        assert!(by_id(&d, 5).placements.is_empty());
    }

    #[test]
    fn media_box_is_inherited_from_the_page_tree() {
        // Real documents usually declare /MediaBox once, on the root /Pages.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 400] >>",
            "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
            &stream_obj("", "BT (hi) Tj ET"),
        ]);
        let d = describe_objects(&pdf).unwrap();
        let p = &by_id(&d, 4).placements;
        assert_eq!(p.len(), 1);
        assert_rect(&p[0], 1, 0.0, 0.0, 200.0, 400.0);
    }

    #[test]
    fn a_page_without_a_resolvable_media_box_yields_no_placement() {
        // Fail soft: no geometry beats invented geometry.
        let pdf = build_pdf(&[
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>",
            &stream_obj("", "BT (hi) Tj ET"),
        ]);
        let d = describe_objects(&pdf).unwrap();
        assert!(by_id(&d, 4).placements.is_empty());
    }

    #[test]
    fn a_degenerate_transform_yields_no_placement() {
        // A zero-scale CTM paints nothing selectable; a 0×0 rect can't be
        // hit-tested, so report none rather than a phantom point.
        let d = describe_objects(&image_page_pdf("q 0 0 0 0 100 100 cm /Im0 Do Q")).unwrap();
        assert!(by_id(&d, 5).placements.is_empty());
    }
}
