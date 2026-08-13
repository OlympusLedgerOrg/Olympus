// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0037 coordinate contract: **selectable page objects in normalized
//! page-space**.
//!
//! [`crate::zk::pdf_placement`] answers "where does this object paint, in PDF
//! user space?". That space is the document's own: its origin is the
//! `/MediaBox` lower-left corner, which is often but not always `(0, 0)`, and it
//! ignores `/Rotate`, so a page the reader shows in landscape is still described
//! in its unrotated portrait frame. Handing those numbers to a UI means the UI
//! has to know about MediaBox origins and page rotation to draw a box — exactly
//! the kind of geometry reasoning ADR-0037 §"Coordinate Contract" moves into the
//! backend so there is "one stable orientation per page".
//!
//! This module is that normalization:
//!
//! * origin at the **bottom-left of the displayed page**, `y` upwards;
//! * `/Rotate` applied, so `page_width`/`page_height` are the dimensions the
//!   reader shows and every rect is expressed against them;
//! * every emitted rect finite, non-negative, and clipped to the page extent;
//! * `page_num` **zero-based** (`/Pages` order), unlike the 1-based page number
//!   `pdf_describe`/`pdf_placement` carry for human labels.
//!
//! **Presentation only**, exactly like the geometry it normalizes (ADR-0029 §A,
//! ADR-0037 §"Non-Goals"). Bounds are recomputed on demand from the uploaded
//! bytes, never persisted, and never part of the commitment. A selection made
//! against them is re-resolved against the committed manifest before it can be
//! staged, so a wrong rectangle can mislead a human but cannot change what is
//! cut.
//!
//! Fail-soft, inherited from `pdf_placement`: an object whose geometry cannot be
//! resolved is **omitted** from the page listing rather than guessed at
//! (ADR-0037: "Objects with invalid or unavailable geometry are omitted from
//! selectable page-object results rather than being guessed"). Omission costs
//! the operator a drag-box affordance; the object is still selectable from the
//! manifest checklist.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::zk::pdf_describe::describe_regions;
use crate::zk::pdf_placement::{media_box, page_rotate, Placement};
use crate::zk::pdf_syntax::{dict_region, name_after};

/// One selectable object on one page, in normalized page-space (ADR-0037).
///
/// An object painted more than once on the same page yields one entry per paint,
/// all sharing an `object_id` — the same shape `pdf_placement` uses, because the
/// UI hit-tests rectangles and a single union box would cover empty space
/// between two distant paints.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PageObject {
    /// Committed segment id, as a string — the same spelling `stage_redaction`
    /// takes, so a UI can pass what it received straight back without
    /// reformatting a number and risking a mismatch.
    pub object_id: String,
    /// Classification tag from [`crate::zk::pdf_describe`] (`content_stream`,
    /// `image`, `annotation`, …).
    pub kind: &'static str,
    /// Human label from [`crate::zk::pdf_describe`].
    pub label: String,
    /// Distance from the left edge of the normalized page.
    pub x: f32,
    /// Distance from the **bottom** edge of the normalized page.
    pub y: f32,
    /// Width in page-space units.
    pub w: f32,
    /// Height in page-space units.
    pub h: f32,
}

/// Every selectable object on one page, plus that page's normalized extent.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PageObjects {
    /// Zero-based page index (ADR-0037: "`page_num` is zero-based across all
    /// commands").
    pub page_num: u32,
    /// Normalized page width — post-`/Rotate`, so it is the width the reader
    /// displays.
    pub page_width: f32,
    /// Normalized page height — post-`/Rotate`.
    pub page_height: f32,
    /// Rotation that was applied to reach this frame, one of `0 | 90 | 180 |
    /// 270`. Reported so an operator can tell a normalized landscape page from a
    /// natively landscape one when reconciling with another tool; the emitted
    /// rects already have it applied and need no further correction.
    pub rotation: u32,
    /// Selectable objects, ascending by object id then by paint order.
    pub objects: Vec<PageObject>,
}

/// The `/MediaBox` + `/Rotate` frame of one page, and the mapping from PDF user
/// space into it.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PageFrame {
    /// `/MediaBox` lower-left corner, subtracted before rotating.
    origin_x: f32,
    origin_y: f32,
    /// Unrotated page extent.
    raw_width: f32,
    raw_height: f32,
    rotation: u32,
}

impl PageFrame {
    /// Displayed extent: a quarter turn swaps the axes.
    fn normalized_size(&self) -> (f32, f32) {
        match self.rotation {
            90 | 270 => (self.raw_height, self.raw_width),
            _ => (self.raw_width, self.raw_height),
        }
    }

    /// Map one user-space point into the normalized frame.
    ///
    /// `/Rotate` turns the page **clockwise** for display, so the content turns
    /// with it. Working in MediaBox-relative coordinates `(x, y)` over a
    /// `W × H` page, a clockwise quarter turn sends `(x, y) → (y, W - x)` onto
    /// an `H × W` page; the half turn is `(W - x, H - y)`; and the three-quarter
    /// turn is `(H - y, x)`.
    fn map_point(&self, x: f32, y: f32) -> (f32, f32) {
        let (rx, ry) = (x - self.origin_x, y - self.origin_y);
        match self.rotation {
            90 => (ry, self.raw_width - rx),
            180 => (self.raw_width - rx, self.raw_height - ry),
            270 => (self.raw_height - ry, rx),
            _ => (rx, ry),
        }
    }

    /// Map a user-space rectangle into the normalized frame, clipped to the
    /// page.
    ///
    /// Returns `None` for anything that would break the ADR-0037 guarantee that
    /// emitted boxes are "finite, non-NaN, non-negative, and clipped to the
    /// normalized page extent": a non-finite input or result, and a rectangle
    /// whose intersection with the page has no area (fully off-page, or reduced
    /// to a line by clipping). Rotation maps an axis-aligned rectangle to an
    /// axis-aligned rectangle, so mapping two opposite corners is exact — no
    /// bounding-box slack is introduced here.
    fn map_rect(&self, p: &Placement) -> Option<(f32, f32, f32, f32)> {
        if ![p.x, p.y, p.w, p.h].iter().all(|v| v.is_finite()) {
            return None;
        }
        let (ax, ay) = self.map_point(p.x, p.y);
        let (bx, by) = self.map_point(p.x + p.w, p.y + p.h);
        if ![ax, ay, bx, by].iter().all(|v| v.is_finite()) {
            return None;
        }

        let (page_w, page_h) = self.normalized_size();
        let x0 = ax.min(bx).max(0.0);
        let y0 = ay.min(by).max(0.0);
        let x1 = ax.max(bx).min(page_w);
        let y1 = ay.max(by).min(page_h);
        let (w, h) = (x1 - x0, y1 - y0);
        if w <= 0.0 || h <= 0.0 {
            return None;
        }
        Some((x0, y0, w, h))
    }
}

/// Resolve every page's normalized frame, keyed by **zero-based** page index.
///
/// Pages are numbered by [`crate::zk::pdf_describe::resolve_pages`], which walks
/// `/Pages → /Kids` in document order; this converts its 1-based numbering to
/// the zero-based indexing ADR-0037 mandates. A page whose `/MediaBox` cannot be
/// resolved (absent through the whole `/Parent` chain, or declared degenerate)
/// gets no frame and therefore no listing — the same fail-soft rule as an
/// unresolvable placement, one level up.
fn page_frames(
    dicts: &BTreeMap<u32, &[u8]>,
    page_of: &HashMap<u32, u32>,
) -> BTreeMap<u32, PageFrame> {
    let mut out = BTreeMap::new();
    for (&page_id, &dict) in dicts {
        if name_after(dict, b"/Type").as_deref() != Some("Page") {
            continue;
        }
        // `page_of` also maps content-stream ids to their page; only the `/Page`
        // object's own entry is the page's index, which is why the `/Type` guard
        // above comes first.
        let Some(&one_based) = page_of.get(&page_id) else {
            continue; // page outside the resolvable /Pages tree
        };
        let Some([x0, y0, raw_width, raw_height]) = media_box(page_id, dicts) else {
            continue; // no honest page extent to normalize against
        };
        out.insert(
            one_based - 1,
            PageFrame {
                origin_x: x0,
                origin_y: y0,
                raw_width,
                raw_height,
                rotation: page_rotate(page_id, dicts),
            },
        );
    }
    out
}

/// Every selectable object on `page_num` (zero-based), in normalized page-space.
///
/// `regions` is the committed object set from
/// [`crate::zk::pdf_describe::committed_object_regions`] — the same bytes the
/// segmenter committed, so the listed objects are committed objects and nothing
/// else.
///
/// Returns `None` when the page does not exist or has no resolvable
/// `/MediaBox`; an empty `objects` list means the page exists but nothing on it
/// resolved to usable geometry.
pub(crate) fn page_objects(regions: &BTreeMap<u32, Vec<u8>>, page_num: u32) -> Option<PageObjects> {
    let borrowed: BTreeMap<u32, &[u8]> = crate::zk::pdf_describe::borrow_regions(regions);
    let dicts: BTreeMap<u32, &[u8]> = borrowed
        .iter()
        .map(|(&id, &region)| (id, dict_region(region)))
        .collect();
    let page_of = crate::zk::pdf_describe::resolve_pages(&dicts);

    let frame = *page_frames(&dicts, &page_of).get(&page_num)?;
    let (page_width, page_height) = frame.normalized_size();

    // `describe_regions` already computes placements for the whole document (a
    // form XObject can be drawn from several pages), so this reuses that single
    // parse rather than walking content streams a second time.
    let mut objects = Vec::new();
    for description in describe_regions(&borrowed) {
        for placement in &description.placements {
            // `Placement::page` is 1-based; this listing is 0-based.
            if placement.page != page_num + 1 {
                continue;
            }
            let Some((x, y, w, h)) = frame.map_rect(placement) else {
                continue; // omitted rather than guessed (ADR-0037)
            };
            objects.push(PageObject {
                object_id: description.obj_id.to_string(),
                kind: description.kind,
                label: description.label.clone(),
                x,
                y,
                w,
                h,
            });
        }
    }

    Some(PageObjects {
        page_num,
        page_width,
        page_height,
        rotation: frame.rotation,
        objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(rotation: u32) -> PageFrame {
        PageFrame {
            origin_x: 0.0,
            origin_y: 0.0,
            raw_width: 200.0,
            raw_height: 400.0,
            rotation,
        }
    }

    fn placement(x: f32, y: f32, w: f32, h: f32) -> Placement {
        Placement {
            page: 1,
            x,
            y,
            w,
            h,
        }
    }

    #[test]
    fn unrotated_frame_only_shifts_by_the_media_box_origin() {
        let mut f = frame(0);
        f.origin_x = 10.0;
        f.origin_y = 20.0;
        assert_eq!(f.normalized_size(), (200.0, 400.0));
        assert_eq!(
            f.map_rect(&placement(10.0, 20.0, 30.0, 40.0)),
            Some((0.0, 0.0, 30.0, 40.0))
        );
    }

    #[test]
    fn quarter_turns_swap_the_page_axes_and_move_the_corner() {
        // A 10×20 rect in the page's bottom-left corner, on a 200×400 page.
        let rect = placement(0.0, 0.0, 10.0, 20.0);

        // 90° clockwise: the bottom-left corner becomes the top-left.
        let f = frame(90);
        assert_eq!(f.normalized_size(), (400.0, 200.0));
        assert_eq!(f.map_rect(&rect), Some((0.0, 190.0, 20.0, 10.0)));

        // 180°: bottom-left becomes top-right.
        let f = frame(180);
        assert_eq!(f.normalized_size(), (200.0, 400.0));
        assert_eq!(f.map_rect(&rect), Some((190.0, 380.0, 10.0, 20.0)));

        // 270°: bottom-left becomes bottom-right.
        let f = frame(270);
        assert_eq!(f.normalized_size(), (400.0, 200.0));
        assert_eq!(f.map_rect(&rect), Some((380.0, 0.0, 20.0, 10.0)));
    }

    #[test]
    fn rotation_preserves_area_and_stays_inside_the_page() {
        let rect = placement(30.0, 50.0, 40.0, 60.0);
        for rotation in [0, 90, 180, 270] {
            let f = frame(rotation);
            let (page_w, page_h) = f.normalized_size();
            let (x, y, w, h) = f.map_rect(&rect).expect("rect is fully on the page");
            assert!((w * h - 40.0 * 60.0).abs() < 1e-3, "rotation {rotation}");
            assert!(x >= 0.0 && y >= 0.0, "rotation {rotation}");
            assert!(x + w <= page_w + 1e-3, "rotation {rotation}");
            assert!(y + h <= page_h + 1e-3, "rotation {rotation}");
        }
    }

    #[test]
    fn overhanging_rect_is_clipped_to_the_page_extent() {
        let f = frame(0);
        // Straddles the right and top edges of the 200×400 page.
        let (x, y, w, h) = f.map_rect(&placement(180.0, 380.0, 100.0, 100.0)).unwrap();
        assert_eq!((x, y, w, h), (180.0, 380.0, 20.0, 20.0));
    }

    #[test]
    fn fully_offpage_and_nonfinite_rects_are_omitted_not_guessed() {
        let f = frame(0);
        assert_eq!(f.map_rect(&placement(500.0, 10.0, 20.0, 20.0)), None);
        assert_eq!(f.map_rect(&placement(-40.0, 10.0, 20.0, 20.0)), None);
        assert_eq!(f.map_rect(&placement(f32::NAN, 10.0, 20.0, 20.0)), None);
        assert_eq!(
            f.map_rect(&placement(10.0, 10.0, f32::INFINITY, 20.0)),
            None
        );
        // Touching the edge with zero overlap is an empty intersection, not a
        // zero-area box at the boundary.
        assert_eq!(f.map_rect(&placement(200.0, 10.0, 20.0, 20.0)), None);
    }

    /// Minimal traditional-xref PDF from raw object bodies (obj `i+1` = `bodies[i]`).
    /// Mirrors `pdf_placement::tests::build_pdf` — a real `xref`/`trailer`/
    /// `startxref` is required for [`extract_object_spans`] to parse at all.
    fn build_pdf(bodies: &[String]) -> Vec<u8> {
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

    /// Builds a two-page PDF whose second page carries `page_extras` (e.g. a
    /// `/Rotate`) and paints image object 6 through a `cm` transform.
    fn two_page_pdf(page_extras: &str) -> Vec<u8> {
        let content = "q 40 0 0 60 20 30 cm /Im0 Do Q";
        let bodies = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 200 400] >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>".to_owned(),
            format!(
                "<< /Type /Page /Parent 2 0 R /Contents 7 0 R {page_extras} \
                 /Resources << /XObject << /Im0 6 0 R >> >> >>"
            ),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 >>\nstream\nx\nendstream"
                .to_owned(),
            // Object 7: page 2's content stream, painting Im0 at (20,30) sized 40×60.
            format!(
                "<< /Length {} >>\nstream\n{content}\nendstream",
                content.len()
            ),
        ];
        build_pdf(&bodies)
    }

    fn regions_of(pdf: &[u8]) -> BTreeMap<u32, Vec<u8>> {
        crate::zk::pdf_describe::committed_object_regions(
            pdf,
            crate::zk::segment::SegmentFormat::PdfObject,
        )
        .expect("fixture parses as a traditional-xref PDF")
    }

    #[test]
    fn page_num_is_zero_based_and_pages_are_listed_independently() {
        let regions = regions_of(&two_page_pdf(""));

        let first = page_objects(&regions, 0).expect("page 0 exists");
        assert_eq!(first.page_num, 0);
        // Page 1's content stream covers the page; the image lives on page 2.
        assert!(first.objects.iter().all(|o| o.object_id != "6"));

        let second = page_objects(&regions, 1).expect("page 1 exists");
        assert_eq!(second.page_num, 1);
        let image = second
            .objects
            .iter()
            .find(|o| o.object_id == "6")
            .expect("the image paints on page 2");
        assert_eq!(image.kind, "image");
        assert_eq!(
            (image.x, image.y, image.w, image.h),
            (20.0, 30.0, 40.0, 60.0)
        );

        assert!(
            page_objects(&regions, 2).is_none(),
            "there is no third page"
        );
    }

    #[test]
    fn rotate_normalizes_the_reported_page_and_object_geometry() {
        let upright = regions_of(&two_page_pdf(""));
        let rotated = regions_of(&two_page_pdf("/Rotate 90"));

        let before = page_objects(&upright, 1).unwrap();
        assert_eq!(before.rotation, 0);
        assert_eq!((before.page_width, before.page_height), (200.0, 400.0));

        let after = page_objects(&rotated, 1).unwrap();
        assert_eq!(after.rotation, 90);
        // The quarter turn is reflected in the page the operator is shown …
        assert_eq!((after.page_width, after.page_height), (400.0, 200.0));
        // … and in the object's box, which must not still be in the upright frame.
        let image = after.objects.iter().find(|o| o.object_id == "6").unwrap();
        assert_eq!(
            (image.x, image.y, image.w, image.h),
            (30.0, 140.0, 60.0, 40.0)
        );
        assert!(image.x + image.w <= after.page_width);
        assert!(image.y + image.h <= after.page_height);
    }

    #[test]
    fn a_page_without_a_resolvable_media_box_is_not_listed() {
        // `/MediaBox` declared degenerate on the page tree: `media_box` refuses
        // to invent a page size, so the page has no frame to normalize against.
        let content = "q 40 0 0 60 20 30 cm /Im0 Do Q";
        let bodies = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 0 0] >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 7 0 R \
             /Resources << /XObject << /Im0 6 0 R >> >> >>"
                .to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 >>\nstream\nx\nendstream"
                .to_owned(),
            format!(
                "<< /Length {} >>\nstream\n{content}\nendstream",
                content.len()
            ),
        ];
        let regions = regions_of(&build_pdf(&bodies));
        assert!(page_objects(&regions, 0).is_none());
        assert!(page_objects(&regions, 1).is_none());
    }
}
