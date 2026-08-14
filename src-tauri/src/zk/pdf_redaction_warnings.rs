// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! ADR-0037 structured, severity-bearing redaction warnings for the object
//! redaction schemes (`pdf-object`, `pdf-xref-stream`).
//!
//! ADR-0037 requires the backend, not the frontend, to detect "dangerous
//! object relationships" — cases where redacting the selected objects has an
//! effect the operator did not ask for. This module is that detection: it
//! reads the same committed dictionaries [`crate::zk::pdf_describe`] classifies
//! and looks for two relationships whole-object redaction can get wrong:
//!
//! * an XObject or content stream that more than one page/form paints, so
//!   redacting it blanks every place it appears, not just the one the operator
//!   was looking at ([`RedactionWarningCode::SharedXObject`] /
//!   [`RedactionWarningCode::SharedStream`]);
//! * an annotation whose `/AP` appearance stream is a *separate* committed
//!   object the selection did not include, so the annotation's on-page mark
//!   would survive a redaction that looks complete
//!   ([`RedactionWarningCode::AnnotationAppearanceStream`]).
//!
//! [`RedactionWarningCode::AmbiguousTextSpan`] is deliberately not produced
//! here — ADR-0037's own table marks it "surfaced from a UI click", i.e. it
//! describes a frontend selection ambiguity (which word a click meant), not a
//! backend-observable object relationship. There is nothing in the committed
//! object graph for this module to detect.
//!
//! Severity follows ADR-0037 exactly: a shared reference is `Warning` (the
//! redaction is still safe, just wider than the operator may expect) *unless*
//! the shared byte range cannot be isolated from unselected visible content, in
//! which case it is `Blocking`. Whole-object redaction never partially zero-fills
//! a stream shared with unselected objects — the object is redacted for every
//! referrer or not at all — so a shared reference can never make redaction
//! *unsafe* here, only *broader than expected*. The one blocking case is the
//! appearance-stream gap: leaving a rendered mark that looks like the covered
//! text is exactly the failure ADR-0037 calls unsafe.

use std::collections::{BTreeMap, HashMap};

use crate::api::redaction::staging::{
    RedactionWarning, RedactionWarningCode, RedactionWarningSeverity,
};
use crate::zk::pdf_syntax::{name_after, refs_after};

/// Every selected object referenced from more than one page/form's
/// `/Resources → /XObject`, mapped to the referring object ids (for the
/// message).
fn shared_xobject_referrers(
    dicts: &BTreeMap<u32, &[u8]>,
    regions: &BTreeMap<u32, &[u8]>,
    selected: &[u32],
) -> HashMap<u32, Vec<u32>> {
    // referenced XObject id -> set of dict ids whose /Resources names it.
    let mut referrers: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&owner_id, &dict) in dicts {
        let Some(resources) = crate::zk::pdf_placement::dict_value(dict, b"/Resources", regions)
        else {
            continue;
        };
        let Some(xobjects) = crate::zk::pdf_placement::dict_value(resources, b"/XObject", regions)
        else {
            continue;
        };
        for target in crate::zk::pdf_placement::name_to_ref(xobjects).into_values() {
            let list = referrers.entry(target).or_default();
            if !list.contains(&owner_id) {
                list.push(owner_id);
            }
        }
    }
    referrers.retain(|target, refs| selected.contains(target) && refs.len() > 1);
    referrers
}

/// Every selected object referenced as `/Contents` by more than one page.
fn shared_content_referrers(
    dicts: &BTreeMap<u32, &[u8]>,
    selected: &[u32],
) -> HashMap<u32, Vec<u32>> {
    let mut referrers: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&page_id, &dict) in dicts {
        if name_after(dict, b"/Type").as_deref() != Some("Page") {
            continue;
        }
        for content_id in refs_after(dict, b"/Contents") {
            let list = referrers.entry(content_id).or_default();
            if !list.contains(&page_id) {
                list.push(page_id);
            }
        }
    }
    referrers.retain(|target, refs| selected.contains(target) && refs.len() > 1);
    referrers
}

/// Every selected annotation whose `/AP` names a normal (`/N`) or, absent that,
/// a down (`/D`) or rollover (`/R`) appearance stream object that is **not**
/// itself in `selected`.
fn annotation_appearance_gaps(
    dicts: &BTreeMap<u32, &[u8]>,
    regions: &BTreeMap<u32, &[u8]>,
    selected: &[u32],
) -> Vec<(u32, u32)> {
    let mut gaps = Vec::new();
    for &annot_id in selected {
        let Some(&dict) = dicts.get(&annot_id) else {
            continue;
        };
        if name_after(dict, b"/Type").as_deref() != Some("Annot") {
            continue;
        }
        let Some(ap) = crate::zk::pdf_placement::dict_value(dict, b"/AP", regions) else {
            continue;
        };
        // `/N` is the required normal appearance; PDF32000 §12.5.5 lets it be an
        // indirect stream reference or (for appearance *subdictionaries*, e.g. a
        // checkbox's on/off states) a dict of named references — either way
        // `refs_after` recovers every referenced object id.
        let mut appearance_refs = refs_after(ap, b"/N");
        if appearance_refs.is_empty() {
            appearance_refs = refs_after(ap, b"/D");
        }
        if appearance_refs.is_empty() {
            appearance_refs = refs_after(ap, b"/R");
        }
        for appearance_id in appearance_refs {
            if !selected.contains(&appearance_id) {
                gaps.push((annot_id, appearance_id));
            }
        }
    }
    gaps
}

/// Compute every structured warning for redacting `selected` from the given
/// object dictionaries/regions (ADR-0037 "Warnings are structured and
/// severity-bearing").
///
/// `dicts`/`regions` must be the same object graph
/// [`crate::zk::pdf_describe::describe_regions`] classified — both PDF object
/// schemes (`pdf-object`, `pdf-xref-stream`) share this detector because it
/// reads only object dictionaries, which both schemes expose identically once
/// parsed.
pub(crate) fn compute_redaction_warnings(
    dicts: &BTreeMap<u32, &[u8]>,
    regions: &BTreeMap<u32, &[u8]>,
    selected: &[u32],
) -> Vec<RedactionWarning> {
    let mut warnings = Vec::new();

    for (target, referrers) in shared_xobject_referrers(dicts, regions, selected) {
        warnings.push(RedactionWarning {
            code: RedactionWarningCode::SharedXObject,
            severity: RedactionWarningSeverity::Warning,
            message: format!(
                "object {target} is drawn from {} other places — redacting it will \
                 remove it everywhere it appears, not just where you selected it.",
                referrers.len().saturating_sub(1)
            ),
            object_ids: {
                let mut ids: Vec<String> = referrers.iter().map(u32::to_string).collect();
                ids.push(target.to_string());
                ids.sort();
                ids.dedup();
                ids
            },
        });
    }

    for (target, referrers) in shared_content_referrers(dicts, selected) {
        warnings.push(RedactionWarning {
            code: RedactionWarningCode::SharedStream,
            severity: RedactionWarningSeverity::Warning,
            message: format!(
                "content stream {target} is the /Contents of {} pages — redacting it \
                 will blank all of them.",
                referrers.len()
            ),
            object_ids: {
                let mut ids: Vec<String> = referrers.iter().map(u32::to_string).collect();
                ids.push(target.to_string());
                ids.sort();
                ids.dedup();
                ids
            },
        });
    }

    for (annot_id, appearance_id) in annotation_appearance_gaps(dicts, regions, selected) {
        warnings.push(RedactionWarning {
            code: RedactionWarningCode::AnnotationAppearanceStream,
            severity: RedactionWarningSeverity::Blocking,
            message: format!(
                "annotation {annot_id}'s appearance stream (object {appearance_id}) is not \
                 in the selection — its on-page mark would remain visible after redaction."
            ),
            object_ids: vec![annot_id.to_string(), appearance_id.to_string()],
        });
    }

    // Deterministic order: the staging table's `warning_digest` is order
    // sensitive (it hashes the slice in iterated order), and the three detectors
    // above walk `HashMap`s, so without a fixed sort the same document could
    // digest differently across processes / runs and spuriously trip
    // `StagingStale` on commit.
    warnings.sort_by(|a, b| (a.code as u8, &a.object_ids).cmp(&(b.code as u8, &b.object_ids)));
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zk::pdf_describe::committed_object_regions;
    use crate::zk::pdf_syntax::dict_region;
    use crate::zk::segment::SegmentFormat;

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

    type Dicts<'a> = BTreeMap<u32, &'a [u8]>;
    type Regions<'a> = BTreeMap<u32, &'a [u8]>;

    fn dicts_and_regions(regions: &BTreeMap<u32, Vec<u8>>) -> (Dicts<'_>, Regions<'_>) {
        let borrowed = crate::zk::pdf_describe::borrow_regions(regions);
        let dicts: BTreeMap<u32, &[u8]> = borrowed
            .iter()
            .map(|(&id, &r)| (id, dict_region(r)))
            .collect();
        (dicts, borrowed)
    }

    #[test]
    fn image_shared_by_two_pages_warns_but_does_not_block() {
        let bodies = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 200 400] >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 5 0 R \
             /Resources << /XObject << /Im0 7 0 R >> >> >>"
                .to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 6 0 R \
             /Resources << /XObject << /Im0 7 0 R >> >> >>"
                .to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 >>\nstream\nx\nendstream"
                .to_owned(),
        ];
        let pdf = build_pdf(&bodies);
        let regions =
            committed_object_regions(&pdf, SegmentFormat::PdfObject).expect("valid fixture");
        let (dicts, borrowed) = dicts_and_regions(&regions);

        let warnings = compute_redaction_warnings(&dicts, &borrowed, &[7]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, RedactionWarningCode::SharedXObject);
        assert_eq!(warnings[0].severity, RedactionWarningSeverity::Warning);
        assert!(warnings[0].object_ids.contains(&"7".to_owned()));
    }

    #[test]
    fn image_used_once_produces_no_warning() {
        let bodies = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 400] >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 4 0 R \
             /Resources << /XObject << /Im0 5 0 R >> >> >>"
                .to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 >>\nstream\nx\nendstream"
                .to_owned(),
        ];
        let pdf = build_pdf(&bodies);
        let regions =
            committed_object_regions(&pdf, SegmentFormat::PdfObject).expect("valid fixture");
        let (dicts, borrowed) = dicts_and_regions(&regions);

        assert!(compute_redaction_warnings(&dicts, &borrowed, &[5]).is_empty());
    }

    #[test]
    fn annotation_without_its_appearance_stream_selected_is_blocking() {
        let bodies = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 200 400] \
             /Annots [4 0 R] >>"
                .to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 6 0 R /Annots [4 0 R] >>".to_owned(),
            "<< /Type /Annot /Subtype /Text /AP << /N 5 0 R >> >>".to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
        ];
        let pdf = build_pdf(&bodies);
        let regions =
            committed_object_regions(&pdf, SegmentFormat::PdfObject).expect("valid fixture");
        let (dicts, borrowed) = dicts_and_regions(&regions);

        // Selecting only the annotation (not its /N appearance, object 5) blocks.
        let warnings = compute_redaction_warnings(&dicts, &borrowed, &[4]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            RedactionWarningCode::AnnotationAppearanceStream
        );
        assert_eq!(warnings[0].severity, RedactionWarningSeverity::Blocking);

        // Selecting both together clears it.
        assert!(compute_redaction_warnings(&dicts, &borrowed, &[4, 5]).is_empty());
    }

    #[test]
    fn warning_order_is_deterministic_across_recomputation() {
        let bodies = vec![
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 /MediaBox [0 0 200 400] >>".to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 5 0 R \
             /Resources << /XObject << /Im0 8 0 R /Im1 9 0 R >> >> >>"
                .to_owned(),
            "<< /Type /Page /Parent 2 0 R /Contents 6 0 R \
             /Resources << /XObject << /Im0 8 0 R /Im1 9 0 R >> >> >>"
                .to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
            "<< /Type /XObject /Subtype /Image /Width 8 /Height 8 >>\nstream\nx\nendstream"
                .to_owned(),
            "<< /Type /XObject /Subtype /Image /Width 4 /Height 4 >>\nstream\nx\nendstream"
                .to_owned(),
        ];
        let pdf = build_pdf(&bodies);
        let regions =
            committed_object_regions(&pdf, SegmentFormat::PdfObject).expect("valid fixture");
        let (dicts, borrowed) = dicts_and_regions(&regions);

        let a = compute_redaction_warnings(&dicts, &borrowed, &[8, 9]);
        let b = compute_redaction_warnings(&dicts, &borrowed, &[8, 9]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
    }
}
