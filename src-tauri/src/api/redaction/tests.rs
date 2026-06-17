use std::collections::HashSet;

use super::manifest::validate_redaction_selection;
use crate::zk::segment::{variable_geometry, Segment, SegmentFormat, SegmentManifest};

fn seg(id: u32) -> Segment {
    Segment {
        segment_id: id,
        label: None,
        byte_offset: 0,
        byte_length: 0,
        leaf_hex: "00".repeat(32),
    }
}

fn manifest(ids: &[u32]) -> SegmentManifest {
    let (tree_depth, max_leaves) = variable_geometry(ids.len());
    SegmentManifest {
        format: SegmentFormat::PdfObject,
        segments: ids.iter().map(|&i| seg(i)).collect(),
        original_root_hex: "00".repeat(32),
        tree_depth,
        max_leaves,
    }
}

#[test]
fn selection_accepts_a_partial_redaction() {
    let m = manifest(&[1, 2, 3]);
    let revealed = validate_redaction_selection(&m, &HashSet::from([2])).unwrap();
    assert_eq!(revealed, 2, "objects 1 and 3 remain revealed");
}

#[test]
fn selection_rejects_unknown_redacting_all_or_none() {
    let m = manifest(&[1, 2, 3]);
    // unknown id
    assert!(validate_redaction_selection(&m, &HashSet::from([9])).is_err());
    // nothing redacted (producer rule — ADR-0030 §3)
    assert!(validate_redaction_selection(&m, &HashSet::new()).is_err());
    // everything redacted (producer rule — ADR-0030 §3)
    assert!(validate_redaction_selection(&m, &HashSet::from([1, 2, 3])).is_err());
}
