use std::collections::HashSet;

use super::issue::parse_decimal_fr;
use super::manifest::build_reveal_mask;
use crate::zk::segment::{Segment, SegmentFormat, SegmentManifest, MAX_SEGMENTS};

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
    SegmentManifest {
        format: SegmentFormat::PdfObject,
        segments: ids.iter().map(|&i| seg(i)).collect(),
        original_root_hex: "00".repeat(32),
        tree_depth: 10,
        max_leaves: MAX_SEGMENTS,
    }
}

#[test]
fn reveal_mask_redacts_selected_objects() {
    let m = manifest(&[1, 2, 3]);
    let (mask, revealed) = build_reveal_mask(&m, &HashSet::from([2])).unwrap();
    assert_eq!(mask.len(), MAX_SEGMENTS);
    assert_eq!(&mask[..3], &[true, false, true]); // object 2 hidden
    assert!(mask[3..].iter().all(|&b| !b)); // padding never revealed
    assert_eq!(revealed, 2);
}

#[test]
fn reveal_mask_rejects_unknown_redacting_all_or_none() {
    let m = manifest(&[1, 2, 3]);
    // unknown id
    assert!(build_reveal_mask(&m, &HashSet::from([9])).is_err());
    // nothing redacted
    assert!(build_reveal_mask(&m, &HashSet::new()).is_err());
    // everything redacted
    assert!(build_reveal_mask(&m, &HashSet::from([1, 2, 3])).is_err());
}

#[test]
fn parse_decimal_fr_is_canonical() {
    // "0001" and "1" reduce to the same field element (and same proof).
    assert_eq!(
        parse_decimal_fr("0001").unwrap(),
        parse_decimal_fr("1").unwrap()
    );
    assert!(parse_decimal_fr("not-a-number").is_err());

    // A value >= the BN254 scalar field modulus must be rejected, never
    // silently reduced and never panic the byte-padding path. This decimal is
    // the modulus itself (the smallest non-canonical value).
    let modulus_dec =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    assert!(parse_decimal_fr(modulus_dec).is_err());
    // modulus - 1 is the largest canonical element and must still parse.
    let max_canonical =
        "21888242871839275222246405745257275088548364400416034343698204186575808495616";
    assert!(parse_decimal_fr(max_canonical).is_ok());
}
