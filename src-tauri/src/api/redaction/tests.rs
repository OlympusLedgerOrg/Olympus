use std::collections::HashSet;

use super::issue::parse_decimal_fr;
use super::manifest::build_reveal_mask;
use crate::zk::pdf_objects::{PdfObject, PdfObjectManifest, MAX_OBJECTS};

fn obj(id: u32) -> PdfObject {
    PdfObject {
        obj_id: id,
        generation: 0,
        byte_offset: 0,
        byte_length: 0,
        leaf_hex: "00".repeat(32),
    }
}

fn manifest(ids: &[u32]) -> PdfObjectManifest {
    PdfObjectManifest {
        objects: ids.iter().map(|&i| obj(i)).collect(),
        original_root_hex: "00".repeat(32),
        tree_depth: 10,
        max_leaves: MAX_OBJECTS,
    }
}

#[test]
fn reveal_mask_redacts_selected_objects() {
    let m = manifest(&[1, 2, 3]);
    let (mask, revealed) = build_reveal_mask(&m, &HashSet::from([2])).unwrap();
    assert_eq!(mask.len(), MAX_OBJECTS);
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
}
