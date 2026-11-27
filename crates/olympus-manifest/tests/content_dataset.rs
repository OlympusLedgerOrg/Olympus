// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests for content-addressed dataset commitments (RFC-0000
//! draft): the builder rules, M1-open / N1 / MD1, and the §13 negative cases.
//! Every negative case asserts the specific rejection, not merely failure.

use olympus_manifest::content::canon::CanonProfile;
use olympus_manifest::content::commit::{
    audit_meta_set, content_digest, content_key, fresh_blinding, MetaEntry,
};
use olympus_manifest::content::dataset::{
    verify_m1_open, verify_md1, verify_n1, AddOutcome, BuiltVersion, DatasetBuilder,
};
use olympus_manifest::content::error::ContentError;
use olympus_manifest::content::version::{ExtractionEntry, GlobalRootInput};

const P: u8 = 2;

fn extraction() -> Vec<ExtractionEntry> {
    vec![ExtractionEntry {
        id: "jsonl/field".into(),
        version: 1,
        implementation_id: "olympus-manifest=0.1.0".into(),
        params: vec![("field".into(), "/text".into())],
    }]
}

fn meta(uri: &str, status: u8) -> MetaEntry {
    MetaEntry {
        blinding: fresh_blinding(),
        extraction_index: 0,
        source_uri: uri.into(),
        license: "CC-BY-4.0".into(),
        retrieved_at_unix_s: 1_764_000_000,
        opt_out_status: status,
    }
}

fn text_key(s: &str) -> [u8; 32] {
    let canon = CanonProfile::TextUtf8Nfc
        .canonicalize(s.as_bytes())
        .unwrap();
    content_key("text/utf8-nfc", 1, &content_digest(&canon))
}

/// Items A (3 occurrences, with metadata), B (1, with), C (2, without), plus
/// filler so the tree has real depth.
fn build() -> BuiltVersion {
    let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
    for (i, uri) in [
        "https://a.example/1",
        "https://a.example/2",
        "https://a.example/1",
    ]
    .iter()
    .enumerate()
    {
        // Same work, differing only by line endings: one leaf.
        let raw = if i == 0 {
            "work A\r\nline 2"
        } else {
            "work A\nline 2"
        };
        b.add(0, raw.as_bytes(), Some(meta(uri, 1))).unwrap();
    }
    b.add(0, b"work B", Some(meta("https://b.example/", 0)))
        .unwrap();
    b.add(0, b"work C", None).unwrap();
    b.add(0, b"work C", None).unwrap();
    for i in 0..40 {
        b.add(0, format!("filler {i}").as_bytes(), None).unwrap();
    }
    b.finish("example-corpus", 1, P, &extraction()).unwrap()
}

fn item_root(v: &BuiltVersion) -> [u8; 32] {
    v.root_input.item_root
}

#[test]
fn duplicates_merge_and_counts_are_committed() {
    let v = build();
    let a = v.open(&text_key("work A\nline 2")).expect("A is a member");
    assert_eq!(a.preimage.occurrence_count, 3);
    assert_eq!(v.root_input.item_count, 43);
    assert_eq!(v.root_input.occurrence_total, 3 + 1 + 2 + 40);
    assert_eq!(v.global_root, v.root_input.compute().unwrap());
}

#[test]
fn rejected_items_are_counted_not_committed() {
    let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
    assert_eq!(
        b.add(0, &[0xff], None).unwrap(),
        AddOutcome::Rejected(ContentError::InvalidUtf8)
    );
    let v = b.finish("d", 1, 0, &extraction()).unwrap();
    assert_eq!(v.rejected_count, 1);
    assert_eq!(v.root_input.item_count, 0);
}

#[test]
fn m1_open_verifies_and_n1_verifies_for_an_absent_work() {
    let v = build();
    let root = item_root(&v);
    let a = v.open(&text_key("work A\nline 2")).unwrap();
    let pre = verify_m1_open(P, &root, &v.profile_table, &a).unwrap();
    assert_eq!(pre.occurrence_count, 3);

    let absent = text_key("a work nobody committed");
    assert_eq!(verify_n1(P, &root, &absent, &v.path(&absent)), Ok(()));
}

#[test]
fn m1_open_rejects_a_tampered_preimage_and_a_wrong_profile() {
    let v = build();
    let root = item_root(&v);
    let a = v.open(&text_key("work A\nline 2")).unwrap();

    let mut bad = a.clone();
    bad.preimage.occurrence_count = 1; // understate repetition
    assert_eq!(
        verify_m1_open(P, &root, &v.profile_table, &bad),
        Err(ContentError::CommitmentMismatch)
    );

    // Same commitment, but verified under a table that names a different
    // profile at that index: the content key no longer derives.
    let mut table = v.profile_table.clone();
    table[0].id = "bytes/raw".into();
    assert_eq!(
        verify_m1_open(P, &root, &table, &a),
        Err(ContentError::ContentKeyMismatch)
    );
}

#[test]
fn md1_verifies_every_entry_of_every_item_with_metadata() {
    let v = build();
    let root = item_root(&v);
    for work in ["work A\nline 2", "work B"] {
        let key = text_key(work);
        let n = v.meta_set(&key).unwrap().entries().len();
        for j in 0..n {
            let d = v.disclose(&key, j).unwrap();
            assert_eq!(
                verify_md1(P, &root, &v.profile_table, &d),
                Ok(()),
                "{work} j={j}"
            );
        }
    }
}

// --- RFC §13 negative cases -------------------------------------------------

#[test]
fn neg_wrong_blinder() {
    let v = build();
    let mut d = v.disclose(&text_key("work A\nline 2"), 1).unwrap();
    d.entry.blinding[0] ^= 1;
    assert_eq!(
        verify_md1(P, &item_root(&v), &v.profile_table, &d),
        Err(ContentError::MetaRootMismatch)
    );
}

#[test]
fn neg_swapped_entry() {
    let v = build();
    let key = text_key("work A\nline 2");
    let mut d = v.disclose(&key, 0).unwrap();
    d.entry = v.meta_set(&key).unwrap().entries()[1].clone();
    assert_eq!(
        verify_md1(P, &item_root(&v), &v.profile_table, &d),
        Err(ContentError::MetaRootMismatch)
    );
}

#[test]
fn neg_entry_from_another_item() {
    let v = build();
    let mut d = v.disclose(&text_key("work A\nline 2"), 0).unwrap();
    let from_b = v.disclose(&text_key("work B"), 0).unwrap();
    // B has n = 1 (no siblings); A has n = 3. Transplant B's entry with A's
    // own path shape so the failure is the fold, not the length check.
    d.entry = from_b.entry;
    assert_eq!(
        verify_md1(P, &item_root(&v), &v.profile_table, &d),
        Err(ContentError::MetaRootMismatch)
    );
    // And B's whole (entry, path) pair, which has the wrong shape for A.
    let mut d = v.disclose(&text_key("work A\nline 2"), 0).unwrap();
    let from_b = v.disclose(&text_key("work B"), 0).unwrap();
    d.entry = from_b.entry;
    d.meta_path = from_b.meta_path;
    assert!(matches!(
        verify_md1(P, &item_root(&v), &v.profile_table, &d),
        Err(ContentError::MetaPathLength { .. })
    ));
}

#[test]
fn neg_wrong_set_size() {
    let v = build();
    let mut d = v.disclose(&text_key("work A\nline 2"), 0).unwrap();
    d.n = 2;
    assert_eq!(
        verify_md1(P, &item_root(&v), &v.profile_table, &d),
        Err(ContentError::MetaCountMismatch {
            n: 2,
            occurrence_count: 3
        })
    );
}

#[test]
fn neg_out_of_range_position() {
    let v = build();
    let mut d = v.disclose(&text_key("work A\nline 2"), 0).unwrap();
    d.j = 3;
    assert_eq!(
        verify_md1(P, &item_root(&v), &v.profile_table, &d),
        Err(ContentError::MetaPositionOutOfRange { j: 3, n: 3 })
    );
}

#[test]
fn neg_invalid_fields_are_rejected_by_the_builder() {
    let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
    assert_eq!(
        b.add(0, b"x", Some(meta("u", 3))),
        Err(ContentError::InvalidOptOutStatus(3))
    );
    assert_eq!(
        b.add(0, b"x", Some(meta("e\u{0301}", 0))),
        Err(ContentError::NotNfc("source_uri"))
    );
}

#[test]
fn guessed_uri_cannot_be_confirmed_from_a_sibling_hash() {
    // Positive test of hiding: a holder of a valid MD1 for entry 0 sees the
    // sibling leaf hash of entry 1. Knowing entry 1's every field *except*
    // its blinder must not reproduce that hash.
    let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
    let e0 = meta("https://known.example/", 0);
    let e1 = meta("https://secret.example/private", 0);
    b.add(0, b"pair", Some(e0)).unwrap();
    b.add(0, b"pair", Some(e1.clone())).unwrap();
    let pv = b.finish("d", 1, 0, &extraction()).unwrap();
    let pk = text_key("pair");
    let set = pv.meta_set(&pk).unwrap();
    let pos1 = set
        .entries()
        .iter()
        .position(|e| e.source_uri == e1.source_uri)
        .unwrap();
    let pos0 = 1 - pos1;
    let d = pv.disclose(&pk, pos0).unwrap();
    let sibling = d.meta_path[0];
    let mut guess = e1.clone();
    for attempt in 0..64u8 {
        guess.blinding = [attempt; 32];
        assert_ne!(
            guess.leaf(),
            sibling,
            "a guessed blinder reproduced the sibling"
        );
    }
    // Sanity: with the true blinder the guess *would* match, so the test is
    // exercising the right hash.
    assert_eq!(e1.leaf(), sibling);
}

#[test]
fn neg_reused_blinder_is_rejected_across_items() {
    let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
    let m = meta("u", 0);
    b.add(0, b"one", Some(m.clone())).unwrap();
    assert_eq!(
        b.add(0, b"two", Some(m)),
        Err(ContentError::DuplicateBlinder)
    );
}

#[test]
fn neg_partial_metadata_set_is_refused_at_build() {
    let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
    b.add(0, b"w", Some(meta("u", 0))).unwrap();
    b.add(0, b"w", None).unwrap();
    assert_eq!(
        b.finish("d", 1, 0, &extraction()).err(),
        Some(ContentError::PartialMetadata { with: 1, total: 2 })
    );
}

#[test]
fn neg_incomplete_set_is_caught_by_audit() {
    let v = build();
    let key = text_key("work A\nline 2");
    let pre = v.open(&key).unwrap().preimage;
    let all = v.meta_set(&key).unwrap().entries().to_vec();
    assert_eq!(audit_meta_set(&pre, &all), Ok(()));
    assert_eq!(
        audit_meta_set(&pre, &all[..2]),
        Err(ContentError::MetaSetSize {
            expected: 3,
            got: 2
        })
    );
    let mut reordered = all.clone();
    reordered.swap(0, 1);
    assert_eq!(
        audit_meta_set(&pre, &reordered),
        Err(ContentError::MetaOrder)
    );
}

#[test]
fn neg_version_and_dataset_transplant_changes_the_global_root() {
    let v = build();
    let base = v.root_input.clone();
    let r = base.compute().unwrap();
    for m in [
        GlobalRootInput {
            dataset_id: "other-corpus".into(),
            ..base.clone()
        },
        GlobalRootInput {
            version: 2,
            ..base.clone()
        },
    ] {
        assert_ne!(m.compute().unwrap(), r);
    }
}

#[test]
fn opt_out_status_is_recorded_not_judged() {
    // An item recorded as opted out is committed normally: the format records
    // the committer's state (class C) and does not refuse it.
    let v = build();
    let d = v.disclose(&text_key("work A\nline 2"), 0).unwrap();
    assert_eq!(d.entry.opt_out_status, 1);
    assert_eq!(verify_md1(P, &item_root(&v), &v.profile_table, &d), Ok(()));
}

#[test]
fn roots_are_reproducible_given_the_same_blinders() {
    // Audit rebuild: same occurrences and the same (persisted) blinders give
    // the same global root; regenerated blinders do not.
    let fixed: Vec<MetaEntry> = (0..3).map(|i| meta(&format!("https://x/{i}"), 0)).collect();
    let build_with = |entries: &[MetaEntry]| {
        let mut b = DatasetBuilder::new(vec![CanonProfile::TextUtf8Nfc]);
        for e in entries {
            b.add(0, b"same work", Some(e.clone())).unwrap();
        }
        b.finish("d", 1, 1, &extraction()).unwrap().global_root
    };
    let mut reversed = fixed.clone();
    reversed.reverse();
    assert_eq!(
        build_with(&fixed),
        build_with(&reversed),
        "insertion order leaked into the root"
    );
    let regenerated: Vec<MetaEntry> = fixed
        .iter()
        .map(|e| MetaEntry {
            blinding: fresh_blinding(),
            ..e.clone()
        })
        .collect();
    assert_ne!(build_with(&fixed), build_with(&regenerated));
}
