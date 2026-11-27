// SPDX-License-Identifier: Apache-2.0

//! Measure compact bodies against a real BLAKE3 tree, with synthetic inputs.
//! Run with: cargo run -p olympus-manifest --example bench_dataset_proof_sizes

use olympus_manifest::content::{
    commit::{content_digest, content_key, empty_meta_root, ItemPreimage},
    error::ContentError,
    fingerprint::{FpEntry, FpSet, MINHASH_WIDTH},
    tree::ItemTree,
    verify_m1_open, verify_m2, verify_n1,
    version::ProfileEntry,
    wire::ExactProof,
    FpProfile, M2Proof, OpenedItem,
};

const PARTITION_BITS: u8 = 4;
const ITEMS: u32 = 1 << 20;
const QUERIES: u32 = 4096;

/// 128 synthetic segment fingerprints of the `text/minhash-120` width under
/// one profile, built with the real fingerprint-set code.
fn fingerprint_set() -> Result<FpSet, ContentError> {
    FpSet::new(
        (0u32..128)
            .map(|segment| {
                let mut fingerprint = vec![0; MINHASH_WIDTH];
                blake3::Hasher::new()
                    .update(&segment.to_be_bytes())
                    .finalize_xof()
                    .fill(&mut fingerprint);
                FpEntry {
                    fp_profile_index: 0,
                    segment_index: segment,
                    fingerprint,
                }
            })
            .collect(),
    )
}

fn report(name: &str, sizes: &mut [usize], target: usize) {
    sizes.sort_unstable();
    let median = (sizes[(sizes.len() - 1) / 2] + sizes[sizes.len() / 2]) as f64 / 2.0;
    let p95 = sizes[(sizes.len() * 95).div_ceil(100) - 1];
    let largest = sizes[sizes.len() - 1];
    println!("{name:8} {median:>8.1} {p95:>8} {largest:>8}");
    assert!(largest < target);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fp_set = fingerprint_set()?;
    let fp_set_root = fp_set.root();
    let fp_table = [FpProfile::text_minhash_120().entry()];
    let profiles = [ProfileEntry {
        id: "text/utf8-nfc".into(),
        version: 1,
        implementation_id: "olympus=0.1.0".into(),
    }];
    let item = |number: u32| ItemPreimage {
        profile_index: 0,
        canonical_len: 4,
        content_digest: content_digest(&number.to_be_bytes()),
        fp_set_root,
        occurrence_count: 1,
        meta_root: empty_meta_root(),
    };
    let key = |preimage: &ItemPreimage| content_key("text/utf8-nfc", 1, &preimage.content_digest);
    let leaves = (0..ITEMS)
        .map(|number| {
            let preimage = item(number);
            Ok((key(&preimage)?, preimage.commitment()))
        })
        .collect::<Result<_, ContentError>>()?;
    let tree = ItemTree::build(PARTITION_BITS, leaves)?;

    let mut memberships = Vec::new();
    let mut absences = Vec::new();
    let mut similarities = Vec::new();
    for query in 0..QUERIES {
        let preimage = item(query * (ITEMS / QUERIES));
        let member = key(&preimage)?;
        let opened_item = OpenedItem {
            key: member,
            path: tree.path(&member),
            preimage,
        };
        let proof = ExactProof::Membership(opened_item.clone()).encode(PARTITION_BITS)?;
        let ExactProof::Membership(opened) = ExactProof::decode(PARTITION_BITS, &proof)? else {
            unreachable!();
        };
        assert_eq!(opened.key, member);
        let verified = verify_m1_open(PARTITION_BITS, &tree.root(), &profiles, &opened)?;
        assert_eq!(verified.fp_set_root, fp_set_root);
        memberships.push(proof.len());

        // Plain M2 for segment 0 through the real codec and verifier.
        let segment = &fp_set.entries()[0];
        let m2 = M2Proof {
            item: opened_item,
            fp_profile_index: 0,
            segment_index: segment.segment_index,
            leaf_index: 0,
            leaf_count: fp_set.entries().len() as u32,
            fingerprint: segment.fingerprint.clone(),
            fp_path: fp_set.path(0),
        }
        .encode(PARTITION_BITS)?;
        let decoded = M2Proof::decode(PARTITION_BITS, &fp_table, &m2)?;
        verify_m2(
            PARTITION_BITS,
            &tree.root(),
            &profiles,
            &fp_table,
            &decoded,
            &segment.fingerprint,
        )?;
        similarities.push(m2.len());

        let absent = key(&item(ITEMS + query))?;
        let proof = ExactProof::NonMembership {
            key: absent,
            path: tree.path(&absent),
        }
        .encode(PARTITION_BITS)?;
        let ExactProof::NonMembership { key, path } = ExactProof::decode(PARTITION_BITS, &proof)?
        else {
            unreachable!();
        };
        assert_eq!(key, absent);
        verify_n1(PARTITION_BITS, &tree.root(), &key, &path)?;
        absences.push(proof.len());
    }

    println!("{ITEMS} items, {QUERIES} samples per statement, p={PARTITION_BITS}");
    println!("Raw bytes per body. Header, signature, ledger evidence and bundle framing excluded.");
    println!("              median      p95      max");
    report("M1-open", &mut memberships, 2 * 1024);
    report("N1", &mut absences, 2 * 1024);
    report("text M2", &mut similarities, 4 * 1024);
    Ok(())
}
