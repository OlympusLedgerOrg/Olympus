// SPDX-License-Identifier: Apache-2.0

//! Measure compact bodies against a real BLAKE3 tree, with synthetic inputs.
//! Run with: cargo run -p olympus-manifest --example bench_dataset_proof_sizes

use olympus_manifest::content::{
    commit::{content_digest, content_key, empty_meta_root, ItemPreimage},
    domains::{h, Domain},
    tree::ItemTree,
    verify_m1_open, verify_n1,
    version::ProfileEntry,
    wire::ExactProof,
    OpenedItem,
};

const PARTITION_BITS: u8 = 4;
const ITEMS: u32 = 1 << 20;
const QUERIES: u32 = 4096;

fn fingerprint_witness() -> ([u8; 32], Vec<u8>) {
    let fingerprint = |segment: u32| {
        let mut bytes = [0; 480];
        blake3::Hasher::new()
            .update(&segment.to_be_bytes())
            .finalize_xof()
            .fill(&mut bytes);
        bytes
    };
    let mut level: Vec<_> = (0u32..128)
        .map(|segment| {
            h(
                Domain::Fp,
                &[&[0, 0], &segment.to_be_bytes(), &fingerprint(segment)],
            )
        })
        .collect();
    let mut wire = Vec::new();
    wire.extend_from_slice(&0u16.to_be_bytes()); // fingerprint profile
    wire.extend_from_slice(&0u32.to_be_bytes()); // segment
    wire.extend_from_slice(&0u32.to_be_bytes()); // leaf position
    wire.extend_from_slice(&128u32.to_be_bytes()); // fingerprint tree size
    wire.extend_from_slice(&fingerprint(0));
    while level.len() > 1 {
        wire.extend_from_slice(&level[1]);
        level = level
            .chunks_exact(2)
            .map(|pair| h(Domain::FpNode, &[&pair[0], &pair[1]]))
            .collect();
    }

    let mut root = h(Domain::Fp, &[&wire[..2], &wire[2..6], &wire[14..494]]);
    for sibling in wire[494..].chunks_exact(32) {
        root = h(Domain::FpNode, &[&root, sibling]);
    }
    assert_eq!(root, level[0]);
    (root, wire)
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
    let (fp_set_root, fingerprint) = fingerprint_witness();
    let profiles = [ProfileEntry {
        id: "bytes/raw".into(),
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
    let key = |preimage: &ItemPreimage| content_key("bytes/raw", 1, &preimage.content_digest);
    let leaves = (0..ITEMS)
        .map(|number| {
            let preimage = item(number);
            Ok((key(&preimage)?, preimage.commitment()))
        })
        .collect::<Result<_, olympus_manifest::content::error::ContentError>>()?;
    let tree = ItemTree::build(PARTITION_BITS, leaves)?;

    let mut memberships = Vec::new();
    let mut absences = Vec::new();
    let mut similarities = Vec::new();
    for query in 0..QUERIES {
        let preimage = item(query * (ITEMS / QUERIES));
        let member = key(&preimage)?;
        let proof = ExactProof::Membership(OpenedItem {
            key: member,
            path: tree.path(&member),
            preimage,
        })
        .encode(PARTITION_BITS)?;
        let ExactProof::Membership(opened) = ExactProof::decode(PARTITION_BITS, &proof)? else {
            unreachable!();
        };
        assert_eq!(opened.key, member);
        let verified = verify_m1_open(PARTITION_BITS, &tree.root(), &profiles, &opened)?;
        assert_eq!(verified.fp_set_root, fp_set_root);
        memberships.push(proof.len());

        // M2's separate statement tag plus lp(M1-open) and its fingerprint witness.
        let mut m2 = vec![3];
        m2.extend_from_slice(&(proof.len() as u32).to_be_bytes());
        m2.extend_from_slice(&proof);
        m2.extend_from_slice(&fingerprint);
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
