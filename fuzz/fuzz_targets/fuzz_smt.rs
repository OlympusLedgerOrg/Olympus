//! Fuzz the hierarchical Sparse Merkle Tree (`olympus_crypto::smt`).
//!
//! Invariants for an arbitrary set of records:
//! 1. `update` / `prove` / `verify_*` never panic.
//! 2. The shard is the high 8 bytes of every tree key (`shard_record_key`).
//! 3. Every inserted key produces an existence proof that verifies against the
//!    current root.
//! 4. A probe key produces a proof (existence or non-existence) that verifies.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use olympus_crypto::smt::{
    shard_prefix, shard_record_key, verify_existence_proof, verify_nonexistence_proof, Proof,
    SparseMerkleTree, SHARD_PREFIX_BYTES,
};

#[derive(Debug, Arbitrary)]
struct Record<'a> {
    shard_id: &'a str,
    record_key: [u8; 32],
    value_hash: [u8; 32],
    parser_id_raw: &'a [u8],
    cpv_raw: &'a [u8],
}

#[derive(Debug, Arbitrary)]
struct SmtInput<'a> {
    records: Vec<Record<'a>>,
    probe_shard: &'a str,
    probe_key: [u8; 32],
}

fn nonempty_utf8<'a>(raw: &'a [u8], fallback: &'a str) -> &'a str {
    std::str::from_utf8(raw).ok().filter(|s| !s.is_empty()).unwrap_or(fallback)
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = SmtInput::arbitrary(&mut u) else {
        return;
    };

    let mut tree = SparseMerkleTree::new();
    let mut inserted: Vec<[u8; 32]> = Vec::new();

    for r in &input.records {
        let parser_id = nonempty_utf8(r.parser_id_raw, "fuzz@1.0");
        let cpv = nonempty_utf8(r.cpv_raw, "v1");
        let key = shard_record_key(r.shard_id, &r.record_key);

        // Invariant 2: shard prefix occupies the high bytes of the key.
        assert_eq!(key[..SHARD_PREFIX_BYTES], shard_prefix(r.shard_id));

        // Invariant 1: must not panic.
        tree.update(key, r.value_hash, parser_id, cpv);
        inserted.push(key);
    }

    let root = tree.root();

    // Invariant 3: every inserted key verifies as present (latest value wins on
    // duplicate keys, which still verifies against the root).
    for key in &inserted {
        match tree.prove(key) {
            Proof::Existence(p) => {
                assert!(verify_existence_proof(&p, Some(&root)), "inserted key must verify");
            }
            Proof::NonExistence(_) => panic!("inserted key proved non-existence"),
        }
    }

    // Invariant 4: a probe key's proof (whichever kind) reconstructs the root.
    let probe = shard_record_key(input.probe_shard, &input.probe_key);
    match tree.prove(&probe) {
        Proof::Existence(p) => assert!(verify_existence_proof(&p, Some(&root))),
        Proof::NonExistence(p) => {
            assert!(verify_nonexistence_proof(&p, Some(&root)), "absent key must verify");
        }
    }
});
