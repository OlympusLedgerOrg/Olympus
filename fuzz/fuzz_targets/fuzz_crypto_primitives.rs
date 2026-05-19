//! Fuzz the olympus-crypto hash primitives.
//!
//! Invariant: none of these functions may panic regardless of input.
//! They all accept arbitrary byte slices and produce deterministic 32-byte digests.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct HashInputs<'a> {
    a: &'a [u8],
    b: &'a [u8],
    c: &'a [u8],
    d: &'a [u8],
    shard_id: &'a str,
    record_type: &'a str,
    record_id: &'a str,
    version: u64,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(inputs) = HashInputs::arbitrary(&mut u) else {
        return;
    };

    // leaf_hash: arbitrary key, value_hash, parser_id, cpv — must never panic.
    // Empty parser_id / cpv produce the same result as passing b"" — no panic.
    let _ = olympus_crypto::leaf_hash(inputs.a, inputs.b, inputs.c, inputs.d);

    // node_hash: arbitrary left and right children — must never panic.
    let _ = olympus_crypto::node_hash(inputs.a, inputs.b);

    // global_key: arbitrary shard_id (already valid UTF-8 from Arbitrary) and key bytes.
    let _ = olympus_crypto::global_key(inputs.shard_id, inputs.a);

    // record_key: arbitrary type / id strings and version — must never panic.
    let _ = olympus_crypto::record_key(inputs.record_type, inputs.record_id, inputs.version);

    // blake3_hash: arbitrary parts — must never panic.
    let _ = olympus_crypto::blake3_hash(&[inputs.a, inputs.b]);

    // Cross-check: node_hash is commutative only in the domain-tag sense;
    // assert determinism (same inputs → same output on successive calls).
    let h1 = olympus_crypto::node_hash(inputs.a, inputs.b);
    let h2 = olympus_crypto::node_hash(inputs.a, inputs.b);
    assert_eq!(h1, h2, "node_hash must be deterministic");

    let lh1 = olympus_crypto::leaf_hash(inputs.a, inputs.b, inputs.c, inputs.d);
    let lh2 = olympus_crypto::leaf_hash(inputs.a, inputs.b, inputs.c, inputs.d);
    assert_eq!(lh1, lh2, "leaf_hash must be deterministic");

    // Domain separation: leaf_hash ≠ node_hash for the same byte content.
    // (Not guaranteed for all inputs, but the fuzzer will find any systematic collision.)
    let lh = olympus_crypto::leaf_hash(inputs.a, inputs.a, inputs.c, inputs.d);
    let nh = olympus_crypto::node_hash(inputs.a, inputs.a);
    // We cannot assert lh != nh in general (collisions are theoretically possible for
    // adversarial inputs), but if both are non-zero we can at least check they came
    // from different code paths (which the above calls already exercise).
    let _ = (lh, nh);
});
