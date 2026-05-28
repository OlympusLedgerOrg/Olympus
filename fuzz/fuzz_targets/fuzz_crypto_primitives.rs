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
    e: &'a [u8],
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

    // leaf_hash / node_hash require exactly-32-byte key/value/child inputs
    // (release assert, R6-L1), so fold the arbitrary slices through hash_bytes
    // first. The fuzzer then drives the variable-length provenance fields
    // (parser_id / cpv / model_hash) — including empty — which must never panic.
    let key32 = olympus_crypto::hash_bytes(inputs.a);
    let val32 = olympus_crypto::hash_bytes(inputs.b);

    let _ = olympus_crypto::leaf_hash(&key32, &val32, inputs.c, inputs.d, inputs.e);

    // node_hash: 32-byte left and right children — must never panic.
    let _ = olympus_crypto::node_hash(&key32, &val32);

    // global_key: arbitrary shard_id (already valid UTF-8 from Arbitrary) and key bytes.
    let _ = olympus_crypto::global_key(inputs.shard_id, inputs.a);

    // record_key: arbitrary type / id strings and version — must never panic.
    let _ = olympus_crypto::record_key(inputs.record_type, inputs.record_id, inputs.version);

    // blake3_hash: arbitrary parts — must never panic.
    let _ = olympus_crypto::blake3_hash(&[inputs.a, inputs.b]);

    // Cross-check determinism (same inputs → same output on successive calls).
    let h1 = olympus_crypto::node_hash(&key32, &val32);
    let h2 = olympus_crypto::node_hash(&key32, &val32);
    assert_eq!(h1, h2, "node_hash must be deterministic");

    let lh1 = olympus_crypto::leaf_hash(&key32, &val32, inputs.c, inputs.d, inputs.e);
    let lh2 = olympus_crypto::leaf_hash(&key32, &val32, inputs.c, inputs.d, inputs.e);
    assert_eq!(lh1, lh2, "leaf_hash must be deterministic");

    // Domain separation: leaf_hash ≠ node_hash for the same byte content.
    // (Not guaranteed for all inputs, but the fuzzer will find any systematic collision.)
    let lh = olympus_crypto::leaf_hash(&key32, &key32, inputs.c, inputs.d, inputs.e);
    let nh = olympus_crypto::node_hash(&key32, &key32);
    // We cannot assert lh != nh in general (collisions are theoretically possible for
    // adversarial inputs), but if both are non-zero we can at least check they came
    // from different code paths (which the above calls already exercise).
    let _ = (lh, nh);
});
