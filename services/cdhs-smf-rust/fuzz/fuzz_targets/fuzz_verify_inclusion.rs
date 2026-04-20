//! Fuzz target for `smt::verify_inclusion()`.
//!
//! Feeds arbitrary keys, value hashes, sibling arrays, and roots into the
//! verifier.  This exercises the 256-level Merkle path reconstruction and
//! bit-extraction logic.  The verifier must never panic — returning `false`
//! for malformed input is the correct behaviour.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cdhs_smf_service::smt;

fuzz_target!(|data: &[u8]| {
    // We need: key(32) + value_hash(32) + root(32) + 256*32 siblings = 8288 bytes minimum.
    // If the input is shorter, slice what we can.
    if data.len() < 96 {
        return;
    }

    let key: [u8; 32] = data[0..32].try_into().unwrap();
    let value_hash: [u8; 32] = data[32..64].try_into().unwrap();
    let root: [u8; 32] = data[64..96].try_into().unwrap();

    // Build siblings from remaining data.  Pad with zeros if fewer than 256
    // siblings are provided (verify_inclusion rejects len != 256 anyway, but
    // we also want to exercise the happy path).
    let remaining = &data[96..];
    let mut siblings = Vec::with_capacity(256);
    for i in 0..256 {
        let start = i * 32;
        if start + 32 <= remaining.len() {
            let sib: [u8; 32] = remaining[start..start + 32].try_into().unwrap();
            siblings.push(sib);
        } else {
            siblings.push([0u8; 32]);
        }
    }

    // Must not panic.  Returning false for invalid proofs is fine.
    let _ = smt::verify_inclusion(
        &key,
        &value_hash,
        "fuzz@0.0.0",
        "v1",
        &siblings,
        &root,
    );
});
