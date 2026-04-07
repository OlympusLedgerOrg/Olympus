//! Fuzz target for `smt::verify_non_inclusion()`.
//!
//! Feeds arbitrary keys, sibling arrays, and roots into the non-inclusion
//! verifier.  Like verify_inclusion, the function must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

use cdhs_smf_service::smt;

fuzz_target!(|data: &[u8]| {
    // We need: key(32) + root(32) + 256*32 siblings = 8256 bytes minimum.
    if data.len() < 64 {
        return;
    }

    let key: [u8; 32] = data[0..32].try_into().unwrap();
    let root: [u8; 32] = data[32..64].try_into().unwrap();

    let remaining = &data[64..];
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

    // Must not panic.
    let _ = smt::verify_non_inclusion(&key, &siblings, &root);
});
