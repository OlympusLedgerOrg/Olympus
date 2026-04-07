//! Fuzz target for `compute_merkle_root()`.
//!
//! Feeds arbitrary leaf byte-vectors into the Merkle root computation,
//! exercising the CT-style promotion logic, domain-separated leaf/node
//! hashing, and the bottom-up tree build.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use olympus_verifier::compute_merkle_root;

#[derive(Arbitrary, Debug)]
struct MerkleRootInput {
    leaves: Vec<Vec<u8>>,
}

fuzz_target!(|input: MerkleRootInput| {
    // Empty leaves return Err, which is fine.  Panics are not.
    let _ = compute_merkle_root(&input.leaves);
});
