//! Fuzz target for `verify_merkle_proof()`.
//!
//! Exercises the Merkle proof verifier with arbitrary leaf hashes, sibling
//! chains (with fuzzed hex-encoded hashes and position strings), and root
//! hashes.  The function must never panic — returning `Err` or `Ok(false)`
//! for malformed proofs is acceptable.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use olympus_verifier::{verify_merkle_proof, MerkleProof, MerkleSibling};

#[derive(Arbitrary, Debug)]
struct FuzzProofInput {
    leaf_hash: [u8; 32],
    root_hash: String,
    siblings: Vec<FuzzSibling>,
}

#[derive(Arbitrary, Debug)]
struct FuzzSibling {
    hash: String,
    position: String,
}

fuzz_target!(|input: FuzzProofInput| {
    let siblings: Vec<MerkleSibling> = input
        .siblings
        .into_iter()
        .map(|s| MerkleSibling {
            hash: s.hash,
            position: s.position,
        })
        .collect();

    let proof = MerkleProof {
        leaf_hash: input.leaf_hash,
        siblings,
        root_hash: input.root_hash,
    };

    // Must not panic.
    let _ = verify_merkle_proof(&proof);
});
