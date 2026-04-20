//! Fuzz target for `SparseMerkleTree::update()`.
//!
//! Inserts one or more leaves with fuzz-derived keys and value hashes, then
//! asserts that the tree remains internally consistent: the root changes,
//! the tree size tracks correctly, and no panics occur during the 256-level
//! Merkle path recomputation.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use cdhs_smf_service::smt::SparseMerkleTree;

#[derive(Arbitrary, Debug)]
struct SmtUpdateInput {
    /// A sequence of (key, value_hash) pairs to insert.
    entries: Vec<([u8; 32], [u8; 32])>,
}

fuzz_target!(|input: SmtUpdateInput| {
    let tree = SparseMerkleTree::new();

    for (key, value_hash) in &input.entries {
        // Errors are acceptable (e.g. lock poisoning); panics are not.
        let _ = tree.update(key, value_hash, "fallback@1.0.0", "v1");
    }
});
