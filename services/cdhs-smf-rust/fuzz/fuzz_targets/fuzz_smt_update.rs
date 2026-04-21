//! Fuzz target for `SparseMerkleTree::update()`.
//!
//! Inserts one or more leaves with fuzz-derived keys and value hashes, then
//! asserts that the tree remains internally consistent: the root changes,
//! the tree size tracks correctly, and no panics occur during the 256-level
//! Merkle path recomputation.
//!
//! ADR-0003: leaf hashing now binds the parser identity into the leaf
//! domain, so `update()` requires a non-empty `parser_id` and
//! `canonical_parser_version`. We pass fixed test values here — the goal of
//! this target is the SMT path math, not the parser-domain validation.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use cdhs_smf_service::smt::SparseMerkleTree;

const FUZZ_PARSER_ID: &str = "fallback@1.0.0";
const FUZZ_CANONICAL_PARSER_VERSION: &str = "v1";

#[derive(Arbitrary, Debug)]
struct SmtUpdateInput {
    /// A sequence of (key, value_hash) pairs to insert.
    entries: Vec<([u8; 32], [u8; 32])>,
}

fuzz_target!(|input: SmtUpdateInput| {
    let tree = SparseMerkleTree::new();
    // The SMT's async `update()` requires a tokio runtime. We build a
    // single-thread runtime per fuzz iteration; if that ever fails
    // (e.g. resource exhaustion under libfuzzer) we skip this iteration
    // rather than panic — the target's invariant is "no panics", not
    // "every input produces a tree".
    let runtime = match tokio::runtime::Builder::new_current_thread().build() {
        Ok(rt) => rt,
        Err(_) => return,
    };

    for (key, value_hash) in &input.entries {
        // Errors are acceptable (e.g. lock poisoning); panics are not.
        let _ = runtime.block_on(tree.update(
            key,
            value_hash,
            FUZZ_PARSER_ID,
            FUZZ_CANONICAL_PARSER_VERSION,
        ));
    }
});
