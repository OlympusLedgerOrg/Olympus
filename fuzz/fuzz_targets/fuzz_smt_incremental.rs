//! Fuzz the SMT incremental update kernel.
//!
//! Invariants:
//! 1. `incremental_update_raw` must never panic for any valid input.
//! 2. The returned root is a 32-byte value derived deterministically from inputs.
//! 3. Exactly 256 node deltas are always returned.
//! 4. The root-level delta (last entry) has db_level=0 and empty packed_index.
//! 5. Inserting the same key twice with the same value produces the same root.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use olympus_core::smt::incremental_update_raw;
use olympus_crypto::empty_leaf;

/// Precompute empty sibling hashes (done once per fuzz invocation — not per iteration).
fn empty_siblings() -> Vec<[u8; 32]> {
    let mut e = Vec::with_capacity(257);
    e.push(empty_leaf());
    for _ in 0..256 {
        let last = *e.last().unwrap();
        e.push(olympus_crypto::node_hash(&last, &last));
    }
    // Return the 256 leaf-to-root siblings (indices 0..256 of the empty tree).
    e[..256].to_vec()
}

#[derive(Debug, Arbitrary)]
struct SmtInput<'a> {
    key: [u8; 32],
    value_hash: [u8; 32],
    /// Non-empty parser_id bytes; Arbitrary may produce empty slice, handled below.
    parser_id_raw: &'a [u8],
    /// Non-empty canonical parser version; handled below.
    cpv_raw: &'a [u8],
    /// Optional: override some sibling slots with fuzz data.
    sibling_overrides: Vec<(u8, [u8; 32])>,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = SmtInput::arbitrary(&mut u) else {
        return;
    };

    // Guarantee non-empty strings (protocol invariant).
    let parser_id = if input.parser_id_raw.is_empty() { b"fuzz@1.0".as_slice() } else { input.parser_id_raw };
    let cpv = if input.cpv_raw.is_empty() { b"v1".as_slice() } else { input.cpv_raw };

    // Build sibling array: start from all-empty and apply overrides.
    let mut siblings = empty_siblings();
    for (idx, hash) in &input.sibling_overrides {
        let i = (*idx as usize) % 256;
        siblings[i] = *hash;
    }

    // Invariant 1 & 2: must not panic, returns a root.
    let (root, deltas) = incremental_update_raw(
        &input.key,
        &input.value_hash,
        parser_id,
        cpv,
        &siblings,
    );

    // Invariant 3: exactly 256 deltas.
    assert_eq!(deltas.len(), 256, "must produce exactly 256 node deltas");

    // Invariant 4: last delta is the root (db_level=0, empty packed_index).
    let (db_level, packed_index, root_delta_hash) = &deltas[255];
    assert_eq!(*db_level, 0usize, "last delta must be root level (db_level=0)");
    assert!(packed_index.is_empty(), "root delta packed_index must be empty");
    assert_eq!(root_delta_hash, &root, "last delta hash must equal returned root");

    // Invariant 5: deterministic — same inputs produce same root.
    let (root2, _) = incremental_update_raw(
        &input.key,
        &input.value_hash,
        parser_id,
        cpv,
        &siblings,
    );
    assert_eq!(root, root2, "incremental_update_raw must be deterministic");
});
