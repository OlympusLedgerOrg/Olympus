//! Fuzz target for `crypto::KeyManager::sign_root()`.
//!
//! Exercises the Ed25519 signing path with arbitrary root bytes, tree_size,
//! and context maps.  The signing operation must never panic — in particular
//! the length-prefixed context serialization and `ed25519_dalek::Signer::sign`
//! must handle all inputs gracefully.
//!
//! The `KeyManager` is created once (via `LazyLock`) so that:
//! - Crashes are reproducible (same key + same fuzz input = same result).
//! - CPU time is spent fuzzing `sign_root`, not regenerating Ed25519 keys.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use std::sync::LazyLock;

use cdhs_smf_service::crypto::KeyManager;

/// Single `KeyManager` shared across all fuzz iterations.
/// Set SEQUENCER_SMT_SIGNING_KEY once at startup to a fixed test key.
static KEY_MANAGER: LazyLock<KeyManager> = LazyLock::new(|| {
    // Set a deterministic test key for reproducible fuzzing
    std::env::set_var("SEQUENCER_SMT_SIGNING_KEY", "0000000000000000000000000000000000000000000000000000000000000000");
    KeyManager::new()
});

#[derive(Arbitrary, Debug)]
struct SignRootInput {
    root: [u8; 32],
    tree_size: u64,
    context: Vec<(String, String)>,
}

fuzz_target!(|input: SignRootInput| {
    let context: HashMap<String, String> = input.context.into_iter().collect();

    // Must not panic.
    let _ = KEY_MANAGER.sign_root(&input.root, input.tree_size, &context);
});
