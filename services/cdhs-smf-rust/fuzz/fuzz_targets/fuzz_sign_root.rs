//! Fuzz target for `crypto::KeyManager::sign_root()`.
//!
//! Exercises the Ed25519 signing path with arbitrary root bytes and context
//! maps.  The signing operation must never panic — in particular the
//! length-prefixed context serialization and `ed25519_dalek::Signer::sign`
//! must handle all inputs gracefully.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;

use cdhs_smf_service::crypto::KeyManager;

#[derive(Arbitrary, Debug)]
struct SignRootInput {
    root: [u8; 32],
    context: Vec<(String, String)>,
}

fuzz_target!(|input: SignRootInput| {
    let km = KeyManager::new();
    let context: HashMap<String, String> = input.context.into_iter().collect();

    // Must not panic.
    let _ = km.sign_root(&input.root, &context);
});
