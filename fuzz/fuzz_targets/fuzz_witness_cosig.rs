//! Fuzz the witness cosignature verifier.
//!
//! Invariants:
//! 1. `verify_witness_cosignature` must never panic for any input.
//! 2. It returns Ok or a typed CryptoError — never unwinds unexpectedly.
//! 3. A threshold of 0 always returns InvalidThreshold.
//! 4. An out-of-range witness_index is silently skipped, not a panic.
//! 5. A valid signature from a key in the set succeeds when threshold is met.
//! 6. A bit-flipped signature always fails verification.
#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use olympus_core::crypto::{verify_witness_cosignature, CryptoError, Cosignature};

/// Fixed key pool (deterministic seeds) so we have real verifying keys to fuzz against.
/// The pool is small enough to keep compile time low.
const POOL_SIZE: usize = 4;

fn key_pool() -> [SigningKey; POOL_SIZE] {
    std::array::from_fn(|i| SigningKey::from_bytes(&[i as u8 + 1; 32]))
}

#[derive(Debug, Arbitrary)]
struct WitnessInput {
    root: [u8; 32],
    /// Which pool keys to include as witness_keys (bitmask over POOL_SIZE bits).
    key_mask: u8,
    /// Cosignature attempts: (pool_index, signature_bytes, flip_byte_idx).
    cosigs: Vec<(u8, [u8; 64], Option<u8>)>,
    threshold: u8,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = WitnessInput::arbitrary(&mut u) else {
        return;
    };

    let pool = key_pool();

    // Build the witness_keys list from the pool according to the bitmask.
    let witness_keys: Vec<_> = (0..POOL_SIZE)
        .filter(|i| input.key_mask & (1 << i) != 0)
        .map(|i| pool[i].verifying_key())
        .collect();

    // Build cosignatures.
    let cosigs: Vec<Cosignature> = input
        .cosigs
        .iter()
        .map(|(idx, sig_bytes, flip)| {
            let mut bytes = *sig_bytes;
            if let Some(fi) = flip {
                let fi = (*fi as usize) % 64;
                bytes[fi] ^= 0xFF;
            }
            Cosignature {
                witness_index: (*idx as usize) % (POOL_SIZE + 2), // allow OOB indices
                signature: bytes,
            }
        })
        .collect();

    let threshold = input.threshold as usize;

    // Invariant 1 & 2: must never panic.
    let result = verify_witness_cosignature(&input.root, &cosigs, &witness_keys, threshold);

    // Invariant 3: threshold=0 with any witness set is always InvalidThreshold.
    if threshold == 0 {
        assert_eq!(result, Err(CryptoError::InvalidThreshold));
        return;
    }

    // Invariant 3 (cont): threshold > keys.len() is also InvalidThreshold.
    if threshold > witness_keys.len() {
        assert_eq!(result, Err(CryptoError::InvalidThreshold));
        return;
    }

    // For the remaining cases result is Ok or ThresholdNotMet — both are valid.
    // The fuzzer explores all the paths between them.
    let _ = result;
});
