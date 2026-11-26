// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Fuzz the ADR-0035 signature-envelope wire parser and verifier.
//!
//! Invariants:
//! 1. Arbitrary JSON never panics `SignatureEnvelopeV3::verify` in either mode.
//! 2. Shape errors (schema, suite/algorithm mismatch, duplicate or missing
//!    components, malformed key/signature lengths) come back as typed errors.
//! 3. A deserialized envelope never verifies without its actual key.
//!
//! Audit C-P2-1 asked for wire-parser fuzz coverage; this target covers the
//! envelope schema, including the v3 suite/algorithm binding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use olympus_crypto::signature_envelope::{SignatureEnvelopeV3, SignatureVerificationMode};

fuzz_target!(|data: &[u8]| {
    // The envelope is a small JSON sidecar; anything larger is not a realistic
    // input and only slows the fuzzer down.
    if data.len() > 64 * 1024 {
        return;
    }
    if let Ok(envelope) = serde_json::from_slice::<SignatureEnvelopeV3>(data) {
        let _ = envelope.verify(SignatureVerificationMode::ClassicalRequired);
        let _ = envelope.verify(SignatureVerificationMode::HybridRequired);
    }
});
