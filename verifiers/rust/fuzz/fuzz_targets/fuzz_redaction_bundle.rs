//! Fuzz target for the ADR-0030 V3 redaction bundle verifier.
//!
//! The target deliberately feeds arbitrary, often-invalid bundle shapes into
//! `verify_bundle`. The contract is panic freedom: malformed artifacts, segment
//! tables, encodings, signatures, and offsets must reject with `Err`, never
//! unwind in the offline verifier.

#![no_main]

use arbitrary::Arbitrary;
use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use olympus_verifier::pedersen::Curve;
use olympus_verifier::redaction::{verify_bundle, Bundle, Segment};

#[derive(Arbitrary, Debug)]
struct FuzzSegment {
    segment_id: u32,
    redacted: bool,
    artifact_offset: u64,
    artifact_length: u64,
    label: Option<String>,
    blinding_decimal: Option<String>,
    leaf_hex: Option<String>,
}

#[derive(Arbitrary, Debug)]
struct FuzzBundle {
    original_root: String,
    format: String,
    segment_count: u64,
    recipient_id: String,
    artifact_hex: Option<String>,
    segments: Vec<FuzzSegment>,
    nullifier: String,
    signature_hex: String,
}

fuzz_target!(|input: FuzzBundle| {
    let curve = Curve::baby_jubjub();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let issuer_pubkey = signing_key.verifying_key();

    let segments: Vec<Segment> = input
        .segments
        .into_iter()
        .take(64)
        .map(|s| Segment {
            segment_id: s.segment_id,
            redacted: s.redacted,
            artifact_offset: s.artifact_offset,
            artifact_length: s.artifact_length,
            label: s.label,
            blinding_decimal: s.blinding_decimal,
            leaf_hex: s.leaf_hex,
        })
        .collect();

    let bundle = Bundle {
        original_root: input.original_root,
        format: input.format,
        segment_count: input.segment_count.min(64),
        recipient_id: input.recipient_id,
        artifact_hex: input.artifact_hex,
        segments,
        nullifier: input.nullifier,
        signature_hex: input.signature_hex,
    };

    let _ = verify_bundle(&curve, &bundle, &issuer_pubkey, true);
});
