// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Producer → verifier round-trip gate (ADR-0030 §3).
//!
//! This is the control the V6 audit carried as `I-01` — "the producer→verifier
//! round-trip gate still does not exist". Until this file, nothing anywhere fed
//! the output of the shipping redaction producer into
//! `olympus_verifier::redaction::verify_bundle`. The offline verifiers were
//! exercised only against `verifiers/test_vectors/redaction_vectors.json`, which
//! is emitted by `gen_redaction_vectors.rs` — a *second* implementation that
//! hand-rolls its own containers and cannot call the real producer (the
//! generator lives in `olympus-crypto`, which must not depend on `src-tauri`).
//!
//! Vectors built that way can only ever prove `verifier == generator`. They
//! cannot prove `verifier == producer`, and the gap is not hypothetical: audit
//! finding `A1-01` was the offline verifiers rejecting *every* genuine producer
//! bundle, with the whole suite green throughout.
//!
//! The direction of the dependency is what makes this work. An integration test
//! in `src-tauri` can dev-depend on `olympus-verifier` by path, which reverses
//! the arrow that blocks the generator, so the real producer and the real
//! verifier meet in one process.
//!
//! What each test asserts:
//!   * a bundle minted by `produce_bundle` — the shipping path, reached through
//!     `perform_redaction` in production — is **accepted** by the offline
//!     verifier with the fold check on; and
//!   * mutating what the bundle claims to bind makes the verifier **reject with
//!     the specific reason**. Acceptance alone would pass if `verify_bundle`
//!     were replaced by `Ok(())`, so the negative controls are what give the
//!     positive one meaning.

use std::collections::HashSet;

use ed25519_dalek::{SigningKey, VerifyingKey};

use olympus_tauri_lib::api::redaction::bundle_v3::V3Bundle;
use olympus_tauri_lib::api::redaction::redact::produce_bundle;
use olympus_tauri_lib::zk::segment::{segment_document, SegmentManifest};

use olympus_verifier::pedersen::Curve;
use olympus_verifier::redaction::{verify_bundle, Bundle, RejectReason, Segment};

/// Arbitrary but fixed — the blind secret only has to be the *same* value at
/// segmentation and at bundle assembly, which is the production contract
/// (`AppState.redaction_blind_secret`, resolved once at startup).
const BLIND_SECRET: &[u8; 32] = b"round-trip-gate-blind-secret-32b";

/// Ed25519 seed standing in for `OLYMPUS_INGEST_SIGNING_KEY`.
const SIGNING_SEED: &[u8; 32] = b"round-trip-gate-ed25519-seed-32b";

fn issuer_vk() -> VerifyingKey {
    SigningKey::from_bytes(SIGNING_SEED).verifying_key()
}

/// Translate the producer's `V3Bundle` into the offline verifier's own `Bundle`.
///
/// The two crates deliberately own separate structs — same wire shape, no
/// shared type — so this really is the relying party's parse step. `artifact_hex`
/// carries the redacted artifact the recipient holds, which is what lets the
/// verifier re-derive spans and refold the tree rather than trust the bundle.
fn to_verifier_bundle(v3: &V3Bundle, artifact: &[u8]) -> Bundle {
    Bundle {
        original_root: v3.original_root.clone(),
        format: v3.format.clone(),
        segment_count: u64::from(v3.segment_count),
        recipient_id: v3.recipient_id.clone(),
        artifact_hex: Some(hex::encode(artifact)),
        segments: v3
            .segments
            .iter()
            .map(|s| Segment {
                segment_id: s.segment_id,
                redacted: s.redacted,
                artifact_offset: s.artifact_offset,
                artifact_length: s.artifact_length,
                label: s.label.clone(),
                blinding_decimal: s.blinding_decimal.clone(),
                leaf_hex: s.leaf_hex.clone(),
            })
            .collect(),
        nullifier: v3.nullifier.clone(),
        signature_hex: v3.signature_hex.clone(),
    }
}

/// Run the whole shipping producer path over `original`, hiding `redacted_ids`.
fn produce(original: &[u8], redacted_ids: &[u32]) -> (SegmentManifest, Vec<u8>, V3Bundle) {
    let manifest = segment_document(original, BLIND_SECRET).expect("segmentation");
    let redacted: HashSet<u32> = redacted_ids.iter().copied().collect();
    let (artifact, bundle) = produce_bundle(
        original,
        &manifest,
        &redacted,
        "12345",
        BLIND_SECRET,
        SIGNING_SEED,
    )
    .expect("produce_bundle");
    (manifest, artifact, bundle)
}

fn verify(bundle: &Bundle) -> Result<(), RejectReason> {
    verify_bundle(&Curve::baby_jubjub(), bundle, &issuer_vk(), true)
}

/// A minimal valid traditional-xref PDF with correct byte offsets.
///
/// Objects 1–3 are the Catalog/Pages/Page skeleton (which the producer refuses
/// to null — the #1306 guard), so the redactable content objects start at 4.
/// This builds the test *input*; every byte the gate actually checks is produced
/// by the real segmenter and the real verifier.
fn build_pdf(bodies: &[&str]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        buf.extend_from_slice(body.as_bytes());
        buf.extend_from_slice(b"\nendobj\n");
    }
    let xref_off = buf.len();
    let n = bodies.len() + 1; // include free object 0
    buf.extend_from_slice(format!("xref\n0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        buf.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    buf.extend_from_slice(format!("trailer\n<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

fn sample_pdf() -> Vec<u8> {
    build_pdf(&[
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
        "<< /Secret (patient name Alice) >>",
        "<< /Public (clinic address) >>",
    ])
}

const SAMPLE_TEXT: &[u8] = b"public header line\nsecret middle line\npublic footer line\n";

// ── Positive: the shipping producer's output verifies offline ────────────────

#[test]
fn text_line_bundle_from_real_producer_is_accepted_by_offline_verifier() {
    let (manifest, artifact, v3) = produce(SAMPLE_TEXT, &[1]);
    assert_eq!(manifest.format.as_tag(), "text-line");

    let bundle = to_verifier_bundle(&v3, &artifact);
    assert_eq!(verify(&bundle), Ok(()));
}

#[test]
fn pdf_object_bundle_from_real_producer_is_accepted_by_offline_verifier() {
    let pdf = sample_pdf();
    let (manifest, artifact, v3) = produce(&pdf, &[4]);
    assert_eq!(manifest.format.as_tag(), "pdf-object");

    let bundle = to_verifier_bundle(&v3, &artifact);
    assert_eq!(verify(&bundle), Ok(()));
}

/// The producer's destroyed representation for `pdf-object` is ADR-0034's
/// structural null via a file rebuild — *not* the in-place NUL-fill ADR-0030
/// used to describe. Pinning it here means a silent revert to NUL-filling
/// breaks this gate rather than only the prose.
#[test]
fn pdf_object_redacted_body_is_the_structural_null_token() {
    let pdf = sample_pdf();
    let (_, artifact, _) = produce(&pdf, &[4]);

    let text = String::from_utf8_lossy(&artifact);
    assert!(
        text.contains("4 0 obj\nnull\nendobj"),
        "redacted object must be rebuilt as the `null` structural token (ADR-0034 §2)"
    );
    assert!(
        !artifact.contains(&0x00),
        "no NUL bytes: the in-place NUL-fill was rejected by ADR-0034"
    );
    assert!(
        !text.contains("patient name Alice"),
        "redacted content must not survive into the artifact"
    );
}

// ── Negative controls: the acceptance above has to be falsifiable ────────────

#[test]
fn tampering_a_revealed_segment_in_the_artifact_breaks_the_fold() {
    let (_, artifact, v3) = produce(SAMPLE_TEXT, &[1]);
    let bundle = to_verifier_bundle(&v3, &artifact);
    assert_eq!(
        verify(&bundle),
        Ok(()),
        "precondition: clean bundle verifies"
    );

    // Flip a byte inside a revealed segment's span. The revealed leaf is
    // recomputed from these exact bytes, so the fold must stop matching the
    // signed root.
    let revealed = v3
        .segments
        .iter()
        .find(|s| !s.redacted)
        .expect("a revealed segment");
    let mut mutated = artifact.clone();
    mutated[revealed.artifact_offset as usize] ^= 0x20;

    let tampered = to_verifier_bundle(&v3, &mutated);
    assert_eq!(
        verify(&tampered),
        Err(RejectReason("fold != original_root"))
    );
}

#[test]
fn tampering_a_redacted_leaf_breaks_the_fold() {
    let (_, artifact, mut v3) = produce(SAMPLE_TEXT, &[1]);

    let seg = v3
        .segments
        .iter_mut()
        .find(|s| s.redacted)
        .expect("a redacted segment");
    // Keep it a canonical field element so this fails at the fold, not at the
    // structural hex check — otherwise the test would pass for the wrong reason.
    seg.leaf_hex = Some(format!("{:064x}", 1u8));

    let tampered = to_verifier_bundle(&v3, &artifact);
    assert_eq!(
        verify(&tampered),
        Err(RejectReason("fold != original_root"))
    );
}

#[test]
fn tampering_the_nullifier_is_detected() {
    let (_, artifact, mut v3) = produce(SAMPLE_TEXT, &[1]);
    v3.nullifier = format!("{:064x}", 2u8);

    let tampered = to_verifier_bundle(&v3, &artifact);
    assert_eq!(verify(&tampered), Err(RejectReason("nullifier mismatch")));
}

#[test]
fn a_bundle_signed_by_another_key_is_rejected() {
    let (_, artifact, v3) = produce(SAMPLE_TEXT, &[1]);
    let bundle = to_verifier_bundle(&v3, &artifact);

    let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    assert_eq!(
        verify_bundle(&Curve::baby_jubjub(), &bundle, &other, true),
        Err(RejectReason("Ed25519 signature invalid"))
    );
}
