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

// ── ooxml-part ──────────────────────────────────────────────────────────────
//
// This format was the gap this gate originally left open, and it is where the
// hand-built vectors had actually drifted: the generator's own ZIP writer emitted
// `version_needed = 20, mdate = 0`, a local-header profile the shipping producer
// never produces (it emits `10` / `33` via the `zip` crate). Both offline
// verifiers carried widened allowances — `version ∈ {10, 20}`, `mdate ∈ {0, 33}` —
// so the fixture stayed acceptable and nothing failed. Feeding real producer
// output through `verify_bundle` is what pins the profile that actually ships.

/// Root relationship part naming the main document, so the producer can resolve
/// the package skeleton it refuses to redact.
const ROOT_RELS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#;

/// A minimal valid OOXML package. Sorted part order gives the segment ids:
/// 0 `[Content_Types].xml`, 1 `_rels/.rels`, 2 `word/document.xml`,
/// 3 `word/media/secret.bin` — only 3 is redactable, the rest being structural
/// or XML.
fn sample_docx() -> Vec<u8> {
    let parts = vec![
        ("[Content_Types].xml".to_string(), b"<Types/>".to_vec()),
        ("_rels/.rels".to_string(), ROOT_RELS.to_vec()),
        (
            "word/document.xml".to_string(),
            b"<w:document>hello public world</w:document>".to_vec(),
        ),
        (
            "word/media/secret.bin".to_string(),
            b"patient name Alice".to_vec(),
        ),
    ];
    olympus_crypto::container::ooxml::write_canonical_stored_zip(&parts).expect("build docx")
}

#[test]
fn ooxml_part_bundle_from_real_producer_is_accepted_by_offline_verifier() {
    let docx = sample_docx();
    let (manifest, artifact, v3) = produce(&docx, &[3]);
    assert_eq!(manifest.format.as_tag(), "ooxml-part");

    let bundle = to_verifier_bundle(&v3, &artifact);
    assert_eq!(verify(&bundle), Ok(()));
}

/// `ooxml-part` redaction is length-hiding: the entry survives with its name
/// visible but a zero-length payload, so the artifact never discloses the
/// original size (ADR-0034). A revert to width-preserving fill breaks this.
#[test]
fn ooxml_redacted_part_is_emptied_not_filled() {
    let docx = sample_docx();
    let (manifest, artifact, _) = produce(&docx, &[3]);

    let secret = manifest
        .segments
        .iter()
        .find(|s| s.label.as_deref() == Some("word/media/secret.bin"))
        .expect("secret part committed");
    assert_eq!(secret.segment_id, 3);

    let spans = olympus_crypto::container::ooxml::stored_data_spans(&artifact).expect("spans");
    let &(_, length) = spans
        .get("word/media/secret.bin")
        .expect("entry survives redaction");
    assert_eq!(length, 0, "redacted part must be emptied, not filled");

    // The plaintext must be gone from the artifact entirely.
    assert!(
        !artifact
            .windows(b"patient name Alice".len())
            .any(|w| w == b"patient name Alice"),
        "redacted payload still present in the artifact"
    );
}

/// CRC-32 (IEEE, reflected) — the checksum the ZIP local header and central
/// directory both carry.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

/// Overwrite one payload byte of `name` **and repair both CRC copies**, leaving a
/// structurally canonical package.
///
/// The repair is the whole point. A naive byte flip is caught by the verifier's
/// CRC check (`non-canonical ooxml zip entry`) before the fold is ever computed,
/// so a test that skipped this would be exercising ZIP container integrity while
/// claiming to exercise the commitment. Keeping the package well-formed leaves
/// the Merkle fold as the only thing that can still object.
fn tamper_ooxml_payload_keeping_crcs_valid(artifact: &mut [u8], name: &str) {
    let spans = olympus_crypto::container::ooxml::stored_data_spans(artifact).expect("spans");
    let &(offset, length) = spans.get(name).expect("part present");
    assert!(length > 0, "need a non-empty part to tamper");

    let data_start = offset as usize;
    artifact[data_start] ^= 0xff;
    let new_crc = crc32(&artifact[data_start..data_start + length as usize]);

    // Local header: extra_len is 0 in the canonical profile, so the header starts
    // 30 + name_len before the data. CRC sits at header_start + 14.
    let local_header = data_start - 30 - name.len();
    assert_eq!(&artifact[local_header..local_header + 4], b"PK\x03\x04");
    artifact[local_header + 14..local_header + 18].copy_from_slice(&new_crc.to_le_bytes());

    // Central directory: find this entry's record by its local-header offset
    // (at +42) and patch the CRC copy at +16.
    let mut i = 0usize;
    let mut patched = false;
    while i + 46 <= artifact.len() {
        if &artifact[i..i + 4] == b"PK\x01\x02" {
            let rel = u32::from_le_bytes(artifact[i + 42..i + 46].try_into().unwrap()) as usize;
            if rel == local_header {
                artifact[i + 16..i + 20].copy_from_slice(&new_crc.to_le_bytes());
                patched = true;
                break;
            }
            let name_len =
                u16::from_le_bytes(artifact[i + 28..i + 30].try_into().unwrap()) as usize;
            let extra = u16::from_le_bytes(artifact[i + 30..i + 32].try_into().unwrap()) as usize;
            let comment = u16::from_le_bytes(artifact[i + 32..i + 34].try_into().unwrap()) as usize;
            i += 46 + name_len + extra + comment;
        } else {
            i += 1;
        }
    }
    assert!(patched, "central directory entry for {name} not found");
}

/// The same fold binding the other formats get: altering a revealed part's bytes
/// must break the root, even when the package is left perfectly well-formed.
#[test]
fn tampering_a_revealed_ooxml_part_breaks_the_fold() {
    let docx = sample_docx();
    let (_, mut artifact, v3) = produce(&docx, &[3]);

    tamper_ooxml_payload_keeping_crcs_valid(&mut artifact, "word/document.xml");

    let bundle = to_verifier_bundle(&v3, &artifact);
    assert_eq!(verify(&bundle), Err(RejectReason("fold != original_root")));
}

/// The container-integrity check is a *separate* line of defence from the fold,
/// and it fires first: a raw byte flip that leaves a stale CRC never reaches the
/// commitment. Pinning both reasons keeps the two from being confused for each
/// other.
#[test]
fn a_raw_byte_flip_is_caught_as_a_non_canonical_entry() {
    let docx = sample_docx();
    let (_, mut artifact, v3) = produce(&docx, &[3]);

    let spans = olympus_crypto::container::ooxml::stored_data_spans(&artifact).expect("spans");
    let &(offset, _) = spans.get("word/document.xml").expect("revealed part");
    artifact[offset as usize] ^= 0xff;

    let bundle = to_verifier_bundle(&v3, &artifact);
    assert_eq!(
        verify(&bundle),
        Err(RejectReason("non-canonical ooxml zip entry"))
    );
}

#[test]
fn ooxml_artifact_is_byte_reproducible() {
    let docx = sample_docx();
    let (_, first, _) = produce(&docx, &[3]);
    let (_, second, _) = produce(&docx, &[3]);
    assert_eq!(
        first, second,
        "ooxml redaction artifact is not reproducible"
    );
}
