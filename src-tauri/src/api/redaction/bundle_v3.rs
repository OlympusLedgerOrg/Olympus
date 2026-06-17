//! ADR-0030 **V3 redaction bundle** crypto core (Phase 2): the signed segment
//! table, the signed payload, the nullifier, and Ed25519 sign/verify.
//!
//! This is the producer-side assembler plus a signature/structure verifier that
//! does **not** need the redacted artifact (the artifact-based fold
//! reconstruction is the offline recipient verifier — ADR-0030 §3 / Phase 3). It
//! checks that the issuer authorized *exactly* this segment table for this
//! recipient.
//!
//! Values are signed as their **canonical text** renderings (SR-DEC-3 reverted on
//! ratification, 2026-06-15); malleability is closed by the canonical-form reject
//! rules below, not by raw-byte encoding. Encodings (ADR-0030 §2, normative):
//!
//! ```text
//! signed payload = OLY:REDACTION_BUNDLE:V3 || lp(original_root_hex) || lp(format)
//!                  || u32_be(N) || lp(recipient_id_dec) || table_hash(32 raw)
//! table_hash     = BLAKE3( OLY:REDACTION:TABLE:V3
//!                    || for each segment in ascending segment_id:
//!                         u32_be(segment_id) || u8(redacted) || u64_be(offset)
//!                         || u64_be(length) || lp(label) || lp(redacted ? leaf_hex : blinding_decimal) )
//! nullifier      = BLAKE3( OLY:REDACTION:NULLIFIER:V1 || original_root(32 raw)
//!                    || table_hash(32 raw) || lp(recipient_id_dec) )
//! ```
//!
//! Wired into `/redaction/redact` (the V3 producer); the offline recipient
//! verifier (`verify` + artifact-fold reconstruction) lands in the verifiers
//! milestone.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use num_bigint::{BigInt, BigUint};
use olympus_crypto::redaction::{
    is_blinding_in_range, redaction_nullifier, redaction_signing_message, redaction_table_hash,
    RedactionTableEntry,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::types::bn254_fr_modulus;

/// Frozen V3 format tags — mirror `crate::zk::segment::SegmentFormat::as_tag`.
const FORMAT_TAGS: [&str; 4] = ["pdf-object", "pdf-xref-stream", "text-line", "ooxml-part"];

/// BN254 scalar field is 254 bits → 78 decimal digits; Baby JubJub subgroup order
/// is 76 digits. 90 gives slack before `BigUint`/`BigInt::parse_bytes`.
const MAX_DECIMAL_LEN: usize = 90;

/// Operational DoS bound on V3 bundle segment count (ADR-0030 §1, SR-5).
/// The Groth16 `redaction_validity` circuit's 1,024-leaf cap was a circuit
/// *implementation* constraint, removed by ADR-0030. This constant is the
/// normative protocol replacement — 2²⁰ bounds the fold at ~2.1M Poseidon
/// hashes / depth 20. It is implementation defense-in-depth, not a circuit
/// constraint, and may be raised in a future ADR if operational evidence warrants.
const MAX_REDACTION_SEGMENTS: u32 = 1_048_576;

/// One segment row of a V3 bundle (ADR-0030 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V3Segment {
    pub segment_id: u32,
    pub redacted: bool,
    /// Byte range **into the redacted artifact** the recipient holds.
    pub artifact_offset: u64,
    pub artifact_length: u64,
    /// Present (and bound into the leaf) for `ooxml-part`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub label: Option<String>,
    /// Revealed segments only: decimal blinding so the recipient recomputes the leaf.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub blinding_decimal: Option<String>,
    /// Redacted segments only: the committed blinded leaf (64-char lowercase hex).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub leaf_hex: Option<String>,
}

/// A complete V3 redaction bundle (ADR-0030 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V3Bundle {
    /// 64-char lowercase hex of the committed variable-depth fold root.
    pub original_root: String,
    /// Frozen segment-format tag.
    pub format: String,
    pub segment_count: u32,
    /// Canonical decimal recipient field element.
    pub recipient_id: String,
    pub segments: Vec<V3Segment>,
    /// 64-char lowercase hex BLAKE3 nullifier (derived; recompute-and-check).
    pub nullifier: String,
    /// Ed25519 signature over the signed payload, hex.
    pub signature_hex: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum V3Error {
    #[error("segment_count {declared} != segments.len() {actual}")]
    CountMismatch { declared: u32, actual: usize },
    #[error(
        "segment_count {found} exceeds the maximum {max} (ADR-0030 §1, MAX_REDACTION_SEGMENTS)"
    )]
    TooManySegments { found: u32, max: u32 },
    #[error("segment ids must be strictly ascending and unique (at index {0})")]
    NonAscendingIds(usize),
    #[error("ooxml-part requires dense 0..N-1 ids with a label per entry (at index {0})")]
    BadOoxmlStructure(usize),
    #[error("segment {0} is redacted but has no leaf_hex")]
    MissingLeafHex(u32),
    #[error("segment {0} is revealed but has no blinding_decimal")]
    MissingBlinding(u32),
    #[error("segment {0}: a redacted segment must not carry a blinding_decimal")]
    UnexpectedBlinding(u32),
    #[error("segment {0}: a revealed segment must not carry a leaf_hex")]
    UnexpectedLeafHex(u32),
    #[error("{field}: not a canonical lowercase 64-hex field element (< r)")]
    NonCanonicalHex { field: &'static str },
    #[error("{field}: not a canonical base-10 integer in the required range")]
    NonCanonicalDecimal { field: &'static str },
    #[error("format tag is empty or unknown")]
    BadFormat,
    #[error("nullifier mismatch: recomputed value differs from the bundle field")]
    NullifierMismatch,
    #[error("Ed25519 signature is malformed")]
    BadSignatureEncoding,
    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,
}

// ── Canonical-form validators (ADR-0030 §2 "reject, do not reduce") ───────────

/// Validate a canonical lowercase 64-hex string decoding to `< r` (BN254); return
/// the 32 raw bytes. Rejects uppercase, wrong length, non-hex, and `>= r`.
fn validate_field_hex(field: &'static str, s: &str) -> Result<[u8; 32], V3Error> {
    let ok_chars = s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok_chars {
        return Err(V3Error::NonCanonicalHex { field });
    }
    let raw = hex::decode(s).map_err(|_| V3Error::NonCanonicalHex { field })?;
    if BigUint::from_bytes_be(&raw) >= bn254_fr_modulus() {
        return Err(V3Error::NonCanonicalHex { field });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// True iff `s` is a canonical non-negative base-10 integer string (digits only,
/// no sign, no leading zero except the single digit "0").
fn is_canonical_decimal(s: &str) -> bool {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    !(s.len() > 1 && s.starts_with('0'))
}

/// `recipient_id` decimal: canonical and `< r`.
fn validate_recipient_decimal(s: &str) -> Result<(), V3Error> {
    let field = "recipient_id";
    if s.len() > MAX_DECIMAL_LEN || !is_canonical_decimal(s) {
        return Err(V3Error::NonCanonicalDecimal { field });
    }
    let v = BigUint::parse_bytes(s.as_bytes(), 10).ok_or(V3Error::NonCanonicalDecimal { field })?;
    if v >= bn254_fr_modulus() {
        return Err(V3Error::NonCanonicalDecimal { field });
    }
    Ok(())
}

/// `blinding_decimal`: canonical and `∈ [0, l)` (Baby Jubjub subgroup order).
fn validate_blinding_decimal(s: &str) -> Result<(), V3Error> {
    let field = "blinding_decimal";
    if s.len() > MAX_DECIMAL_LEN || !is_canonical_decimal(s) {
        return Err(V3Error::NonCanonicalDecimal { field });
    }
    let v = BigInt::parse_bytes(s.as_bytes(), 10).ok_or(V3Error::NonCanonicalDecimal { field })?;
    if !is_blinding_in_range(&v) {
        return Err(V3Error::NonCanonicalDecimal { field });
    }
    Ok(())
}

/// Validate the whole segment table + scalar fields. Returns the raw 32-byte
/// `original_root`. Enforces strictly-ascending-unique ids (dense `0..N-1` with a
/// label per entry only for `ooxml-part`) and the correct optional fields.
fn validate_structure(
    original_root: &str,
    format: &str,
    segment_count: u32,
    recipient_id: &str,
    segments: &[V3Segment],
) -> Result<[u8; 32], V3Error> {
    if segment_count == 0 || segment_count as usize != segments.len() {
        return Err(V3Error::CountMismatch {
            declared: segment_count,
            actual: segments.len(),
        });
    }
    if segment_count > MAX_REDACTION_SEGMENTS {
        return Err(V3Error::TooManySegments {
            found: segment_count,
            max: MAX_REDACTION_SEGMENTS,
        });
    }
    if !FORMAT_TAGS.contains(&format) {
        return Err(V3Error::BadFormat);
    }
    let root_raw = validate_field_hex("original_root", original_root)?;
    validate_recipient_decimal(recipient_id)?;

    let ooxml = format == "ooxml-part";
    let mut prev: Option<u32> = None;
    for (i, s) in segments.iter().enumerate() {
        if let Some(p) = prev {
            if s.segment_id <= p {
                return Err(V3Error::NonAscendingIds(i));
            }
        }
        prev = Some(s.segment_id);

        if ooxml && (s.segment_id as usize != i || s.label.as_deref().is_none_or(str::is_empty)) {
            return Err(V3Error::BadOoxmlStructure(i));
        }

        if s.redacted {
            let leaf = s
                .leaf_hex
                .as_deref()
                .ok_or(V3Error::MissingLeafHex(s.segment_id))?;
            validate_field_hex("leaf_hex", leaf)?;
            if s.blinding_decimal.is_some() {
                return Err(V3Error::UnexpectedBlinding(s.segment_id));
            }
        } else {
            let b = s
                .blinding_decimal
                .as_deref()
                .ok_or(V3Error::MissingBlinding(s.segment_id))?;
            validate_blinding_decimal(b)?;
            if s.leaf_hex.is_some() {
                return Err(V3Error::UnexpectedLeafHex(s.segment_id));
            }
        }
    }
    Ok(root_raw)
}

// ── Encodings (ADR-0030 §2) ──────────────────────────────────────────────────
//
// The byte-layout is the single source of truth in `olympus_crypto::redaction`
// (the producer and both offline verifiers consume the identical encoders); this
// module only maps the wire `V3Segment` onto `RedactionTableEntry` and delegates.

/// `table_hash` over `segments` in the given (ascending) order. Only called after
/// [`validate_structure`], so the required `leaf_hex`/`blinding_decimal` are present.
/// Maps each `V3Segment` onto an `olympus_crypto::redaction::RedactionTableEntry`
/// (`value_text` = `leaf_hex` when redacted, else `blinding_decimal`; an absent
/// `label` frames as empty) and delegates to the canonical [`redaction_table_hash`].
fn table_hash(segments: &[V3Segment]) -> [u8; 32] {
    let entries: Vec<RedactionTableEntry> = segments
        .iter()
        .map(|s| RedactionTableEntry {
            segment_id: s.segment_id,
            redacted: s.redacted,
            artifact_offset: s.artifact_offset,
            artifact_length: s.artifact_length,
            label: s.label.as_deref().unwrap_or("").as_bytes(),
            value_text: if s.redacted {
                s.leaf_hex.as_deref().unwrap_or("")
            } else {
                s.blinding_decimal.as_deref().unwrap_or("")
            },
        })
        .collect();
    redaction_table_hash(&entries)
}

// ── Assemble + verify ────────────────────────────────────────────────────────

/// Build a signed V3 bundle from validated segments: validate, compute
/// `table_hash` + `nullifier`, and Ed25519-sign the payload.
pub fn assemble_and_sign(
    original_root: &str,
    format: &str,
    recipient_id: &str,
    segments: Vec<V3Segment>,
    signing_key: &[u8; 32],
) -> Result<V3Bundle, V3Error> {
    let n = segments.len() as u32;
    let root_raw = validate_structure(original_root, format, n, recipient_id, &segments)?;
    let th = table_hash(&segments);
    let payload = redaction_signing_message(original_root, format, n, recipient_id, &th);
    let sk = SigningKey::from_bytes(signing_key);
    let signature_hex = hex::encode(sk.sign(&payload).to_bytes());
    let nullifier = hex::encode(redaction_nullifier(&root_raw, &th, recipient_id));
    Ok(V3Bundle {
        original_root: original_root.to_string(),
        format: format.to_string(),
        segment_count: n,
        recipient_id: recipient_id.to_string(),
        segments,
        nullifier,
        signature_hex,
    })
}

/// Verify a V3 bundle's structure + Ed25519 signature + nullifier against an
/// issuer verifying key. Does **not** reconstruct leaves from an artifact (that is
/// the offline recipient verifier, ADR-0030 §3).
///
/// The in-process producer mints bundles via [`assemble_and_sign`]; this
/// structure/signature verifier is exercised by the unit tests below and is the
/// seam the verifiers milestone builds the artifact-fold recipient check on, so
/// it has no production caller yet.
#[allow(dead_code)]
pub fn verify(bundle: &V3Bundle, vk: &VerifyingKey) -> Result<(), V3Error> {
    let root_raw = validate_structure(
        &bundle.original_root,
        &bundle.format,
        bundle.segment_count,
        &bundle.recipient_id,
        &bundle.segments,
    )?;
    let th = table_hash(&bundle.segments);
    let payload = redaction_signing_message(
        &bundle.original_root,
        &bundle.format,
        bundle.segment_count,
        &bundle.recipient_id,
        &th,
    );

    if bundle.signature_hex.len() != 128
        || !bundle
            .signature_hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(V3Error::BadSignatureEncoding);
    }
    let sig_bytes: [u8; 64] = hex::decode(&bundle.signature_hex)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b).ok())
        .ok_or(V3Error::BadSignatureEncoding)?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(&payload, &sig)
        .map_err(|_| V3Error::SignatureInvalid)?;

    // Recompute + check the nullifier (well-formedness; SR-DEC-2 reverted — kept).
    let expected = hex::encode(redaction_nullifier(&root_raw, &th, &bundle.recipient_id));
    if expected != bundle.nullifier {
        return Err(V3Error::NullifierMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn rev(id: u32, blinding: &str) -> V3Segment {
        V3Segment {
            segment_id: id,
            redacted: false,
            artifact_offset: 0,
            artifact_length: 10,
            label: None,
            blinding_decimal: Some(blinding.to_string()),
            leaf_hex: None,
        }
    }

    fn red(id: u32, leaf: &str) -> V3Segment {
        V3Segment {
            segment_id: id,
            redacted: true,
            artifact_offset: 0,
            artifact_length: 0,
            label: None,
            blinding_decimal: None,
            leaf_hex: Some(leaf.to_string()),
        }
    }

    fn leaf_hex(n: u8) -> String {
        format!("{n:064x}")
    }

    fn sample() -> V3Bundle {
        let segs = vec![rev(0, "42"), red(1, &leaf_hex(7)), rev(2, "100")];
        assemble_and_sign(&leaf_hex(5), "text-line", "12345", segs, &key().to_bytes()).unwrap()
    }

    #[test]
    fn assemble_then_verify_roundtrips() {
        let b = sample();
        assert_eq!(verify(&b, &key().verifying_key()), Ok(()));
    }

    #[test]
    fn table_hash_binds_id_flag_range_label_and_value() {
        let base = table_hash(&[rev(0, "42"), red(1, &leaf_hex(7))]);
        // Different id.
        assert_ne!(base, table_hash(&[rev(0, "42"), red(2, &leaf_hex(7))]));
        // Flipped reveal/redact role (the partition).
        assert_ne!(
            base,
            table_hash(&[red(0, &leaf_hex(9)), red(1, &leaf_hex(7))])
        );
        // Different byte range.
        let mut moved = rev(0, "42");
        moved.artifact_offset = 5;
        assert_ne!(base, table_hash(&[moved, red(1, &leaf_hex(7))]));
        // Different leaf value.
        assert_ne!(base, table_hash(&[rev(0, "42"), red(1, &leaf_hex(8))]));
    }

    #[test]
    fn signature_binds_the_partition_flag() {
        // Mandatory regression: flip a segment's revealed→redacted role on an
        // otherwise-valid bundle (kept structurally valid) and assert the signature
        // check fails — the table_hash changes, so the old signature no longer verifies.
        let mut b = sample();
        b.segments[0] = red(0, &leaf_hex(3)); // was revealed id 0
        assert_eq!(
            verify(&b, &key().verifying_key()),
            Err(V3Error::SignatureInvalid)
        );
    }

    #[test]
    fn nullifier_tamper_is_detected() {
        let mut b = sample();
        b.nullifier = leaf_hex(0xaa); // valid hex, wrong value
        assert_eq!(
            verify(&b, &key().verifying_key()),
            Err(V3Error::NullifierMismatch)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let b = sample();
        let other = SigningKey::from_bytes(&[9u8; 32]);
        assert_eq!(
            verify(&b, &other.verifying_key()),
            Err(V3Error::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_noncanonical_leaf_hex() {
        // Uppercase hex is non-canonical. Use a value with hex LETTERS (0xab) so
        // to_uppercase() actually changes it (an all-digit value would be a no-op).
        let upper = leaf_hex(0xab).to_uppercase();
        assert!(upper.contains('A'), "test value must contain a hex letter");
        let segs = vec![rev(0, "42"), red(1, &upper)];
        assert!(matches!(
            assemble_and_sign(&leaf_hex(5), "text-line", "12345", segs, &key().to_bytes()),
            Err(V3Error::NonCanonicalHex { field: "leaf_hex" })
        ));
    }

    #[test]
    fn rejects_noncanonical_decimals() {
        // Leading-zero blinding.
        let segs = vec![rev(0, "042")];
        assert!(matches!(
            assemble_and_sign(&leaf_hex(5), "text-line", "12345", segs, &key().to_bytes()),
            Err(V3Error::NonCanonicalDecimal {
                field: "blinding_decimal"
            })
        ));
        // Leading-zero recipient.
        let segs = vec![rev(0, "42"), rev(1, "7")];
        assert!(matches!(
            assemble_and_sign(&leaf_hex(5), "text-line", "0123", segs, &key().to_bytes()),
            Err(V3Error::NonCanonicalDecimal {
                field: "recipient_id"
            })
        ));
    }

    #[test]
    fn rejects_wrong_optional_fields_and_ordering() {
        // Redacted segment carrying a blinding.
        let mut bad = red(1, &leaf_hex(7));
        bad.blinding_decimal = Some("9".to_string());
        assert!(matches!(
            assemble_and_sign(
                &leaf_hex(5),
                "text-line",
                "1",
                vec![rev(0, "1"), bad],
                &key().to_bytes()
            ),
            Err(V3Error::UnexpectedBlinding(1))
        ));
        // Non-ascending ids.
        assert!(matches!(
            assemble_and_sign(
                &leaf_hex(5),
                "text-line",
                "1",
                vec![rev(1, "1"), rev(1, "2")],
                &key().to_bytes()
            ),
            Err(V3Error::NonAscendingIds(1))
        ));
    }

    #[test]
    fn ooxml_requires_dense_ids_and_labels() {
        // Sparse ids are rejected for ooxml-part.
        let mut a = rev(0, "1");
        a.label = Some("[Content_Types].xml".to_string());
        let mut b = rev(2, "2");
        b.label = Some("word/document.xml".to_string());
        assert!(matches!(
            assemble_and_sign(
                &leaf_hex(5),
                "ooxml-part",
                "1",
                vec![a, b],
                &key().to_bytes()
            ),
            Err(V3Error::BadOoxmlStructure(1))
        ));
        // Empty-string label is also rejected (same as None for the hash).
        let mut c = rev(0, "1");
        c.label = Some("".to_string());
        assert!(matches!(
            assemble_and_sign(&leaf_hex(5), "ooxml-part", "1", vec![c], &key().to_bytes()),
            Err(V3Error::BadOoxmlStructure(0))
        ));
    }

    #[test]
    fn rejects_zero_segments() {
        assert!(matches!(
            assemble_and_sign(&leaf_hex(5), "text-line", "1", vec![], &key().to_bytes()),
            Err(V3Error::CountMismatch {
                declared: 0,
                actual: 0
            })
        ));
    }

    #[test]
    fn cap_boundary() {
        // Verify the constant is 2²⁰ as specified in ADR-0030 §1 (SR-5).
        assert_eq!(MAX_REDACTION_SEGMENTS, 1_048_576);
        assert_eq!(MAX_REDACTION_SEGMENTS, 1u32 << 20);

        // Verify the error variant and message for an over-cap count.
        let e = V3Error::TooManySegments {
            found: MAX_REDACTION_SEGMENTS + 1,
            max: MAX_REDACTION_SEGMENTS,
        };
        let msg = e.to_string();
        assert!(msg.contains("1048577"), "found count must appear: {msg}");
        assert!(msg.contains("1048576"), "max must appear: {msg}");
    }

    #[test]
    fn bundle_json_roundtrips() {
        use olympus_crypto::canonical::canonicalize_bytes;
        let b = sample();
        let json = serde_json::to_vec(&b).unwrap();
        let canonical = canonicalize_bytes(&json).unwrap();
        let back: V3Bundle = serde_json::from_slice(&canonical).unwrap();
        assert_eq!(b, back);
        assert_eq!(verify(&back, &key().verifying_key()), Ok(()));
    }
}
