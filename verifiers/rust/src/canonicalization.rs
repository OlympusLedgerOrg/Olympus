// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Independent verifier for ADR-0040 canonicalization receipts.
//!
//! This module deliberately does not import the desktop canonicalization host
//! code or `olympus_crypto::canonical_proof`. It independently decodes the
//! fixed-width journal and reproduces the existing unified circuit's eight-slot
//! Poseidon commitment before the caller runs the separate Groth16 check.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use light_poseidon::{Poseidon, PoseidonHasher};
use risc0_zkvm::{compute_image_id, Digest, InnerReceipt, Receipt, VerifierContext};
use thiserror::Error;

const CLAIM_MAGIC: [u8; 8] = *b"OLYCAN01";
const CLAIM_ENCODED_LEN: usize = 96;
const MAX_SOURCE_BYTES: u64 = 1024 * 1024;
const MAX_CANONICAL_BYTES: u64 = 1024 * 1024;
const SECTION_COUNT: usize = 1;
const SECTION_SLOTS: usize = 8;
const COMMITMENT_DOMAIN: u64 = 3;
const MERKLE_NODE_DOMAIN: u64 = 2;
const DOCUMENT_MERKLE_DEPTH: usize = 20;

/// Maximum decoded JSON serialization of a receipt accepted by this verifier.
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024 * 1024;
/// Maximum canonical base64 length for [`MAX_RECEIPT_BYTES`].
pub const MAX_RECEIPT_BASE64_BYTES: usize = MAX_RECEIPT_BYTES.div_ceil(3) * 4;

const GUEST_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../proofs/zkvm/canonicalization/olympus_canonicalization_guest.elf"
));
const GUEST_IMAGE_ID: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../proofs/zkvm/canonicalization/olympus_canonicalization_guest.id"
));

#[derive(Clone, Debug, PartialEq, Eq)]
struct CanonicalizationClaim {
    source_len: u64,
    canonical_len: u64,
    source_commitment: [u8; 32],
    canonical_digest: [u8; 32],
}

/// Receipt and binding material authenticated before the Groth16 pairing check.
#[derive(Clone, Debug)]
pub struct VerifiedCanonicalization {
    /// Image ID derived from the exact guest ELF embedded in this verifier.
    pub image_id: Digest,
    /// Source commitment authenticated by the receipt journal.
    pub source_commitment: [u8; 32],
    /// Eight-slot commitment required to equal Groth16 public signal zero.
    pub canonical_hash: Fr,
}

#[derive(Debug, Error)]
pub enum CanonicalizationError {
    #[error("canonicalization guest artifact is a placeholder")]
    PlaceholderArtifact,
    #[error("canonicalization guest image is invalid: {0}")]
    InvalidGuestImage(String),
    #[error("pinned canonicalization guest image ID is invalid: {0}")]
    InvalidPinnedImageId(&'static str),
    #[error("canonicalization guest image ID mismatch: pinned {pinned}, computed {computed}")]
    ImageIdMismatch { pinned: String, computed: String },
    #[error("canonicalization receipt exceeds the {MAX_RECEIPT_BYTES}-byte decoded limit")]
    ReceiptTooLarge,
    #[error("canonicalization receipt is not canonical base64: {0}")]
    Base64(String),
    #[error("canonicalization receipt JSON is invalid: {0}")]
    ReceiptJson(String),
    #[error("canonicalization receipt must use the succinct proof format")]
    UnsupportedReceiptKind,
    #[error("canonicalization receipt proof rejected: {0}")]
    ReceiptRejected(String),
    #[error("canonicalization journal is malformed: {0}")]
    MalformedJournal(&'static str),
    #[error("source commitment must be exactly 64 lowercase hexadecimal characters")]
    MalformedSourceCommitment,
    #[error("source commitment does not match the authenticated receipt journal")]
    SourceCommitmentMismatch,
    #[error("combined canonicalization proof requires exactly 5 public signals, got {0}")]
    PublicSignalCount(usize),
    #[error("Poseidon commitment failed: {0}")]
    Poseidon(String),
    #[error("receipt-derived commitment does not match Groth16 public signal zero")]
    CommitmentMismatch,
    #[error("treeSize=0 requires the depth-20 empty document Merkle root")]
    EmptyTreeMismatch,
}

impl CanonicalizationError {
    /// Whether this error is a clean cryptographic rejection (CLI exit 1).
    /// Structural/configuration failures remain malformed-input errors (exit 2).
    pub fn is_rejection(&self) -> bool {
        matches!(
            self,
            Self::ReceiptRejected(_)
                | Self::SourceCommitmentMismatch
                | Self::CommitmentMismatch
                | Self::EmptyTreeMismatch
        )
    }
}

/// Verify the RISC Zero receipt and bind its claim to the unified Groth16
/// public signals. The caller must run the Groth16 pairing check only after
/// this function succeeds.
pub fn verify_receipt_binding(
    encoded_receipt: &str,
    expected_source_commitment: &str,
    public_signals: &[Fr],
) -> Result<VerifiedCanonicalization, CanonicalizationError> {
    if public_signals.len() != 5 {
        return Err(CanonicalizationError::PublicSignalCount(
            public_signals.len(),
        ));
    }

    let receipt_bytes = decode_canonical_base64(encoded_receipt)?;
    let receipt: Receipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| CanonicalizationError::ReceiptJson(error.to_string()))?;
    if !matches!(&receipt.inner, InnerReceipt::Succinct(_)) {
        return Err(CanonicalizationError::UnsupportedReceiptKind);
    }
    let image_id = canonicalization_image_id()?;
    receipt
        .verify_with_context(&strict_verifier_context(), image_id)
        .map_err(|error| CanonicalizationError::ReceiptRejected(error.to_string()))?;

    // The journal is security-relevant only after the receipt has authenticated
    // it against the pinned image ID.
    let claim = decode_claim(&receipt.journal.bytes)?;
    let expected_source = decode_source_commitment(expected_source_commitment)?;
    if expected_source != claim.source_commitment {
        return Err(CanonicalizationError::SourceCommitmentMismatch);
    }

    let canonical_hash = map_claim_to_canonical_hash(&claim)?;
    if canonical_hash != public_signals[0] {
        return Err(CanonicalizationError::CommitmentMismatch);
    }
    enforce_empty_tree_invariant(public_signals)?;

    Ok(VerifiedCanonicalization {
        image_id,
        source_commitment: claim.source_commitment,
        canonical_hash,
    })
}

/// Compute the image ID from the exact committed guest artifact.
pub fn canonicalization_image_id() -> Result<Digest, CanonicalizationError> {
    static IMAGE_ID: OnceLock<Result<Digest, String>> = OnceLock::new();

    if GUEST_ELF.starts_with(b"PLACEHOLDER") || GUEST_IMAGE_ID.starts_with("PLACEHOLDER") {
        return Err(CanonicalizationError::PlaceholderArtifact);
    }
    let pinned = decode_image_id_text(GUEST_IMAGE_ID)?;
    let computed = IMAGE_ID
        .get_or_init(|| compute_image_id(GUEST_ELF).map_err(|error| error.to_string()))
        .clone()
        .map_err(CanonicalizationError::InvalidGuestImage)?;
    if computed != pinned {
        return Err(CanonicalizationError::ImageIdMismatch {
            pinned: pinned.to_string(),
            computed: computed.to_string(),
        });
    }
    Ok(computed)
}

fn decode_image_id_text(value: &str) -> Result<Digest, CanonicalizationError> {
    // Permit one conventional final LF, but no other whitespace or alternate
    // hexadecimal representation. The build script emits this exact shape.
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalizationError::InvalidPinnedImageId(
            "expected exactly 64 lowercase hexadecimal characters and an optional final LF",
        ));
    }
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| {
        CanonicalizationError::InvalidPinnedImageId("image ID hexadecimal decoding failed")
    })?;
    Ok(Digest::from(bytes))
}

fn strict_verifier_context() -> VerifierContext {
    // Do not call `VerifierContext::default()`: upstream consults
    // RISC0_DEV_MODE while constructing it and panics when that variable is set
    // together with `disable-dev-mode`. Build the equivalent verifier-only
    // context explicitly; `empty()` starts with dev mode false.
    VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_segment_verifier_parameters(Default::default())
        .with_succinct_verifier_parameters(Default::default())
        .with_groth16_verifier_parameters(Default::default())
}

fn decode_canonical_base64(encoded: &str) -> Result<Vec<u8>, CanonicalizationError> {
    if encoded.len() > MAX_RECEIPT_BASE64_BYTES {
        return Err(CanonicalizationError::ReceiptTooLarge);
    }
    let decoded = BASE64
        .decode(encoded)
        .map_err(|error| CanonicalizationError::Base64(error.to_string()))?;
    if decoded.len() > MAX_RECEIPT_BYTES {
        return Err(CanonicalizationError::ReceiptTooLarge);
    }
    if BASE64.encode(&decoded) != encoded {
        return Err(CanonicalizationError::Base64(
            "non-canonical encoding".to_owned(),
        ));
    }
    Ok(decoded)
}

fn decode_claim(bytes: &[u8]) -> Result<CanonicalizationClaim, CanonicalizationError> {
    if bytes.len() != CLAIM_ENCODED_LEN {
        return Err(CanonicalizationError::MalformedJournal(
            "wrong encoded length",
        ));
    }
    if bytes[..8] != CLAIM_MAGIC {
        return Err(CanonicalizationError::MalformedJournal(
            "wrong magic/version",
        ));
    }

    let source_len = u64::from_be_bytes(bytes[8..16].try_into().expect("fixed slice"));
    let canonical_len = u64::from_be_bytes(bytes[16..24].try_into().expect("fixed slice"));
    if source_len == 0 || source_len > MAX_SOURCE_BYTES {
        return Err(CanonicalizationError::MalformedJournal(
            "source length must be in 1..=1 MiB",
        ));
    }
    if canonical_len == 0 || canonical_len > MAX_CANONICAL_BYTES {
        return Err(CanonicalizationError::MalformedJournal(
            "canonical length must be in 1..=1 MiB",
        ));
    }
    if bytes[88] as usize != SECTION_COUNT {
        return Err(CanonicalizationError::MalformedJournal(
            "section count must equal one",
        ));
    }
    if bytes[89..96].iter().any(|byte| *byte != 0) {
        return Err(CanonicalizationError::MalformedJournal(
            "reserved bytes must be zero",
        ));
    }

    Ok(CanonicalizationClaim {
        source_len,
        canonical_len,
        source_commitment: bytes[24..56].try_into().expect("fixed slice"),
        canonical_digest: bytes[56..88].try_into().expect("fixed slice"),
    })
}

fn decode_source_commitment(value: &str) -> Result<[u8; 32], CanonicalizationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CanonicalizationError::MalformedSourceCommitment);
    }
    let mut decoded = [0u8; 32];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| CanonicalizationError::MalformedSourceCommitment)?;
    Ok(decoded)
}

fn map_claim_to_canonical_hash(claim: &CanonicalizationClaim) -> Result<Fr, CanonicalizationError> {
    let document_section = Fr::from_be_bytes_mod_order(&claim.canonical_digest);
    let real_section_hash = poseidon(&[document_section])?;
    let padding_section_hash = poseidon(&[Fr::from(0u64)])?;

    let mut accumulator = Fr::from(SECTION_COUNT as u64);
    for slot in 0..SECTION_SLOTS {
        let length = if slot == 0 { claim.canonical_len } else { 0 };
        let section_hash = if slot == 0 {
            real_section_hash
        } else {
            padding_section_hash
        };
        accumulator = domain_poseidon(COMMITMENT_DOMAIN, accumulator, Fr::from(length))?;
        accumulator = domain_poseidon(COMMITMENT_DOMAIN, accumulator, section_hash)?;
    }
    Ok(accumulator)
}

fn poseidon(inputs: &[Fr]) -> Result<Fr, CanonicalizationError> {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len())
        .map_err(|error| CanonicalizationError::Poseidon(error.to_string()))?;
    hasher
        .hash(inputs)
        .map_err(|error| CanonicalizationError::Poseidon(error.to_string()))
}

fn domain_poseidon(domain: u64, left: Fr, right: Fr) -> Result<Fr, CanonicalizationError> {
    let inner = poseidon(&[Fr::from(domain), left])?;
    poseidon(&[inner, right])
}

fn empty_document_merkle_root() -> Result<Fr, CanonicalizationError> {
    let mut root = Fr::from(0u64);
    for _ in 0..DOCUMENT_MERKLE_DEPTH {
        root = domain_poseidon(MERKLE_NODE_DOMAIN, root, root)?;
    }
    Ok(root)
}

fn enforce_empty_tree_invariant(public_signals: &[Fr]) -> Result<(), CanonicalizationError> {
    // Unified signal order:
    // [canonicalHash, merkleRoot, ledgerRoot, treeSize, ledgerKeyHash].
    if public_signals[3] == Fr::from(0u64) && public_signals[1] != empty_document_merkle_root()? {
        return Err(CanonicalizationError::EmptyTreeMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLAIM_HEX: &str = concat!(
        "4f4c5943414e3031",
        "000000000000002d",
        "000000000000001f",
        "293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c95354",
        "6711dafbab9471037d55b746ffc7c810af1d5d9f384972498431044f166ddfed",
        "0100000000000000"
    );

    #[test]
    fn pinned_journal_maps_to_javascript_commitment_vector() {
        let bytes = hex::decode(CLAIM_HEX).unwrap();
        let claim = decode_claim(&bytes).unwrap();

        assert_eq!(claim.source_len, 45);
        assert_eq!(claim.canonical_len, 31);
        assert_eq!(
            hex::encode(claim.source_commitment),
            "293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c95354"
        );
        assert_eq!(
            map_claim_to_canonical_hash(&claim).unwrap().to_string(),
            "16060508666336680773438919255447306219275442759648167530745041862815015424516"
        );
    }

    #[test]
    fn pinned_h2_empty_root_matches_javascript_vector() {
        let empty = empty_document_merkle_root().unwrap();
        assert_eq!(
            empty.to_string(),
            "15844545496281054012514088872996878997832991608828444956951187238677813598466"
        );

        let accepted = [
            Fr::from(1u64),
            empty,
            Fr::from(2u64),
            Fr::from(0u64),
            Fr::from(3u64),
        ];
        assert!(enforce_empty_tree_invariant(&accepted).is_ok());

        let mut rejected = accepted;
        rejected[1] = Fr::from(1u64);
        assert!(matches!(
            enforce_empty_tree_invariant(&rejected),
            Err(CanonicalizationError::EmptyTreeMismatch)
        ));
    }

    #[test]
    fn journal_decoder_rejects_noncanonical_structure() {
        let mut bytes = hex::decode(CLAIM_HEX).unwrap();
        bytes[88] = 2;
        assert!(matches!(
            decode_claim(&bytes),
            Err(CanonicalizationError::MalformedJournal(_))
        ));

        let mut bytes = hex::decode(CLAIM_HEX).unwrap();
        bytes[95] = 1;
        assert!(matches!(
            decode_claim(&bytes),
            Err(CanonicalizationError::MalformedJournal(_))
        ));

        let mut bytes = hex::decode(CLAIM_HEX).unwrap();
        bytes[8..16].copy_from_slice(&0u64.to_be_bytes());
        assert!(matches!(
            decode_claim(&bytes),
            Err(CanonicalizationError::MalformedJournal(_))
        ));
    }

    #[test]
    fn source_commitment_requires_lowercase_fixed_hex() {
        let expected = "293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c95354";
        assert_eq!(decode_source_commitment(expected).unwrap().len(), 32);
        assert!(matches!(
            decode_source_commitment(&expected.to_uppercase()),
            Err(CanonicalizationError::MalformedSourceCommitment)
        ));
        assert!(matches!(
            decode_source_commitment(&expected[..62]),
            Err(CanonicalizationError::MalformedSourceCommitment)
        ));
    }

    #[test]
    fn receipt_encoding_and_signal_count_are_strict() {
        assert_eq!(decode_canonical_base64("Zg==").unwrap(), b"f");
        assert!(matches!(
            decode_canonical_base64("Zg"),
            Err(CanonicalizationError::Base64(_))
        ));

        let four_signals = [Fr::from(0u64); 4];
        assert!(matches!(
            verify_receipt_binding("", &"0".repeat(64), &four_signals),
            Err(CanonicalizationError::PublicSignalCount(4))
        ));
    }

    #[test]
    fn committed_succinct_receipt_fixture_verifies_offline() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../proofs/zkvm/canonicalization/receipt-fixture.json"
        )))
        .unwrap();
        assert_eq!(
            fixture["format"].as_str(),
            Some("olympus-canonicalization-receipt-fixture")
        );
        assert_eq!(fixture["version"].as_u64(), Some(1));
        let expected_image_id = canonicalization_image_id().unwrap().to_string();
        assert_eq!(
            fixture["image_id"].as_str(),
            Some(expected_image_id.as_str())
        );

        let source = hex::decode(fixture["source_hex"].as_str().unwrap()).unwrap();
        let mut source_hasher = blake3::Hasher::new();
        source_hasher.update(b"OLY:CANONICAL-SOURCE:V1|");
        source_hasher.update(&(source.len() as u64).to_be_bytes());
        source_hasher.update(&source);
        let expected_source = source_hasher.finalize().to_hex().to_string();

        let journal = hex::decode(fixture["journal_hex"].as_str().unwrap()).unwrap();
        let claim = decode_claim(&journal).unwrap();
        assert_eq!(hex::encode(claim.source_commitment), expected_source);
        let canonical_hash = map_claim_to_canonical_hash(&claim).unwrap();
        let public_signals = [
            canonical_hash,
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(1u64),
            Fr::from(3u64),
        ];

        let verified = verify_receipt_binding(
            fixture["receipt"].as_str().unwrap(),
            &expected_source,
            &public_signals,
        )
        .unwrap();
        assert_eq!(verified.source_commitment, claim.source_commitment);
        assert_eq!(verified.canonical_hash, canonical_hash);
    }

    #[test]
    fn placeholder_guest_fails_closed() {
        if GUEST_ELF.starts_with(b"PLACEHOLDER") || GUEST_IMAGE_ID.starts_with("PLACEHOLDER") {
            assert!(matches!(
                canonicalization_image_id(),
                Err(CanonicalizationError::PlaceholderArtifact)
            ));
        }
    }

    #[test]
    fn pinned_image_id_encoding_is_canonical() {
        let zeros = "0".repeat(64);
        assert_eq!(decode_image_id_text(&zeros).unwrap(), Digest::ZERO);
        assert_eq!(
            decode_image_id_text(&format!("{zeros}\n")).unwrap(),
            Digest::ZERO
        );
        assert!(matches!(
            decode_image_id_text(&"A".repeat(64)),
            Err(CanonicalizationError::InvalidPinnedImageId(_))
        ));
        assert!(matches!(
            decode_image_id_text(&format!("{zeros}\r\n")),
            Err(CanonicalizationError::InvalidPinnedImageId(_))
        ));
    }
}
