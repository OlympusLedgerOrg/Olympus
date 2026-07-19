// SPDX-License-Identifier: Apache-2.0

//! Composition boundary between the canonicalization zkVM receipt and the
//! existing unified Groth16 section/inclusion proof.
//!
//! Receipt verification happens first. Only a journal authenticated by the
//! pinned guest image is decoded, mapped into the circuit's eight section
//! fields, and compared with Groth16 public signal 0.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use olympus_crypto::canonical_proof::{
    CanonicalClaimError, CanonicalizationClaim, MAX_CANONICALIZATION_USER_CYCLES,
    MAX_CANONICAL_RECEIPT_BYTES,
};
use risc0_zkvm::{compute_image_id, sha::Digest, InnerReceipt, Receipt, VerifierContext};
use thiserror::Error;

use super::poseidon::{hash2, hash_n, PoseidonError};
use super::witness::unified::MAX_SECTIONS;

const COMMITMENT_DOMAIN: u64 = 3;
const MAX_RECEIPT_BASE64_BYTES: usize = MAX_CANONICAL_RECEIPT_BYTES.div_ceil(3) * 4;
const GUEST_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proofs/zkvm/canonicalization/olympus_canonicalization_guest.elf"
));
const GUEST_IMAGE_ID: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../proofs/zkvm/canonicalization/olympus_canonicalization_guest.id"
));

/// Construct the complete default verifier parameter set without consulting
/// `RISC0_DEV_MODE`. RISC Zero's `VerifierContext::default()` intentionally
/// panics when that variable conflicts with `disable-dev-mode`; an ambient
/// process setting must produce a normal fail-closed API result, not unwind a
/// request worker.
fn strict_verifier_context() -> VerifierContext {
    VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_segment_verifier_parameters(Default::default())
        .with_succinct_verifier_parameters(Default::default())
        .with_groth16_verifier_parameters(Default::default())
}

#[derive(Debug, Error)]
pub enum CanonicalizationReceiptError {
    #[error("canonicalization guest artifact is a placeholder; build the pinned RISC Zero guest")]
    PlaceholderArtifact,
    #[error("canonicalization guest image is invalid: {0}")]
    InvalidGuestImage(String),
    #[error("canonicalization guest image ID does not match its pinned release ID")]
    GuestImageIdMismatch,
    #[error("canonicalization receipt exceeds the {MAX_CANONICAL_RECEIPT_BYTES}-byte limit")]
    ReceiptTooLarge,
    #[error("canonicalization receipt is not canonical base64: {0}")]
    Base64(String),
    #[error("canonicalization receipt JSON is invalid: {0}")]
    ReceiptJson(String),
    #[error("canonicalization receipt must use the succinct proof format")]
    UnsupportedReceiptKind,
    #[error("canonicalization receipt verification failed: {0}")]
    Verification(String),
    #[error("canonicalization journal is invalid: {0}")]
    Journal(#[from] CanonicalClaimError),
    #[error("canonicalization section commitment failed: {0}")]
    Poseidon(#[from] PoseidonError),
    #[error("canonicalization receipt commitment does not match Groth16 canonicalHash")]
    CommitmentMismatch,
    #[cfg(feature = "zkvm-prover")]
    #[error("canonicalization proving failed: {0}")]
    Proving(String),
}

/// Journal material after deterministic mapping to the unified circuit inputs.
#[derive(Clone, Debug)]
pub struct VerifiedCanonicalization {
    pub claim: CanonicalizationClaim,
    pub canonical_hash: Fr,
    pub document_sections: [Fr; MAX_SECTIONS],
    pub section_hashes: [Fr; MAX_SECTIONS],
}

/// Compute the image ID from the exact committed guest ELF.
pub fn canonicalization_image_id() -> Result<Digest, CanonicalizationReceiptError> {
    static IMAGE_ID: OnceLock<Result<Digest, String>> = OnceLock::new();
    let expected = GUEST_IMAGE_ID.strip_suffix('\n').unwrap_or(GUEST_IMAGE_ID);
    if GUEST_ELF.starts_with(b"PLACEHOLDER") || GUEST_IMAGE_ID.starts_with("PLACEHOLDER") {
        return Err(CanonicalizationReceiptError::PlaceholderArtifact);
    }
    let computed = IMAGE_ID
        .get_or_init(|| compute_image_id(GUEST_ELF).map_err(|error| error.to_string()))
        .clone()
        .map_err(CanonicalizationReceiptError::InvalidGuestImage)?;
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || computed.to_string() != expected
    {
        return Err(CanonicalizationReceiptError::GuestImageIdMismatch);
    }
    Ok(computed)
}

/// Verify an untrusted base64(JSON(Receipt)) and derive its Groth16 binding.
pub fn verify_receipt_base64(
    encoded: &str,
) -> Result<VerifiedCanonicalization, CanonicalizationReceiptError> {
    if encoded.len() > MAX_RECEIPT_BASE64_BYTES {
        return Err(CanonicalizationReceiptError::ReceiptTooLarge);
    }
    let receipt_bytes = BASE64
        .decode(encoded)
        .map_err(|error| CanonicalizationReceiptError::Base64(error.to_string()))?;
    if receipt_bytes.len() > MAX_CANONICAL_RECEIPT_BYTES {
        return Err(CanonicalizationReceiptError::ReceiptTooLarge);
    }
    if BASE64.encode(&receipt_bytes) != encoded {
        return Err(CanonicalizationReceiptError::Base64(
            "non-canonical encoding".to_owned(),
        ));
    }
    let receipt: Receipt = serde_json::from_slice(&receipt_bytes)
        .map_err(|error| CanonicalizationReceiptError::ReceiptJson(error.to_string()))?;
    if !matches!(&receipt.inner, InnerReceipt::Succinct(_)) {
        return Err(CanonicalizationReceiptError::UnsupportedReceiptKind);
    }
    receipt
        .verify_with_context(&strict_verifier_context(), canonicalization_image_id()?)
        .map_err(|error| CanonicalizationReceiptError::Verification(error.to_string()))?;
    verified_from_claim(CanonicalizationClaim::decode(&receipt.journal.bytes)?).map_err(Into::into)
}

/// Bind a verified receipt to public signal 0 of the unified Groth16 proof.
pub fn verify_receipt_binding(
    encoded: &str,
    groth16_canonical_hash: Fr,
) -> Result<VerifiedCanonicalization, CanonicalizationReceiptError> {
    let verified = verify_receipt_base64(encoded)?;
    if verified.canonical_hash != groth16_canonical_hash {
        return Err(CanonicalizationReceiptError::CommitmentMismatch);
    }
    Ok(verified)
}

/// Deterministically map a claim to the circuit witness/public commitment.
///
/// This function does not authenticate the claim. Callers handling untrusted
/// receipts must call [`verify_receipt_base64`] or [`verify_receipt_binding`].
pub fn verified_from_claim(
    claim: CanonicalizationClaim,
) -> Result<VerifiedCanonicalization, PoseidonError> {
    let mut document_sections = [Fr::from(0u64); MAX_SECTIONS];
    document_sections[0] = Fr::from_be_bytes_mod_order(&claim.canonical_digest);
    let mut section_hashes = [Fr::from(0u64); MAX_SECTIONS];
    for index in 0..MAX_SECTIONS {
        section_hashes[index] = hash_n(&[document_sections[index]])?;
    }

    let mut section_lengths = [0u32; MAX_SECTIONS];
    section_lengths[0] = claim.canonical_len as u32;
    let mut canonical_hash = Fr::from(1u64);
    for index in 0..MAX_SECTIONS {
        canonical_hash =
            domain_commitment(canonical_hash, Fr::from(section_lengths[index] as u64))?;
        canonical_hash = domain_commitment(canonical_hash, section_hashes[index])?;
    }

    Ok(VerifiedCanonicalization {
        claim,
        canonical_hash,
        document_sections,
        section_hashes,
    })
}

fn domain_commitment(left: Fr, right: Fr) -> Result<Fr, PoseidonError> {
    hash2(hash2(Fr::from(COMMITMENT_DOMAIN), left)?, right)
}

#[cfg(feature = "zkvm-prover")]
pub fn prove_source_base64(
    source: &[u8],
) -> Result<(String, VerifiedCanonicalization), CanonicalizationReceiptError> {
    use risc0_zkvm::{ExecutorEnv, LocalProver, Prover as _, ProverOpts};

    let mut env_builder = ExecutorEnv::builder();
    env_builder
        .write(&source.to_vec())
        .map_err(|error| CanonicalizationReceiptError::Proving(error.to_string()))?
        .session_limit(Some(MAX_CANONICALIZATION_USER_CYCLES));
    let env = env_builder
        .build()
        .map_err(|error| CanonicalizationReceiptError::Proving(error.to_string()))?;
    // Never use `default_prover`: it may select Bonsai from ambient
    // configuration and silently transmit the private source document.
    // Check the exact truthy values used by RISC Zero before constructing
    // `ProverOpts`: with `disable-dev-mode`, its constructor panics when this
    // variable is enabled, and Olympus's global panic hook performs database
    // cleanup even when the unwind is caught below.
    if std::env::var("RISC0_DEV_MODE")
        .ok()
        .is_some_and(|value| matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
    {
        return Err(CanonicalizationReceiptError::Proving(
            "RISC0_DEV_MODE must be unset when disable-dev-mode is enabled".to_owned(),
        ));
    }
    let opts = std::panic::catch_unwind(ProverOpts::succinct).map_err(|_| {
        CanonicalizationReceiptError::Proving(
            "RISC0_DEV_MODE must be unset when disable-dev-mode is enabled".to_owned(),
        )
    })?;
    let receipt = LocalProver::new("olympus-canonicalization-local")
        .prove_with_ctx(env, &strict_verifier_context(), GUEST_ELF, &opts)
        .map_err(|error| CanonicalizationReceiptError::Proving(error.to_string()))?
        .receipt;
    if !matches!(&receipt.inner, InnerReceipt::Succinct(_)) {
        return Err(CanonicalizationReceiptError::UnsupportedReceiptKind);
    }
    receipt
        .verify_with_context(&strict_verifier_context(), canonicalization_image_id()?)
        .map_err(|error| CanonicalizationReceiptError::Verification(error.to_string()))?;
    let verified = verified_from_claim(CanonicalizationClaim::decode(&receipt.journal.bytes)?)?;
    let receipt_json = serde_json::to_vec(&receipt)
        .map_err(|error| CanonicalizationReceiptError::ReceiptJson(error.to_string()))?;
    if receipt_json.len() > MAX_CANONICAL_RECEIPT_BYTES {
        return Err(CanonicalizationReceiptError::ReceiptTooLarge);
    }
    Ok((BASE64.encode(receipt_json), verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use olympus_crypto::canonical_proof::canonicalization_claim;

    #[test]
    fn one_section_mapping_matches_pinned_cross_language_vector() {
        let source = br#"{ "z":1.2300e+3, "name":"e\u0301", "a":true }"#;
        let claim = canonicalization_claim(source).unwrap();
        let mapped = verified_from_claim(claim.clone()).unwrap();

        assert_eq!(source.len(), 45);
        assert_eq!(claim.canonical_len, 31);
        assert_eq!(
            hex::encode(claim.source_commitment),
            "293b0323fbf994db8e9e206fbe4af7dfba0ad3cbab75b11c309f0a0652c95354"
        );
        assert_eq!(
            hex::encode(claim.canonical_digest),
            "6711dafbab9471037d55b746ffc7c810af1d5d9f384972498431044f166ddfed"
        );
        assert_eq!(
            crate::zk::proof::fr_to_decimal(&mapped.document_sections[0]),
            "2843285426218801039126413362237709188942333282709174045646915685276099403755"
        );
        assert_eq!(
            crate::zk::proof::fr_to_decimal(&mapped.section_hashes[0]),
            "20570190442019205935249310860091264872778035361568852590402287847159887948761"
        );
        assert_eq!(
            crate::zk::proof::fr_to_decimal(&mapped.section_hashes[1]),
            "19014214495641488759237505126948346942972912379615652741039992445865937985820"
        );
        assert_eq!(
            crate::zk::proof::fr_to_decimal(&mapped.canonical_hash),
            "16060508666336680773438919255447306219275442759648167530745041862815015424516"
        );
    }

    #[test]
    fn placeholder_guest_fails_closed() {
        if GUEST_ELF.starts_with(b"PLACEHOLDER") {
            assert!(matches!(
                canonicalization_image_id(),
                Err(CanonicalizationReceiptError::PlaceholderArtifact)
            ));
        }
    }

    #[test]
    fn malformed_base64_is_rejected_before_receipt_parsing() {
        assert!(matches!(
            verify_receipt_base64("%%%"),
            Err(CanonicalizationReceiptError::Base64(_))
        ));
    }

    #[test]
    fn committed_succinct_receipt_fixture_verifies() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../proofs/zkvm/canonicalization/receipt-fixture.json"
        )))
        .unwrap();
        assert_eq!(
            fixture["format"].as_str(),
            Some("olympus-canonicalization-receipt-fixture")
        );
        assert_eq!(fixture["version"].as_u64(), Some(1));

        let source = hex::decode(fixture["source_hex"].as_str().unwrap()).unwrap();
        let claim = canonicalization_claim(&source).unwrap();
        let expected_journal = hex::encode(claim.encode());
        assert_eq!(
            fixture["journal_hex"].as_str(),
            Some(expected_journal.as_str())
        );
        let expected_image_id = canonicalization_image_id().unwrap().to_string();
        assert_eq!(
            fixture["image_id"].as_str(),
            Some(expected_image_id.as_str())
        );

        let verified = verify_receipt_base64(fixture["receipt"].as_str().unwrap()).unwrap();
        assert_eq!(verified.claim, claim);
    }

    #[test]
    fn verifier_context_is_explicitly_non_development() {
        assert!(!strict_verifier_context().dev_mode());
    }
}
