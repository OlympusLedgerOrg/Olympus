//! Experimental crypto-agility signature envelopes (ADR-0035).
//!
//! The envelope is a sidecar around an already-computed 32-byte digest. It does
//! not change ledger roots, SMT leaves, checkpoint anchor hashes, redaction
//! table hashes, or any existing Ed25519/BJJ signature semantics.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::length_prefixed;

/// Wire schema tag for [`SignatureEnvelopeV3`].
///
/// v3 is a deliberate breaking change from v2: the suite identifier and the
/// ordered algorithm list are now inside the signed message. In v2 they were
/// not, so a hybrid envelope could be relabelled as classical and its PQ leg
/// stripped while the Ed25519 signature still verified (audit A-P2-1).
pub const SIGNATURE_ENVELOPE_V3_SCHEMA: &str = "olympus-signature-envelope/v3";

/// Domain prefix for the bytes signed by every envelope component.
pub const SIGNATURE_ENVELOPE_V3_PREFIX: &[u8] = b"OLY:SIGNATURE-ENVELOPE:V3";

/// Algorithm identifiers used in envelope components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    Ed25519,
    MlDsa65,
}

impl SignatureAlgorithm {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }
}

/// Suite identifiers. A suite defines which component algorithms may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureSuite {
    Ed25519,
    HybridEd25519MlDsa65,
}

impl SignatureSuite {
    /// Stable suite identifier bound into the signed message.
    ///
    /// Changing a spelling here is a wire-format change, exactly like changing
    /// an algorithm's [`SignatureAlgorithm::wire_name`].
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::HybridEd25519MlDsa65 => "hybrid-ed25519-ml-dsa-65",
        }
    }

    pub fn descriptor(self) -> SuiteDescriptor {
        match self {
            Self::Ed25519 => SuiteDescriptor {
                suite: self,
                algorithms: vec![SignatureAlgorithm::Ed25519],
                experimental: false,
            },
            Self::HybridEd25519MlDsa65 => SuiteDescriptor {
                suite: self,
                algorithms: vec![SignatureAlgorithm::Ed25519, SignatureAlgorithm::MlDsa65],
                experimental: true,
            },
        }
    }
}

/// Verification policy chosen by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerificationMode {
    /// Verify the classical Ed25519 leg. For a hybrid envelope this is an
    /// explicit downgrade by the *caller*; it is safe against relabelling
    /// because the suite is inside the signed message (v3), but it still does
    /// not verify the PQ leg.
    ClassicalRequired,
    /// Verify Ed25519 and require every advertised hybrid leg to be supported.
    /// ML-DSA verification is not implemented yet, so this currently fails
    /// closed with [`SignatureEnvelopeError::UnsupportedAlgorithm`].
    HybridRequired,
}

/// Human/auditor-readable suite metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuiteDescriptor {
    pub suite: SignatureSuite,
    pub algorithms: Vec<SignatureAlgorithm>,
    pub experimental: bool,
}

/// Non-empty protocol context for the payload digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSeparator(String);

impl DomainSeparator {
    pub fn new(value: impl Into<String>) -> Result<Self, SignatureEnvelopeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(SignatureEnvelopeError::EmptyDomainSeparator);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One algorithm leg inside an envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureComponent {
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Versioned signature sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureEnvelopeV3 {
    pub schema: String,
    pub suite: SignatureSuite,
    pub domain_separator: DomainSeparator,
    pub payload_digest: [u8; 32],
    pub signatures: Vec<SignatureComponent>,
}

/// Minimal result returned after successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    pub suite: SignatureSuite,
    pub domain_separator: DomainSeparator,
    pub payload_digest: [u8; 32],
    pub verified_algorithms: Vec<SignatureAlgorithm>,
    pub ed25519_public_key: [u8; 32],
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SignatureEnvelopeError {
    #[error("signature envelope domain separator must be non-empty")]
    EmptyDomainSeparator,
    #[error("unsupported signature envelope schema: {0}")]
    UnsupportedSchema(String),
    #[error("duplicate signature component for {0:?}")]
    DuplicateSignature(SignatureAlgorithm),
    #[error("missing signature component for {0:?}")]
    MissingSignature(SignatureAlgorithm),
    #[error("unexpected signature component {algorithm:?} for suite {suite:?}")]
    UnexpectedSignature {
        suite: SignatureSuite,
        algorithm: SignatureAlgorithm,
    },
    #[error("signature algorithm is not implemented in this build: {0:?}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    #[error("malformed public key for {algorithm:?}: expected {expected} bytes, got {actual}")]
    MalformedPublicKey {
        algorithm: SignatureAlgorithm,
        expected: usize,
        actual: usize,
    },
    #[error("malformed signature for {algorithm:?}: expected {expected} bytes, got {actual}")]
    MalformedSignature {
        algorithm: SignatureAlgorithm,
        expected: usize,
        actual: usize,
    },
    #[error("signature verification failed for {0:?}")]
    VerificationFailed(SignatureAlgorithm),
}

impl SignatureEnvelopeV3 {
    /// Build an Ed25519 envelope by signing the ADR-0035 envelope message.
    pub fn sign_ed25519(
        domain_separator: DomainSeparator,
        payload_digest: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let descriptor = SignatureSuite::Ed25519.descriptor();
        let message = signature_envelope_message(
            &domain_separator,
            &payload_digest,
            descriptor.suite,
            &descriptor.algorithms,
        );
        let signature = signing_key.sign(&message);
        Self {
            schema: SIGNATURE_ENVELOPE_V3_SCHEMA.to_owned(),
            suite: SignatureSuite::Ed25519,
            domain_separator,
            payload_digest,
            signatures: vec![SignatureComponent {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: signing_key.verifying_key().to_bytes().to_vec(),
                signature: signature.to_bytes().to_vec(),
            }],
        }
    }

    /// Verify according to the caller's policy.
    pub fn verify(
        &self,
        mode: SignatureVerificationMode,
    ) -> Result<VerifiedEnvelope, SignatureEnvelopeError> {
        self.validate_shape()?;
        let ed25519 = self.component(SignatureAlgorithm::Ed25519).ok_or(
            SignatureEnvelopeError::MissingSignature(SignatureAlgorithm::Ed25519),
        )?;

        // v3: the suite and its canonical algorithm list are part of the signed
        // message, so changing either after signing invalidates the Ed25519 leg.
        let descriptor = self.suite.descriptor();
        let message = signature_envelope_message(
            &self.domain_separator,
            &self.payload_digest,
            descriptor.suite,
            &descriptor.algorithms,
        );
        let ed25519_public_key = verify_ed25519_component(ed25519, &message)?;

        let mut verified_algorithms = vec![SignatureAlgorithm::Ed25519];
        if mode == SignatureVerificationMode::HybridRequired {
            let _ = self.component(SignatureAlgorithm::MlDsa65).ok_or(
                SignatureEnvelopeError::MissingSignature(SignatureAlgorithm::MlDsa65),
            )?;
            return Err(SignatureEnvelopeError::UnsupportedAlgorithm(
                SignatureAlgorithm::MlDsa65,
            ));
        }

        verified_algorithms.sort();
        Ok(VerifiedEnvelope {
            suite: self.suite,
            domain_separator: self.domain_separator.clone(),
            payload_digest: self.payload_digest,
            verified_algorithms,
            ed25519_public_key,
        })
    }

    fn validate_shape(&self) -> Result<(), SignatureEnvelopeError> {
        if self.schema != SIGNATURE_ENVELOPE_V3_SCHEMA {
            return Err(SignatureEnvelopeError::UnsupportedSchema(
                self.schema.clone(),
            ));
        }
        if self.domain_separator.as_str().is_empty() {
            return Err(SignatureEnvelopeError::EmptyDomainSeparator);
        }

        let descriptor = self.suite.descriptor();
        let allowed: BTreeSet<_> = descriptor.algorithms.iter().copied().collect();
        let mut seen = BTreeSet::new();
        for component in &self.signatures {
            if !allowed.contains(&component.algorithm) {
                return Err(SignatureEnvelopeError::UnexpectedSignature {
                    suite: self.suite,
                    algorithm: component.algorithm,
                });
            }
            if !seen.insert(component.algorithm) {
                return Err(SignatureEnvelopeError::DuplicateSignature(
                    component.algorithm,
                ));
            }
        }

        for algorithm in descriptor.algorithms {
            if !seen.contains(&algorithm) {
                return Err(SignatureEnvelopeError::MissingSignature(algorithm));
            }
        }
        Ok(())
    }

    fn component(&self, algorithm: SignatureAlgorithm) -> Option<&SignatureComponent> {
        self.signatures.iter().find(|c| c.algorithm == algorithm)
    }
}

/// Compute the exact bytes signed by every envelope component.
///
/// ```text
/// BLAKE3(
///   OLY:SIGNATURE-ENVELOPE:V3 ||
///   lp(domain_separator_utf8) ||
///   lp(payload_digest_32) ||
///   lp(suite_wire_name) ||
///   u32_be(algorithm_count) ||
///   for each algorithm in the suite's canonical order: lp(algorithm_wire_name)
/// )
/// ```
///
/// The algorithm list is the suite descriptor's order, not the order of the
/// serialized `signatures` array: components are a set, and a sender must not
/// be able to reorder JSON to change the digest.
pub fn signature_envelope_message(
    domain_separator: &DomainSeparator,
    payload_digest: &[u8; 32],
    suite: SignatureSuite,
    algorithms: &[SignatureAlgorithm],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SIGNATURE_ENVELOPE_V3_PREFIX);
    hasher.update(&length_prefixed(domain_separator.as_str().as_bytes()));
    hasher.update(&length_prefixed(payload_digest));
    hasher.update(&length_prefixed(suite.wire_name().as_bytes()));
    hasher.update(&(algorithms.len() as u32).to_be_bytes());
    for algorithm in algorithms {
        hasher.update(&length_prefixed(algorithm.wire_name().as_bytes()));
    }
    *hasher.finalize().as_bytes()
}

fn verify_ed25519_component(
    component: &SignatureComponent,
    message: &[u8; 32],
) -> Result<[u8; 32], SignatureEnvelopeError> {
    if component.public_key.len() != 32 {
        return Err(SignatureEnvelopeError::MalformedPublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            expected: 32,
            actual: component.public_key.len(),
        });
    }
    if component.signature.len() != 64 {
        return Err(SignatureEnvelopeError::MalformedSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            expected: 64,
            actual: component.signature.len(),
        });
    }

    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&component.public_key);
    let verifying_key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
        SignatureEnvelopeError::MalformedPublicKey {
            algorithm: SignatureAlgorithm::Ed25519,
            expected: 32,
            actual: component.public_key.len(),
        }
    })?;
    let signature = Signature::from_slice(&component.signature).map_err(|_| {
        SignatureEnvelopeError::MalformedSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            expected: 64,
            actual: component.signature.len(),
        }
    })?;

    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519))?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> DomainSeparator {
        DomainSeparator::new("OLY:TEST:SIGNATURE-ENVELOPE").unwrap()
    }

    /// Build an honestly-signed hybrid-shaped envelope for policy tests. No
    /// ML-DSA implementation exists, so the PQ component is opaque filler; the
    /// Ed25519 leg is real and signs the hybrid message (suite + both
    /// algorithms), which is what makes the shape tests meaningful.
    fn signed_hybrid_fixture(sk: &SigningKey, digest: [u8; 32]) -> SignatureEnvelopeV3 {
        let descriptor = SignatureSuite::HybridEd25519MlDsa65.descriptor();
        let message = signature_envelope_message(
            &domain(),
            &digest,
            descriptor.suite,
            &descriptor.algorithms,
        );
        SignatureEnvelopeV3 {
            schema: SIGNATURE_ENVELOPE_V3_SCHEMA.to_owned(),
            suite: SignatureSuite::HybridEd25519MlDsa65,
            domain_separator: domain(),
            payload_digest: digest,
            signatures: vec![
                SignatureComponent {
                    algorithm: SignatureAlgorithm::Ed25519,
                    public_key: sk.verifying_key().to_bytes().to_vec(),
                    signature: sk.sign(&message).to_bytes().to_vec(),
                },
                SignatureComponent {
                    algorithm: SignatureAlgorithm::MlDsa65,
                    public_key: vec![0x22; 1952],
                    signature: vec![0x33; 3309],
                },
            ],
        }
    }

    #[test]
    fn ed25519_envelope_roundtrips() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let digest = [0x11; 32];
        let envelope = SignatureEnvelopeV3::sign_ed25519(domain(), digest, &sk);

        let verified = envelope
            .verify(SignatureVerificationMode::ClassicalRequired)
            .unwrap();
        assert_eq!(verified.suite, SignatureSuite::Ed25519);
        assert_eq!(verified.payload_digest, digest);
        assert_eq!(
            verified.verified_algorithms,
            vec![SignatureAlgorithm::Ed25519]
        );
        assert_eq!(verified.ed25519_public_key, sk.verifying_key().to_bytes());
    }

    #[test]
    fn domain_separator_participates_in_signature_message() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let digest = [0x11; 32];
        let mut envelope = SignatureEnvelopeV3::sign_ed25519(domain(), digest, &sk);
        envelope.domain_separator = DomainSeparator::new("OLY:TEST:OTHER").unwrap();

        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519)
        );
    }

    #[test]
    fn relabelling_a_hybrid_envelope_as_classical_breaks_the_signature() {
        // Audit A-P2-1 regression. v2 signed only (domain, payload), so this
        // relabel + leg-strip verified. v3 binds the suite and algorithm list,
        // so the same edit must fail the Ed25519 leg even though the Ed25519
        // component itself is untouched.
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut envelope = signed_hybrid_fixture(&sk, [0x11; 32]);
        assert!(envelope
            .verify(SignatureVerificationMode::ClassicalRequired)
            .is_ok());

        envelope.suite = SignatureSuite::Ed25519;
        envelope
            .signatures
            .retain(|c| c.algorithm == SignatureAlgorithm::Ed25519);

        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519)
        );
    }

    #[test]
    fn adding_a_leg_after_signing_breaks_the_signature() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut envelope = SignatureEnvelopeV3::sign_ed25519(domain(), [0x11; 32], &sk);
        envelope.suite = SignatureSuite::HybridEd25519MlDsa65;
        envelope.signatures.push(SignatureComponent {
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key: vec![0x22; 1952],
            signature: vec![0x33; 3309],
        });

        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519)
        );
    }

    #[test]
    fn hybrid_suite_cannot_be_hybrid_verified_until_ml_dsa_exists() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let envelope = signed_hybrid_fixture(&sk, [0x11; 32]);

        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::HybridRequired)
                .unwrap_err(),
            SignatureEnvelopeError::UnsupportedAlgorithm(SignatureAlgorithm::MlDsa65)
        );
    }

    #[test]
    fn duplicate_components_are_rejected() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut envelope = SignatureEnvelopeV3::sign_ed25519(domain(), [0x11; 32], &sk);
        envelope.signatures.push(envelope.signatures[0].clone());

        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::DuplicateSignature(SignatureAlgorithm::Ed25519)
        );
    }

    #[test]
    fn signing_message_is_pinned() {
        let descriptor = SignatureSuite::Ed25519.descriptor();
        let message = signature_envelope_message(
            &domain(),
            &[0x11; 32],
            descriptor.suite,
            &descriptor.algorithms,
        );
        // Pinned so an accidental encoding change (field order, prefix,
        // algorithm list) cannot ship without a deliberate wire-format bump.
        assert_eq!(
            hex::encode(message),
            "c5d5fe6c528cb90e16d2ff7b0f062bdb4305fee78846d5f22414c28942e6f989"
        );
    }

    #[test]
    fn signature_message_binds_suite_and_algorithm_list() {
        let digest = [0x11; 32];
        let classical = signature_envelope_message(
            &domain(),
            &digest,
            SignatureSuite::Ed25519,
            &SignatureSuite::Ed25519.descriptor().algorithms,
        );
        let hybrid = signature_envelope_message(
            &domain(),
            &digest,
            SignatureSuite::HybridEd25519MlDsa65,
            &SignatureSuite::HybridEd25519MlDsa65.descriptor().algorithms,
        );
        assert_ne!(classical, hybrid, "suite must be inside the digest");

        // Same suite, different advertised leg set: also a different digest.
        let doctored = signature_envelope_message(
            &domain(),
            &digest,
            SignatureSuite::HybridEd25519MlDsa65,
            &[SignatureAlgorithm::Ed25519],
        );
        assert_ne!(hybrid, doctored, "algorithm list must be inside the digest");
    }

    #[test]
    fn algorithm_wire_names_and_suite_descriptors_are_pinned() {
        assert_eq!(SignatureAlgorithm::Ed25519.wire_name(), "ed25519");
        assert_eq!(SignatureAlgorithm::MlDsa65.wire_name(), "ml-dsa-65");
        assert_eq!(SignatureSuite::Ed25519.wire_name(), "ed25519");
        assert_eq!(
            SignatureSuite::HybridEd25519MlDsa65.wire_name(),
            "hybrid-ed25519-ml-dsa-65"
        );

        let classical = SignatureSuite::Ed25519.descriptor();
        assert_eq!(classical.suite, SignatureSuite::Ed25519);
        assert_eq!(classical.algorithms, vec![SignatureAlgorithm::Ed25519]);
        assert!(!classical.experimental);

        let hybrid = SignatureSuite::HybridEd25519MlDsa65.descriptor();
        assert_eq!(hybrid.suite, SignatureSuite::HybridEd25519MlDsa65);
        assert_eq!(
            hybrid.algorithms,
            vec![SignatureAlgorithm::Ed25519, SignatureAlgorithm::MlDsa65]
        );
        assert!(hybrid.experimental);
    }

    #[test]
    fn domain_separator_rejects_empty_and_exposes_original_value() {
        assert_eq!(
            DomainSeparator::new("").unwrap_err(),
            SignatureEnvelopeError::EmptyDomainSeparator
        );

        let separator = DomainSeparator::new("OLY:TEST:DOMAIN-AS-STR").unwrap();
        assert_eq!(separator.as_str(), "OLY:TEST:DOMAIN-AS-STR");
        assert_ne!(separator.as_str(), "");
        assert_ne!(separator.as_str(), "xyzzy");
    }

    #[test]
    fn signed_envelope_shape_and_component_errors_are_observable() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let mut envelope = SignatureEnvelopeV3::sign_ed25519(domain(), [0x11; 32], &sk);

        envelope.schema = "olympus-signature-envelope/v2".to_owned();
        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::UnsupportedSchema("olympus-signature-envelope/v2".to_owned())
        );

        let mut envelope = SignatureEnvelopeV3::sign_ed25519(domain(), [0x11; 32], &sk);
        envelope.signatures.clear();
        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::MissingSignature(SignatureAlgorithm::Ed25519)
        );

        let mut envelope = SignatureEnvelopeV3::sign_ed25519(domain(), [0x11; 32], &sk);
        envelope.signatures[0].algorithm = SignatureAlgorithm::MlDsa65;
        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::UnexpectedSignature {
                suite: SignatureSuite::Ed25519,
                algorithm: SignatureAlgorithm::MlDsa65,
            }
        );
    }

    #[test]
    fn ed25519_component_validation_checks_lengths_and_returns_real_key() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let digest = [0x11; 32];
        let envelope = SignatureEnvelopeV3::sign_ed25519(domain(), digest, &sk);
        let descriptor = envelope.suite.descriptor();
        let message = signature_envelope_message(
            &envelope.domain_separator,
            &digest,
            descriptor.suite,
            &descriptor.algorithms,
        );
        let component = &envelope.signatures[0];

        assert_eq!(
            verify_ed25519_component(component, &message).unwrap(),
            sk.verifying_key().to_bytes()
        );

        let mut malformed = component.clone();
        malformed.public_key.pop();
        assert_eq!(
            verify_ed25519_component(&malformed, &message).unwrap_err(),
            SignatureEnvelopeError::MalformedPublicKey {
                algorithm: SignatureAlgorithm::Ed25519,
                expected: 32,
                actual: 31,
            }
        );

        let mut malformed = component.clone();
        malformed.signature.pop();
        assert_eq!(
            verify_ed25519_component(&malformed, &message).unwrap_err(),
            SignatureEnvelopeError::MalformedSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                expected: 64,
                actual: 63,
            }
        );

        let mut tampered = component.clone();
        tampered.signature[0] ^= 0x80;
        assert_eq!(
            verify_ed25519_component(&tampered, &message).unwrap_err(),
            SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519)
        );
    }
}
