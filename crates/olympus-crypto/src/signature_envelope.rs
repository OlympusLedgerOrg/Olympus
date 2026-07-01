//! Experimental crypto-agility signature envelopes (ADR-0035).
//!
//! The envelope is a sidecar around an already-computed 32-byte digest. It does
//! not change ledger roots, SMT leaves, checkpoint anchor hashes, redaction
//! table hashes, or any existing Ed25519/BJJ signature semantics.

use std::collections::BTreeSet;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::length_prefixed;

/// Wire schema tag for [`SignatureEnvelopeV2`].
pub const SIGNATURE_ENVELOPE_V2_SCHEMA: &str = "olympus-signature-envelope/v2";

/// Domain prefix for the bytes signed by every envelope component.
pub const SIGNATURE_ENVELOPE_V2_PREFIX: &[u8] = b"OLY:SIGNATURE-ENVELOPE:V2";

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
    /// Verify the classical Ed25519 leg and ignore experimental sidecar legs.
    ClassicalRequired,
    /// Verify Ed25519 and require every advertised hybrid leg to be supported.
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
pub struct SignatureEnvelopeV2 {
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

impl SignatureEnvelopeV2 {
    /// Build an Ed25519 envelope by signing the ADR-0035 envelope message.
    pub fn sign_ed25519(
        domain_separator: DomainSeparator,
        payload_digest: [u8; 32],
        signing_key: &SigningKey,
    ) -> Self {
        let message = signature_envelope_message(&domain_separator, &payload_digest);
        let signature = signing_key.sign(&message);
        Self {
            schema: SIGNATURE_ENVELOPE_V2_SCHEMA.to_owned(),
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
        let ed25519_public_key = verify_ed25519_component(
            ed25519,
            &signature_envelope_message(&self.domain_separator, &self.payload_digest),
        )?;

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
        if self.schema != SIGNATURE_ENVELOPE_V2_SCHEMA {
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
///   OLY:SIGNATURE-ENVELOPE:V2 ||
///   lp(domain_separator_utf8) ||
///   lp(payload_digest_32)
/// )
/// ```
pub fn signature_envelope_message(
    domain_separator: &DomainSeparator,
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SIGNATURE_ENVELOPE_V2_PREFIX);
    hasher.update(&length_prefixed(domain_separator.as_str().as_bytes()));
    hasher.update(&length_prefixed(payload_digest));
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
        .verify(message, &signature)
        .map_err(|_| SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519))?;
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domain() -> DomainSeparator {
        DomainSeparator::new("OLY:TEST:SIGNATURE-ENVELOPE").unwrap()
    }

    #[test]
    fn ed25519_envelope_roundtrips() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let digest = [0x11; 32];
        let envelope = SignatureEnvelopeV2::sign_ed25519(domain(), digest, &sk);

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
        let mut envelope = SignatureEnvelopeV2::sign_ed25519(domain(), digest, &sk);
        envelope.domain_separator = DomainSeparator::new("OLY:TEST:OTHER").unwrap();

        assert_eq!(
            envelope
                .verify(SignatureVerificationMode::ClassicalRequired)
                .unwrap_err(),
            SignatureEnvelopeError::VerificationFailed(SignatureAlgorithm::Ed25519)
        );
    }

    #[test]
    fn hybrid_suite_can_be_classically_checked_but_not_hybrid_checked_yet() {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let digest = [0x11; 32];
        let mut envelope = SignatureEnvelopeV2::sign_ed25519(domain(), digest, &sk);
        envelope.suite = SignatureSuite::HybridEd25519MlDsa65;
        envelope.signatures.push(SignatureComponent {
            algorithm: SignatureAlgorithm::MlDsa65,
            public_key: vec![0x22; 1952],
            signature: vec![0x33; 3309],
        });

        assert!(envelope
            .verify(SignatureVerificationMode::ClassicalRequired)
            .is_ok());
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
        let mut envelope = SignatureEnvelopeV2::sign_ed25519(domain(), [0x11; 32], &sk);
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
        let digest = [0x11; 32];
        let message = signature_envelope_message(&domain(), &digest);
        assert_eq!(
            hex::encode(message),
            "69c894aefcd729ae67ba5cb83b5d9656d4026b4c8adcfb31f9221112837886d0"
        );
    }
}
