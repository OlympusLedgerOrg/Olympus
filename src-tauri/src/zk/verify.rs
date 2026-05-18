//! Thin wrapper around `ark-groth16` verification.
//!
//! Loads vkey once (cached in `OnceLock`) and verifies proofs without any
//! Node.js subprocess or JSON-IPC round-trip.

use std::path::Path;
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, VerifyingKey};
use ark_snark::SNARK;
use thiserror::Error;

use super::proof::{parse_proof_json, ProofError};
use super::vkey::{load_vkey, VkeyError};

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("Vkey load error: {0}")]
    Vkey(#[from] VkeyError),
    #[error("Proof parse error: {0}")]
    Proof(#[from] ProofError),
    #[error("Groth16 verification failed (proof is invalid)")]
    Invalid,
    #[error("Groth16 verifier error: {0}")]
    Ark(String),
}

/// A prepared (preprocessed) verifying key for one circuit.
pub struct CircuitVerifier {
    pvk: PreparedVerifyingKey<Bn254>,
}

impl CircuitVerifier {
    /// Load from a snarkjs vkey JSON file and preprocess.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, VerifyError> {
        let vk = load_vkey(path)?;
        Ok(Self { pvk: prepare_verifying_key(&vk) })
    }

    /// Load from an embedded JSON string (e.g. `include_str!(...)`).
    pub fn from_json(json: &str) -> Result<Self, VerifyError> {
        let vk = super::vkey::parse_vkey_json(json)?;
        Ok(Self { pvk: prepare_verifying_key(&vk) })
    }

    /// Verify a snarkjs Groth16 proof JSON against a slice of public signals.
    ///
    /// `proof_json` — the `proof` object from snarkjs (not the full prove output).
    /// `public_signals` — Fr elements in the same order as the circuit's public inputs.
    pub fn verify(&self, proof_json: &str, public_signals: &[Fr]) -> Result<bool, VerifyError> {
        let proof = parse_proof_json(proof_json)?;
        Groth16::<Bn254>::verify_with_processed_vk(&self.pvk, public_signals, &proof)
            .map_err(|e| VerifyError::Ark(e.to_string()))
    }
}

// ── Embedded verification keys ─────────────────────────────────────────────────
// Keys are embedded at compile time so the release binary needs no external files.

static EXISTENCE_VERIFIER: OnceLock<CircuitVerifier> = OnceLock::new();
static NON_EXISTENCE_VERIFIER: OnceLock<CircuitVerifier> = OnceLock::new();
static REDACTION_VERIFIER: OnceLock<CircuitVerifier> = OnceLock::new();

const EXISTENCE_VKEY_JSON: &str =
    include_str!("../../../proofs/keys/verification_keys/document_existence_vkey.json");
const NON_EXISTENCE_VKEY_JSON: &str =
    include_str!("../../../proofs/keys/verification_keys/non_existence_vkey.json");
const REDACTION_VKEY_JSON: &str =
    include_str!("../../../proofs/keys/verification_keys/redaction_validity_vkey.json");

pub fn existence_verifier() -> Result<&'static CircuitVerifier, VerifyError> {
    EXISTENCE_VERIFIER.get_or_try_init(|| CircuitVerifier::from_json(EXISTENCE_VKEY_JSON))
}

pub fn non_existence_verifier() -> Result<&'static CircuitVerifier, VerifyError> {
    NON_EXISTENCE_VERIFIER.get_or_try_init(|| CircuitVerifier::from_json(NON_EXISTENCE_VKEY_JSON))
}

pub fn redaction_verifier() -> Result<&'static CircuitVerifier, VerifyError> {
    REDACTION_VERIFIER.get_or_try_init(|| CircuitVerifier::from_json(REDACTION_VKEY_JSON))
}
