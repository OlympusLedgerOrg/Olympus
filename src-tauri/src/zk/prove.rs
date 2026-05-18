//! Native Rust Groth16 prover for Olympus circuits.
//!
//! Pipeline (same for every circuit, only inputs differ):
//!
//!   1. Load circom-emitted `circuit.wasm` + `circuit.r1cs` via ark-circom
//!      (`CircomConfig`).  Witness generation runs in-process under wasmer.
//!   2. Push named inputs into `CircomBuilder`.
//!   3. `builder.build()` → `CircomCircuit` with the full witness in R1CS
//!      variable order, plus the public-inputs slice in snarkjs order
//!      (outputs first, then declared public inputs).
//!   4. Load arkworks-serialized proving key via `zkey::load_proving_key`.
//!   5. `ark-groth16::Groth16::<Bn254>::prove(pk, circuit, &mut rng)`.
//!
//! No Node.js, no snarkjs subprocess.  The `.wasm` + `.r1cs` + `.ark.zkey`
//! artifacts are produced at setup time by `proofs/setup_circuits.sh` and
//! aren't part of the runtime trust boundary — they're outputs of the
//! trusted-setup ceremony, which the verifier independently bounds by
//! checking against an embedded vkey fingerprint.

use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use num_bigint::BigInt;
use thiserror::Error;

use super::witness::{ExistenceWitness, NonExistenceWitness, RedactionWitness};
use super::zkey::{load_proving_key, ZkeyError};

#[derive(Debug, Error)]
pub enum ProveError {
    #[error("Witness pre-check failed: {0}")]
    WitnessInvalid(String),
    #[error("Failed to load CircomConfig from wasm={wasm}, r1cs={r1cs}: {source}")]
    CircomConfig {
        wasm: String,
        r1cs: String,
        #[source]
        source: color_eyre::Report,
    },
    #[error("Witness generation failed: {0}")]
    WitnessGen(color_eyre::Report),
    #[error("Zkey load error: {0}")]
    Zkey(#[from] ZkeyError),
    #[error("ark-groth16 prover error: {0}")]
    Ark(String),
    #[error("CircomCircuit produced no public inputs slot")]
    NoPublicInputs,
}

/// Run the shared prove pipeline. Generic over inputs so each circuit's
/// prover stays a thin three-line wrapper. The caller is responsible for
/// running circuit-specific pre-checks (e.g. Merkle-root re-derivation)
/// before invoking this helper.
fn prove_with_inputs(
    inputs: Vec<(String, Vec<BigInt>)>,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    // Step 1+2: build the circom configuration and push inputs.
    // CircomConfig is generic over the scalar field (`PrimeField`), not the
    // pairing engine — pass BN254's `Fr`, not `Bn254`.
    let cfg = CircomConfig::<Fr>::new(wasm_path, r1cs_path).map_err(|source| {
        ProveError::CircomConfig {
            wasm: wasm_path.display().to_string(),
            r1cs: r1cs_path.display().to_string(),
            source,
        }
    })?;
    let mut builder = CircomBuilder::new(cfg);
    for (name, values) in inputs {
        for v in values {
            builder.push_input(&name, v);
        }
    }

    // Step 3: run the WASM witness generator.
    let circuit = builder.build().map_err(ProveError::WitnessGen)?;
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or(ProveError::NoPublicInputs)?;

    // Step 4: load the arkworks-serialized proving key (cached).
    let pk = load_proving_key(zkey_path)?;

    // Step 5: Groth16 prove. The (r, s) randomness must be fresh per proof.
    let mut rng = rand::thread_rng();
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| ProveError::Ark(e.to_string()))?;

    Ok((proof, public_inputs))
}

/// Prove `document_existence` — Poseidon Merkle inclusion at a given index.
///
/// Public signal order returned: `[root, leafIndex, treeSize]`.
pub fn prove_existence(
    witness: &ExistenceWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    // Fast pre-check: re-derive the Merkle root from private inputs.
    witness
        .verify_merkle_root()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
}

/// Prove `non_existence` — SMT keyed non-membership.
///
/// Public signal order returned: `[root]`. The circuit declares no output
/// signals.
pub fn prove_non_existence(
    witness: &NonExistenceWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    witness
        .verify_merkle_root()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
}

/// Prove `redaction_validity` — selective disclosure with domain-3 commitment.
///
/// Public signal order returned: `[nullifier, originalRoot,
/// redactedCommitment, revealedCount]`.  The leading `nullifier` is a
/// circuit-output signal — in circom 2 outputs precede declared public
/// inputs in the snarkjs publicSignals vector.
pub fn prove_redaction(
    witness: &RedactionWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    witness
        .verify_all_paths()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;
    prove_with_inputs(witness.circom_inputs(), wasm_path, r1cs_path, zkey_path)
}
