//! Native Rust Groth16 prover for Olympus circuits.
//!
//! Round 1 supports only `document_existence`. The pipeline:
//!
//!   1. Load circom-emitted `circuit.wasm` via wasmtime (in-process).
//!   2. Push named inputs into `CircomBuilder`.
//!   3. Run the WASM witness generator → `CircomCircuit` with a full witness
//!      vector matching circom's R1CS variable numbering.
//!   4. Load arkworks-serialized proving key via `zkey::load_proving_key`.
//!   5. Call `ark-groth16::Groth16::create_random_proof_with_reduction`.
//!
//! No Node.js, no snarkjs subprocess — everything runs in this process. The
//! `.wasm` and `.ark.zkey` artifacts are produced at setup time by
//! `proofs/setup_circuits.sh` and are not part of the runtime trust boundary
//! (they're build outputs from the trusted-setup ceremony).

use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_circom::{CircomBuilder, CircomConfig};
use ark_groth16::{Groth16, Proof};
use ark_snark::SNARK;
use thiserror::Error;

use super::witness::ExistenceWitness;
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

/// Generate a Groth16 proof for the `document_existence` circuit.
///
/// `wasm_path`  — path to `document_existence.wasm` (circom's witness generator).
/// `r1cs_path`  — path to `document_existence.r1cs` (circuit constraint system).
/// `zkey_path`  — path to `document_existence_final.ark.zkey` (arkworks-serialized
///                proving key, produced by the `export_ark_zkey` binary).
///
/// Returns the `Proof<Bn254>` and the public inputs in circuit declaration
/// order (`[root, leafIndex, treeSize]`) — the latter is the slice you pass to
/// `CircuitVerifier::verify`.
///
/// The function is synchronous. Callers should wrap in `tokio::task::spawn_blocking`
/// when running under an async runtime: witness generation + proving takes
/// hundreds of milliseconds and would otherwise stall the executor.
pub fn prove_existence(
    witness: &ExistenceWitness,
    wasm_path: &Path,
    r1cs_path: &Path,
    zkey_path: &Path,
) -> Result<(Proof<Bn254>, Vec<Fr>), ProveError> {
    // Fast pre-check: re-derive the Merkle root from the private inputs and
    // confirm it matches the public root. Cheaper than a failed witness-gen.
    witness
        .verify_merkle_root()
        .map_err(|e| ProveError::WitnessInvalid(e.to_string()))?;

    // Step 1+2: build the circom configuration and push inputs.
    // CircomConfig is generic over the scalar field (PrimeField), not the
    // pairing engine — pass BN254's `Fr`, not `Bn254`.
    let cfg = CircomConfig::<Fr>::new(wasm_path, r1cs_path).map_err(|source| {
        ProveError::CircomConfig {
            wasm: wasm_path.display().to_string(),
            r1cs: r1cs_path.display().to_string(),
            source,
        }
    })?;
    let mut builder = CircomBuilder::new(cfg);
    for (name, values) in witness.circom_inputs() {
        for v in values {
            builder.push_input(&name, v);
        }
    }

    // Step 3: run the WASM witness generator.
    let circuit = builder.build().map_err(ProveError::WitnessGen)?;

    // Pull public inputs from the assembled circuit. `get_public_inputs`
    // returns the Vec<Fr> already reduced — these are exactly what the
    // verifier expects.
    let public_inputs = circuit
        .get_public_inputs()
        .ok_or(ProveError::NoPublicInputs)?;

    // Step 4: load the arkworks-serialized proving key (cached).
    let pk = load_proving_key(zkey_path)?;

    // Step 5: Groth16 prove. `create_random_proof_with_reduction` draws the
    // r/s randomness from `thread_rng` — that's the correct source for a
    // proving system that requires fresh, unpredictable scalars per proof.
    let mut rng = rand::thread_rng();
    let proof = Groth16::<Bn254>::prove(pk, circuit, &mut rng)
        .map_err(|e| ProveError::Ark(e.to_string()))?;

    Ok((proof, public_inputs))
}
