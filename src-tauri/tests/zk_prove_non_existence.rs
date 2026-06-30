//! Round-trip test for the native `non_existence` prover.
//!
//! Builds a sparse Merkle tree where the leaf at the path derived from a
//! known 32-byte key is the empty sentinel (Fr::zero()) and all siblings
//! up the path are zero (an empty SMT).  Proves non-membership of that
//! key, then verifies the proof entirely in Rust.
//!
//! Requires (from `bash proofs/setup_circuits.sh`):
//!   * proofs/build/non_existence_js/non_existence.wasm
//!   * proofs/build/non_existence.r1cs
//!   * proofs/build/non_existence_final.ark.zkey
//!
//! Run:  cargo test -p olympus-tauri --test zk_prove_non_existence -- --nocapture

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_ff::Zero;
use olympus_tauri_lib::zk::prove::prove_non_existence;
use olympus_tauri_lib::zk::verify::non_existence_verifier;
use olympus_tauri_lib::zk::witness::NonExistenceWitness;

const SMT_DEPTH: usize = 256;

fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("build")
}

fn artifacts(build: &std::path::Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let wasm = build.join("non_existence_js").join("non_existence.wasm");
    let r1cs = build.join("non_existence.r1cs");
    let ark_zkey = build.join("non_existence_final.ark.zkey");
    if wasm.is_file() && r1cs.is_file() && ark_zkey.is_file() {
        Some((wasm, r1cs, ark_zkey))
    } else {
        None
    }
}

#[test]
fn prove_and_verify_non_existence_roundtrip() {
    let build = build_dir();
    let Some((wasm, r1cs, ark_zkey)) = artifacts(&build) else {
        eprintln!(
            "[skip] non_existence artifacts missing under {}.\n\
             Run `bash proofs/setup_circuits.sh` first.",
            build.display()
        );
        return;
    };

    // Empty SMT: leaf=0 along the entire path, siblings=0 everywhere.
    // The root of an all-zero 256-level Poseidon SMT with NODE_DOMAIN is the
    // value the circuit derives — we just hand it the path elements and let
    // verify_merkle_root compute the expected root.
    let key: [u8; 32] = [0xaa; 32];
    let path_elements: Vec<Fr> = vec![Fr::zero(); SMT_DEPTH];

    // Compute the expected root using the witness's own helper so the
    // public input matches whatever Poseidon(NODE_DOMAIN) yields.
    let path_indices = {
        // Mirror NonExistenceWitness::path_indices() so we can compute the
        // root without needing a temporary witness.
        let mut idx = vec![0u8; SMT_DEPTH];
        for (b_idx, &byte) in key.iter().enumerate() {
            for bit_i in 0..8usize {
                let bit = (byte >> (7 - bit_i)) & 1;
                idx[255 - (b_idx * 8 + bit_i)] = bit;
            }
        }
        idx
    };
    let root = olympus_tauri_lib::zk::poseidon::compute_merkle_root(
        Fr::zero(),
        &path_elements,
        &path_indices,
        olympus_tauri_lib::zk::poseidon::NODE_DOMAIN,
    )
    .expect("root computation");

    let witness =
        NonExistenceWitness::new(root, key, path_elements.clone()).expect("witness construction");
    witness
        .verify_merkle_root()
        .expect("path must agree with declared root");

    let (proof, public_inputs) =
        prove_non_existence(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_non_existence");

    assert_eq!(public_inputs, witness.public_signals());

    let verifier = non_existence_verifier().expect("verifier init");
    let valid = verifier
        .verify_proof(&proof, &public_inputs)
        .expect("verify call");
    assert!(valid, "non_existence round-trip must verify");
}
