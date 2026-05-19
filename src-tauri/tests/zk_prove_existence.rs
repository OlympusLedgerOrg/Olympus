//! Round-trip test for the native Rust Groth16 prover.
//!
//! Builds a small Poseidon Merkle tree, generates a `document_existence`
//! proof entirely in Rust (no Node.js subprocess, no snarkjs), then verifies
//! it with the existing `CircuitVerifier`.
//!
//! Requires build artifacts produced by `bash proofs/setup_circuits.sh`:
//!   * proofs/build/document_existence_js/document_existence.wasm
//!   * proofs/build/document_existence.r1cs
//!   * proofs/build/document_existence_final.ark.zkey
//!
//! If any of these are missing the test prints a clear instruction and exits
//! cleanly — proving needs ceremony artifacts that aren't checked in.
//!
//! Run with:
//!   cargo test -p olympus-tauri --test zk_prove_existence -- --nocapture

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_ff::Zero;
use olympus_tauri_lib::zk::poseidon::compute_merkle_root;
use olympus_tauri_lib::zk::prove::prove_existence;
use olympus_tauri_lib::zk::verify::existence_verifier;
use olympus_tauri_lib::zk::witness::ExistenceWitness;

const DEPTH: usize = 20;

fn build_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is `src-tauri/`, so `../proofs/build` is the snarkjs
    // output directory.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("build")
}

fn artifacts_present(build: &PathBuf) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let wasm = build
        .join("document_existence_js")
        .join("document_existence.wasm");
    let r1cs = build.join("document_existence.r1cs");
    let ark_zkey = build.join("document_existence_final.ark.zkey");
    if wasm.is_file() && r1cs.is_file() && ark_zkey.is_file() {
        Some((wasm, r1cs, ark_zkey))
    } else {
        None
    }
}

/// Build a depth-20 Merkle tree where only one position is occupied; all
/// sibling slots up the path are the empty-leaf sentinel (Fr::zero()). This
/// is sufficient because the prover only needs to demonstrate a path —
/// production usage will pass real siblings drawn from `smt_nodes`.
fn build_trivial_witness(leaf: Fr, leaf_index: u64, tree_size: u64) -> ExistenceWitness {
    let path_elements: Vec<Fr> = (0..DEPTH).map(|_| Fr::zero()).collect();
    // LSB-first bit decomposition of leaf_index.
    let path_indices: Vec<u8> = (0..DEPTH)
        .map(|i| ((leaf_index >> i) & 1) as u8)
        .collect();
    let root = compute_merkle_root(leaf, &path_elements, &path_indices, 1)
        .expect("Merkle root computation must succeed");
    ExistenceWitness::new(root, leaf_index, tree_size, leaf, path_elements, path_indices)
        .expect("witness construction must succeed")
}

#[test]
fn prove_and_verify_existence_roundtrip() {
    let build = build_dir();
    let Some((wasm, r1cs, ark_zkey)) = artifacts_present(&build) else {
        eprintln!(
            "[skip] Required artifacts missing under {}.\n\
             Run `bash proofs/setup_circuits.sh` to generate them, then run\n\
             `cargo run --release --bin export_ark_zkey -- \\\n\
                proofs/build/document_existence_final.zkey \\\n\
                proofs/build/document_existence_final.ark.zkey`",
            build.display()
        );
        return;
    };

    let witness = build_trivial_witness(Fr::from(42u64), 1, 4);

    let (proof, public_inputs) =
        prove_existence(&witness, &wasm, &r1cs, &ark_zkey).expect("prove should succeed");

    // Sanity: the public inputs ark-circom emits should match what
    // ExistenceWitness::public_signals() reports.
    assert_eq!(
        public_inputs,
        witness.public_signals(),
        "ark-circom public inputs must match the declared public-signal order"
    );

    let verifier = existence_verifier().expect("existence verifier init");
    let valid = verifier
        .verify_proof(&proof, &public_inputs)
        .expect("verify call");
    assert!(valid, "round-trip proof should verify");
}

#[test]
fn tampered_public_inputs_fail_verification() {
    let build = build_dir();
    let Some((wasm, r1cs, ark_zkey)) = artifacts_present(&build) else {
        eprintln!("[skip] artifacts missing (see prove_and_verify_existence_roundtrip)");
        return;
    };

    let witness = build_trivial_witness(Fr::from(7u64), 2, 8);
    let (proof, mut public_inputs) = prove_existence(&witness, &wasm, &r1cs, &ark_zkey)
        .expect("prove should succeed");

    // Flip tree_size to a value the proof wasn't generated for.
    public_inputs[2] = Fr::from(9999u64);

    let verifier = existence_verifier().expect("existence verifier init");
    let valid = verifier
        .verify_proof(&proof, &public_inputs)
        .expect("verify call");
    assert!(
        !valid,
        "proof must NOT verify under tampered public inputs"
    );
}
