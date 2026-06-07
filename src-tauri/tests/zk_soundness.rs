//! Dynamic adversarial soundness tests for the in-process Groth16 verifier.
//!
//! The `zk_prove_*` round-trip tests confirm the *positive* path: an honest
//! witness yields a proof that verifies. These tests confirm the *negative*
//! path across every production circuit — that a genuinely-verifying proof is
//! rejected the moment any public input is perturbed, the proof itself is
//! tampered with, or the public-signal arity is wrong. Together they pin the
//! verifier's binding guarantee, the property a soundness bug would break.
//!
//! Each test builds a valid witness via the shared `zk_fixtures` module, proves
//! it with the in-process prover, then runs `run_full_battery`:
//!   1. baseline proof verifies (else the negatives would be vacuous),
//!   2. every single-signal `+1` perturbation is rejected,
//!   3. a structurally-forged proof (negated `A`) is rejected,
//!   4. wrong public-signal arity never verifies.
//!
//! Like the round-trip tests these gracefully skip when the ceremony artifacts
//! produced by `bash proofs/setup_circuits.sh` are absent.
//!
//! Run with:
//!   cargo test -p olympus-desktop --features prover,zk-test-utils \
//!       --test zk_soundness -- --nocapture

#![cfg(all(feature = "prover", feature = "zk-test-utils"))]

use ark_bn254::Fr;

use olympus_tauri_lib::zk::prove::{
    prove_existence, prove_non_existence, prove_redaction, prove_unified,
};
use olympus_tauri_lib::zk::verify::{
    existence_verifier, non_existence_verifier, redaction_verifier, CircuitVerifier,
};

mod zk_fixtures;
use zk_fixtures as fx;

#[test]
fn existence_proof_is_bound_to_its_public_inputs() {
    let Some((wasm, r1cs, ark_zkey)) = fx::artifacts("document_existence") else {
        eprintln!("[skip] document_existence artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    let witness = fx::existence_witness(Fr::from(42u64), 1, 4);
    let (proof, signals) =
        prove_existence(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_existence");
    let verifier = existence_verifier().expect("existence verifier");
    fx::run_full_battery(verifier, &proof, &signals);
}

#[test]
fn non_existence_proof_is_bound_to_its_public_inputs() {
    let Some((wasm, r1cs, ark_zkey)) = fx::artifacts("non_existence") else {
        eprintln!("[skip] non_existence artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    let witness = fx::non_existence_witness([0xaa; 32]);
    let (proof, signals) =
        prove_non_existence(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_non_existence");
    let verifier = non_existence_verifier().expect("non_existence verifier");
    fx::run_full_battery(verifier, &proof, &signals);
}

#[test]
fn redaction_proof_is_bound_to_its_public_inputs() {
    let Some((wasm, r1cs, ark_zkey)) = fx::artifacts("redaction_validity") else {
        eprintln!("[skip] redaction_validity artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    let witness = fx::redaction_witness();
    let (proof, signals) =
        prove_redaction(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_redaction");
    let verifier = redaction_verifier().expect("redaction verifier");
    fx::run_full_battery(verifier, &proof, &signals);
}

#[test]
fn unified_proof_is_bound_to_its_public_inputs() {
    let Some((wasm, r1cs, ark_zkey)) =
        fx::artifacts("unified_canonicalization_inclusion_root_sign")
    else {
        eprintln!("[skip] unified artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    // The unified vkey is ceremony-produced and gitignored until then; only run
    // when a real (non-placeholder) vkey is on disk.
    let Some(vkey_path) = fx::unified_vkey_path() else {
        eprintln!("[skip] unified vkey is a placeholder — run a trusted setup first");
        return;
    };
    let witness = fx::unified_witness();
    let (proof, signals) =
        prove_unified(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_unified");
    let verifier = CircuitVerifier::from_file(&vkey_path).expect("unified vkey parse");
    fx::run_full_battery(&verifier, &proof, &signals);
}
