//! Round-trip test scaffold for the `unified` circuit.
//!
//! Marked `#[ignore]` because Round 3 ships the prover plumbing but not
//! a working Baby Jubjub EdDSA-Poseidon signer in pure Rust.  See
//! `src-tauri/src/zk/witness/baby_jubjub.rs` for the rationale.  To run
//! this test:
//!
//!   1. Run `bash proofs/setup_circuits.sh` to produce the unified
//!      .wasm / .r1cs / .ark.zkey + the vkey JSON.
//!   2. Supply a valid `(authority_pubkey, signature)` pair — either by
//!      implementing `baby_jubjub::sign()` (the Round 3 follow-up) or
//!      by capturing one from circomlib's JS reference signer for a
//!      fixed test message.
//!   3. Construct the rest of the `UnifiedWitness` (document sections,
//!      Merkle path, SMT path) so the in-circuit constraints hold.
//!   4. `cargo test -p olympus-tauri --test zk_prove_unified -- --ignored --nocapture`
//!
//! The vkey is loaded from disk at runtime (`CircuitVerifier::from_file`)
//! because the unified vkey JSON isn't yet embedded in `verify.rs` —
//! adding it requires the file to exist at compile time, which only
//! happens after the trusted-setup ceremony has been run.

use std::path::PathBuf;

use olympus_tauri_lib::zk::verify::CircuitVerifier;

fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("build")
}

fn vkey_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("keys")
        .join("verification_keys")
        .join("unified_canonicalization_inclusion_root_sign_vkey.json")
}

fn artifacts() -> Option<(PathBuf, PathBuf, PathBuf, PathBuf)> {
    let build = build_dir();
    let stem = "unified_canonicalization_inclusion_root_sign";
    let wasm = build.join(format!("{stem}_js")).join(format!("{stem}.wasm"));
    let r1cs = build.join(format!("{stem}.r1cs"));
    let ark_zkey = build.join(format!("{stem}_final.ark.zkey"));
    let vkey = vkey_path();
    if wasm.is_file() && r1cs.is_file() && ark_zkey.is_file() && vkey.is_file() {
        Some((wasm, r1cs, ark_zkey, vkey))
    } else {
        None
    }
}

#[test]
#[ignore = "needs a Baby Jubjub EdDSA-Poseidon signature; see module docs"]
fn prove_and_verify_unified_roundtrip() {
    let Some((_wasm, _r1cs, _ark_zkey, vkey)) = artifacts() else {
        eprintln!("[skip] unified artifacts missing — run `bash proofs/setup_circuits.sh` first");
        return;
    };

    // Smoke-check that we can at least load the verifier from disk. This
    // tells the developer that the vkey is well-formed and parseable
    // before they go produce a signature + run the full proof.
    let _verifier = CircuitVerifier::from_file(&vkey)
        .expect("vkey JSON should parse once the file exists");

    // To complete this test:
    //   * Implement baby_jubjub::sign() OR import a snarkjs-generated
    //     signature for a known message.
    //   * Build an UnifiedWitness whose canonicalHash / merkleRoot /
    //     ledgerRoot are consistent with the private path inputs.
    //   * Call `prove_unified(...)`, then
    //     `verifier.verify_proof(&proof, &public_inputs)` and assert true.
    panic!(
        "TODO(round-3-followup): finish unified prover round-trip — \
         needs Baby Jubjub EdDSA-Poseidon signer (see \
         src-tauri/src/zk/witness/baby_jubjub.rs)."
    );
}
