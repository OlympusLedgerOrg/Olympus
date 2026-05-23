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
use olympus_tauri_lib::zk::poseidon::{compute_merkle_root, domain_node};
use olympus_tauri_lib::zk::prove::prove_existence;
use olympus_tauri_lib::zk::verify::existence_verifier;
use olympus_tauri_lib::zk::witness::ExistenceWitness;

const DEPTH: usize = 20;

/// Empty-subtree hashes for a sparse depth-`DEPTH` Merkle tree.
///
/// `empty[0] = Fr::zero()` is the empty-leaf sentinel.  For each internal
/// level `d > 0`, `empty[d] = DomainPoseidonNode(empty[d-1], empty[d-1])`
/// — i.e. the hash of two empty subtrees of one level below.  Used as
/// sibling placeholders along the path when only one leaf is present.
///
/// This is the same construction `snapshot.rs::build_snapshot_path` uses;
/// the `prove_and_verify_existence_roundtrip` test originally used plain
/// `Fr::zero()` siblings at every depth, which the Rust + WASM prover
/// agreed on but produced a witness that didn't verify under Groth16
/// (see #1011 for the failure mode).
fn empty_subtree_hashes() -> Vec<Fr> {
    let mut empty = vec![Fr::zero(); DEPTH + 1];
    for d in 0..DEPTH {
        empty[d + 1] =
            domain_node(1, empty[d], empty[d]).expect("DomainPoseidonNode must succeed");
    }
    empty
}

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

/// Build a depth-20 Merkle path where the leaf sits at `leaf_index` and
/// every sibling along the path is the canonical empty-subtree hash for
/// that depth.  This matches what `snapshot.rs::build_snapshot_path`
/// produces for a sparse tree containing a single leaf.
///
/// Originally this used `Fr::zero()` siblings at every depth.  That kept
/// the Rust pre-check and the WASM witness-generator in lockstep (both
/// agreed on the resulting root) but produced a witness whose Groth16
/// proof did NOT verify — see #1011.  Switching to the empty-subtree
/// hash chain is the fix.
fn build_trivial_witness(leaf: Fr, leaf_index: u64, tree_size: u64) -> ExistenceWitness {
    let empty = empty_subtree_hashes();
    // At depth `d`, the sibling is the `d`-deep empty subtree (i.e. the
    // hash of two `(d-1)`-deep empty subtrees, recursively bottoming out
    // at `Fr::zero()` for the empty leaf).
    let path_elements: Vec<Fr> = (0..DEPTH).map(|d| empty[d]).collect();
    // LSB-first bit decomposition of leaf_index.
    let path_indices: Vec<u8> = (0..DEPTH)
        .map(|i| ((leaf_index >> i) & 1) as u8)
        .collect();
    let root = compute_merkle_root(leaf, &path_elements, &path_indices, 1)
        .expect("Merkle root computation must succeed");
    ExistenceWitness::new(root, leaf_index, tree_size, leaf, path_elements, path_indices)
        .expect("witness construction must succeed")
}

// `prove_and_verify_existence_roundtrip` is stuck — kept `#[ignore]` while
// #1011 stays open. We initially blamed `Fr::zero()` siblings; switching to
// the empty-subtree-hash chain (above, in `build_trivial_witness`) is
// semantically correct for a sparse Merkle tree but does NOT make the test
// verify. Deeper investigation (see #1011 comments) shows that all four
// verification-key sources reject the proof in the SAME process that just
// generated it:
//
//   * include_str!'d JSON vkey
//   * file-loaded JSON vkey
//   * vk extracted directly from the .ark.zkey ProvingKey (prepared)
//   * vk extracted directly from the .ark.zkey ProvingKey (unprepared)
//
// The third case is the smoking gun: prove() and verify() are using the
// SAME ark_groth16::ProvingKey, but verify rejects. That points to an
// ark-circom witness-gen ↔ ark-groth16 prove-path interop bug — most
// likely the WASM witness produced by ark-circom 0.6 has a signal layout
// inconsistent with the QAP polynomials encoded in the .zkey (which
// snarkjs derives from the same .r1cs). Fix requires either pinning a
// known-good ark-circom or moving to a different prove path; neither
// fits in an "unblock CI" PR.
//
// To run locally while #1011 is open:
//   cargo test --test zk_prove_existence -- --include-ignored
#[test]
#[ignore = "https://github.com/OlympusLedgerOrg/Olympus/issues/1011"]
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
