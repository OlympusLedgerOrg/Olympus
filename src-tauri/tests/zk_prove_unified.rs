//! Round-trip test scaffold for the `unified` circuit.
//!
//! Still marked `#[ignore]` — but the blocker has changed since Round 3
//! shipped.  The Baby Jubjub EdDSA-Poseidon signer now works (see the
//! unit tests in `src-tauri/src/zk/witness/baby_jubjub.rs`, which assert
//! end-to-end that iden3's own verifier accepts the signatures we
//! produce — and `EdDSAPoseidonVerifier` is exactly that verifier
//! lifted into the circuit).
//!
//! What's still needed to fully un-ignore this test:
//!
//!   1. **Build artifacts.**  Run `bash proofs/setup_circuits.sh` to
//!      produce the unified circuit's `.wasm`, `.r1cs`, `.ark.zkey`, and
//!      `_vkey.json`.  PTAU power ≥ 17 (the Hermez 2^20 default is fine).
//!   2. **Consistent fixtures.**  The `UnifiedWitness` has to be
//!      constructed so that:
//!        * `canonicalHash` matches the in-circuit canonicalization
//!          Poseidon chain over `documentSections` / `sectionCount` /
//!          `sectionLengths` / `sectionHashes`.
//!        * `merkleRoot` matches the in-circuit Merkle re-derivation
//!          over `merklePath` + `merkleIndices` from the leaf.
//!        * `ledgerRoot` matches the SMT re-derivation over
//!          `ledgerPathElements` + `ledgerPathIndices`.
//!      This is ~100 LOC of fixture construction (mirror what
//!      `protocol/poseidon_tree.py` / `protocol/ssmf.py` do) and is
//!      tracked as a Round 3 follow-up.
//!
//! Until step 2 is in, the test exercises what it can: deriving a
//! Baby Jubjub authority keypair and signing the checkpoint message —
//! the slice of the pipeline that doesn't depend on circuit-specific
//! fixture construction.  When you're ready to finish the round-trip,
//! drop the `#[ignore]`, fill in the witness, call `prove_unified`, and
//! verify against the vkey loaded from disk.

use std::path::PathBuf;

use ark_bn254::Fr;
use olympus_tauri_lib::zk::poseidon::hash2;
use olympus_tauri_lib::zk::verify::CircuitVerifier;
use olympus_tauri_lib::zk::witness::{BabyJubJubPubKey, UnifiedWitness};

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
#[ignore = "needs consistent canonicalization + Merkle + SMT fixtures; see module docs"]
fn prove_and_verify_unified_roundtrip() {
    let Some((_wasm, _r1cs, _ark_zkey, vkey)) = artifacts() else {
        eprintln!("[skip] unified artifacts missing — run `bash proofs/setup_circuits.sh` first");
        return;
    };

    // Sanity: the vkey on disk parses cleanly.
    let _verifier = CircuitVerifier::from_file(&vkey)
        .expect("vkey JSON should parse once the file exists");

    // Demonstrate that the signer half of the pipeline is fully working
    // end-to-end (deriving a pubkey, signing the canonical checkpoint
    // message). The remaining work is constructing fixtures whose
    // canonicalization / Merkle / SMT roots agree with the private inputs.
    let priv_key = [0x42_u8; 32];
    let pubkey = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey derive");
    let ledger_root = Fr::from(0xABCD_EF00_u64);
    let checkpoint_timestamp = 1_700_000_000_u64;
    let signature = UnifiedWitness::sign_checkpoint(&priv_key, ledger_root, checkpoint_timestamp)
        .expect("sign_checkpoint");

    // Confirm `authorityPubKeyHash` matches what the circuit will compute
    // from the private (Ax, Ay) inputs.  The circuit constrains this
    // equality, so a mismatch here would cause witness generation to fail.
    let expected_hash =
        hash2(pubkey.x, pubkey.y).expect("Poseidon(Ax, Ay) is the in-circuit authority hash");
    assert_eq!(
        pubkey.authority_hash().expect("authority hash"),
        expected_hash
    );

    // Once fixtures land, fill these in and call `prove_unified`:
    //   let witness = UnifiedWitness::new(
    //       canonical_hash, merkle_root, ledger_root, tree_size,
    //       checkpoint_timestamp, pubkey,
    //       document_sections, section_count, section_lengths, section_hashes,
    //       merkle_path, merkle_indices, leaf_index,
    //       ledger_path_elements, ledger_path_indices,
    //       signature,
    //   )?;
    //   let (proof, public_inputs) = prove_unified(&witness, &wasm, &r1cs, &ark_zkey)?;
    //   assert!(_verifier.verify_proof(&proof, &public_inputs)?);
    let _ = signature; // silence unused-warning until prove_unified call is wired
}
