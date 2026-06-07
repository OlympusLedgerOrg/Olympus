//! Adversarial **false-statement** soundness tests for the in-process Groth16
//! prover.
//!
//! `zk_soundness.rs` pins the verifier's *binding* guarantee: take a proof that
//! genuinely verifies and show that perturbing any public input, the proof
//! bytes, or the signal arity is rejected. That is necessary but not
//! sufficient — it only exercises proofs minted from an *honest* witness.
//!
//! These tests pin the complementary, and arguably deeper, property:
//!
//!   **an honest prover cannot produce a verifying proof for a statement that
//!   is false.**
//!
//! This is the property that a circuit *under-constraint* bug breaks. If a
//! circuit fails to constrain (say) the Merkle path to the claimed root, the
//! prover will happily mint a proof for a non-member and the binding battery in
//! `zk_soundness.rs` would still pass (it perturbs an already-valid proof; it
//! never tries to forge a false one). The only way to catch that class is to
//! feed the prover a witness that asserts something untrue and require it to
//! refuse — either by failing witness generation / `Groth16::prove` (the R1CS
//! is unsatisfiable), or, defensively, by yielding a proof that does not verify.
//!
//! Construction note: the witness builders (`ExistenceWitness::new`, …) only
//! validate shape (lengths, index bits, bounds), NOT root↔path consistency —
//! `verify_merkle_root()` is a separate opt-in pre-check. That is exactly what
//! lets us hand the circuit a public `root` that the private `(leaf, path)` does
//! not hash to: a structurally-valid witness for a false claim.
//!
//! Like the rest of the dynamic suite these skip cleanly when the ceremony
//! artifacts produced by `bash proofs/setup_circuits.sh` are absent.
//!
//! Run with:
//!   cargo test -p olympus-desktop --features prover,zk-test-utils \
//!       --test zk_soundness_false_statement -- --nocapture

#![cfg(all(feature = "prover", feature = "zk-test-utils"))]

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;

use olympus_tauri_lib::zk::prove::{
    prove_existence, prove_non_existence, prove_redaction, ProveError,
};
use olympus_tauri_lib::zk::verify::{
    existence_verifier, non_existence_verifier, redaction_verifier, CircuitVerifier,
};

mod zk_fixtures;
use zk_fixtures as fx;

/// The soundness assertion shared by every false-statement test.
///
/// A sound system has exactly two acceptable outcomes when asked to prove a
/// false statement, and we accept either:
///   * `Err(_)` — the R1CS is unsatisfiable, so witness generation or
///     `Groth16::prove` refuses to produce a proof at all (the common case), or
///   * `Ok((proof, signals))` where `verify_proof` returns `Ok(false)` — a
///     proof was somehow produced but the verifier rejects it.
///
/// The one outcome that MUST NOT happen is a proof that verifies: that would be
/// a genuine soundness break (a forged proof of a false statement).
fn assert_false_statement_is_unprovable(
    label: &str,
    proved: Result<(Proof<Bn254>, Vec<Fr>), ProveError>,
    verifier: &CircuitVerifier,
) {
    match proved {
        Err(_e) => {
            // Prover refused to satisfy an unsatisfiable R1CS — sound.
        }
        Ok((proof, signals)) => {
            let r = verifier.verify_proof(&proof, &signals);
            assert!(
                matches!(r, Ok(false)),
                "{label}: a proof asserting a FALSE statement must not verify \
                 (under-constrained circuit?), got {r:?}"
            );
        }
    }
}

/// document_existence: claim a leaf is included under a `root` it is NOT under.
///
/// We build an honest single-leaf witness, then bump the public `root` by 1.
/// The leaf/path now hash to `root - 1`, so the circuit's `computedRoot ===
/// root` constraint is unsatisfiable. A prover that mints a verifying proof
/// here would be forging membership of a non-member.
#[test]
fn cannot_forge_existence_under_wrong_root() {
    let Some((wasm, r1cs, ark_zkey)) = fx::artifacts("document_existence") else {
        eprintln!("[skip] document_existence artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    let mut forged = fx::existence_witness(Fr::from(42u64), 1, 4);
    forged.root += Fr::from(1u64); // false: leaf is not under this root

    let proved = prove_existence(&forged, &wasm, &r1cs, &ark_zkey);
    let verifier = existence_verifier().expect("existence verifier");
    assert_false_statement_is_unprovable("existence/wrong-root", proved, verifier);
}

/// non_existence: claim a key is absent under a `root` that does not correspond
/// to the all-empty path the witness carries. Perturbing the public `root` makes
/// the in-circuit empty-leaf inclusion check unsatisfiable — the prover must not
/// be able to forge a non-existence proof against an arbitrary root.
#[test]
fn cannot_forge_non_existence_under_wrong_root() {
    let Some((wasm, r1cs, ark_zkey)) = fx::artifacts("non_existence") else {
        eprintln!("[skip] non_existence artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    let mut forged = fx::non_existence_witness([0xaa; 32]);
    forged.root += Fr::from(1u64); // false: this is not the empty-path root for the key

    let proved = prove_non_existence(&forged, &wasm, &r1cs, &ark_zkey);
    let verifier = non_existence_verifier().expect("non_existence verifier");
    assert_false_statement_is_unprovable("non_existence/wrong-root", proved, verifier);
}

/// redaction_validity: claim a `revealedCount` that disagrees with the actual
/// reveal mask. The circuit pins `revealedCount === sum(mask)`; bumping the
/// count by 1 (while the mask is unchanged) makes that constraint unsatisfiable.
/// A prover that could satisfy it would let a redactor overstate how much of the
/// document the proof attests to — a soundness break in the disclosure count.
#[test]
fn cannot_forge_redaction_with_inflated_revealed_count() {
    let Some((wasm, r1cs, ark_zkey)) = fx::artifacts("redaction_validity") else {
        eprintln!("[skip] redaction_validity artifacts missing — run proofs/setup_circuits.sh");
        return;
    };
    let mut forged = fx::redaction_witness();
    forged.revealed_count += 1; // false: claim one more revealed leaf than the mask sets

    let proved = prove_redaction(&forged, &wasm, &r1cs, &ark_zkey);
    let verifier = redaction_verifier().expect("redaction verifier");
    assert_false_statement_is_unprovable("redaction/inflated-count", proved, verifier);
}
