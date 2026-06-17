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
//! refuse.
//!
//! ## What "refuse" looks like
//!
//! An unsatisfiable R1CS surfaces through ark-circom in one of two ways, and a
//! sound circuit may use either — so we accept both:
//!   * `Err(ProveError::…)` — witness generation / prove returns an error
//!     (how the existence & non-existence circuits surface it), or
//!   * a **panic** from `CircomBuilder::build()`, which asserts `is_satisfied`
//!     and aborts on an unsatisfiable constraint system (the CI log shows the
//!     expected `Unsatisfied constraint: R1CS - …`).
//!
//! The one outcome that MUST NOT happen is a proof that *verifies*: that would
//! be a genuine soundness break (a forged proof of a false statement). We catch
//! the panic so it counts as a (loud-on-stderr but passing) refusal rather than
//! failing the test.
//!
//! Construction note: the witness builders (`ExistenceWitness::new`, …) only
//! validate shape (lengths, index bits, bounds), NOT root↔path / count
//! consistency, so we can hand the circuit a structurally-valid witness for a
//! false claim.
//!
//! Like the rest of the dynamic suite these skip cleanly when the ceremony
//! artifacts produced by `bash proofs/setup_circuits.sh` are absent.
//!
//! Run with:
//!   cargo test -p olympus-desktop --features prover,zk-test-utils \
//!       --test zk_soundness_false_statement -- --nocapture

#![cfg(all(feature = "prover", feature = "zk-test-utils"))]

use std::panic::{catch_unwind, AssertUnwindSafe};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;

use olympus_tauri_lib::zk::prove::{prove_existence, prove_non_existence, ProveError};
use olympus_tauri_lib::zk::verify::{existence_verifier, non_existence_verifier, CircuitVerifier};

mod zk_fixtures;
use zk_fixtures as fx;

/// The soundness assertion shared by every false-statement test.
///
/// `prove` builds and proves the (false) witness. A sound system refuses, by
/// either returning `Err` or panicking inside `CircomBuilder::build()`'s
/// `is_satisfied` assertion — both are accepted. The only failure is a proof
/// that actually verifies against the false public inputs.
fn assert_false_statement_is_unprovable<F>(label: &str, prove: F, verifier: &CircuitVerifier)
where
    F: FnOnce() -> Result<(Proof<Bn254>, Vec<Fr>), ProveError>,
{
    // ark-circom asserts `is_satisfied` in `build()`, so an unsatisfiable R1CS
    // can abort via panic rather than `Err`; catch it and treat it as a refusal.
    match catch_unwind(AssertUnwindSafe(prove)) {
        Err(_panic) => {
            // Prover panicked on an unsatisfiable constraint system — sound.
        }
        Ok(Err(_e)) => {
            // Prover returned an error on the unsatisfiable witness — sound.
        }
        Ok(Ok((proof, signals))) => {
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

    let verifier = existence_verifier().expect("existence verifier");
    assert_false_statement_is_unprovable(
        "existence/wrong-root",
        || prove_existence(&forged, &wasm, &r1cs, &ark_zkey),
        verifier,
    );
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

    let verifier = non_existence_verifier().expect("non_existence verifier");
    assert_false_statement_is_unprovable(
        "non_existence/wrong-root",
        || prove_non_existence(&forged, &wasm, &r1cs, &ark_zkey),
        verifier,
    );
}
