//! Shared fixtures + adversarial mutation helpers for the ZK dynamic test
//! suite (`zk_soundness.rs`).
//!
//! This module lives in a *subdirectory* of `tests/`, so Cargo does NOT treat
//! it as its own integration-test binary — it is only compiled when a sibling
//! test file pulls it in with `mod zk_fixtures;`. Every consumer is gated on
//! the `prover` + `zk-test-utils` features (it builds proofs via the
//! in-process prover), so the whole module is feature-gated to keep the lean
//! non-prover test job from trying to compile the prover-only paths.
#![cfg(all(feature = "prover", feature = "zk-test-utils"))]
#![allow(dead_code)] // each consumer uses a subset of the builders.

use std::path::{Path, PathBuf};

use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;

use olympus_tauri_lib::zk::poseidon::{compute_merkle_root, domain_node, hash_n};
use olympus_tauri_lib::zk::verify::CircuitVerifier;
use olympus_tauri_lib::zk::witness::{
    BabyJubJubPubKey, ExistenceWitness, NonExistenceWitness, RedactionWitness, UnifiedWitness,
};

/// `proofs/build/` — where `setup_circuits.sh` stages the compiled artifacts.
pub fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("build")
}

/// Resolve `(wasm, r1cs, ark_zkey)` for `stem`, or `None` if any is missing.
/// The witness-generator `.wasm` lives under `<stem>_js/`.
pub fn artifacts(stem: &str) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let build = build_dir();
    let wasm = build
        .join(format!("{stem}_js"))
        .join(format!("{stem}.wasm"));
    let r1cs = build.join(format!("{stem}.r1cs"));
    let ark_zkey = build.join(format!("{stem}_final.ark.zkey"));
    (wasm.is_file() && r1cs.is_file() && ark_zkey.is_file()).then_some((wasm, r1cs, ark_zkey))
}

// ── Adversarial mutation battery ────────────────────────────────────────────
//
// A correct Groth16 verifier binds the proof to *every* public input. These
// helpers encode that as executable soundness checks: take a proof that
// genuinely verifies, then prove that the verifier rejects every single-field
// perturbation of the public-signal vector and a structurally tampered proof.

/// Sanity: the unmodified `(proof, signals)` pair MUST verify, else the
/// negative assertions below would be vacuous.
pub fn assert_baseline_verifies(
    verifier: &CircuitVerifier,
    proof: &ark_groth16::Proof<Bn254>,
    signals: &[Fr],
) {
    let ok = verifier
        .verify_proof(proof, signals)
        .expect("baseline verify call");
    assert!(ok, "baseline proof must verify before mutation testing");
}

/// Flip each public signal independently (+1 mod r) and assert the verifier
/// rejects every one. Groth16 binds all public inputs, so a single-field
/// change must break the pairing check (`Ok(false)`).
pub fn assert_every_signal_flip_rejected(
    verifier: &CircuitVerifier,
    proof: &ark_groth16::Proof<Bn254>,
    signals: &[Fr],
) {
    assert!(
        !signals.is_empty(),
        "circuit must expose at least one public signal"
    );
    for i in 0..signals.len() {
        let mut tampered = signals.to_vec();
        tampered[i] += Fr::from(1u64);
        let r = verifier.verify_proof(proof, &tampered);
        assert!(
            matches!(r, Ok(false)),
            "flipping public signal #{i} must be rejected, got {r:?}"
        );
    }
}

/// Negate the `A` component of the proof and assert the verifier rejects it —
/// a structurally well-formed but forged proof must not verify against the
/// honest public inputs.
pub fn assert_tampered_proof_rejected(
    verifier: &CircuitVerifier,
    proof: &ark_groth16::Proof<Bn254>,
    signals: &[Fr],
) {
    let mut forged = proof.clone();
    // `G1Affine` implements `Neg` directly (negates y); a well-formed but
    // forged `A` must not verify against the honest public inputs.
    forged.a = -forged.a;
    let r = verifier.verify_proof(&forged, signals);
    assert!(
        matches!(r, Ok(false)),
        "proof with a negated `A` component must be rejected, got {r:?}"
    );
}

/// A *truncated* public-signal vector (one input dropped) must never verify:
/// the missing input changes the prepared-input commitment, so the pairing
/// check fails (`Ok(false)`).
///
/// Note we deliberately do NOT assert anything about a *longer*-than-expected
/// vector. ark-groth16's `prepare_inputs` `zip`s the supplied inputs against
/// `gamma_abc_g1.iter().skip(1)`, so it silently ignores surplus *trailing*
/// inputs — an over-length vector whose prefix matches still verifies. That is
/// an arkworks implementation detail, not a soundness gap: every Olympus verify
/// path builds the exact-arity signal vector from the circuit definition, so
/// arity is fixed by construction and never attacker-controlled.
pub fn assert_truncated_signals_rejected(
    verifier: &CircuitVerifier,
    proof: &ark_groth16::Proof<Bn254>,
    signals: &[Fr],
) {
    let mut short = signals.to_vec();
    short.pop();
    let r = verifier.verify_proof(proof, &short);
    assert!(
        !matches!(r, Ok(true)),
        "a truncated public-signal vector ({} of {}) must not verify, got {r:?}",
        short.len(),
        signals.len()
    );
}

/// Run the full battery against a verified `(proof, signals)` pair.
pub fn run_full_battery(
    verifier: &CircuitVerifier,
    proof: &ark_groth16::Proof<Bn254>,
    signals: &[Fr],
) {
    assert_baseline_verifies(verifier, proof, signals);
    assert_every_signal_flip_rejected(verifier, proof, signals);
    assert_tampered_proof_rejected(verifier, proof, signals);
    assert_truncated_signals_rejected(verifier, proof, signals);
}

// ── Per-circuit valid-witness builders ──────────────────────────────────────

const EXISTENCE_DEPTH: usize = 20;
const SMT_DEPTH: usize = 256;
const REDACTION_MAX_LEAVES: usize = 1024;
const REDACTION_DEPTH: usize = 10;

/// Empty-subtree hash chain for a sparse depth-`depth` tree (domain=1).
/// `zeros[0] = 0` (empty-leaf sentinel); `zeros[d] = Node(zeros[d-1], zeros[d-1])`.
fn empty_subtree_hashes(depth: usize) -> Vec<Fr> {
    let mut zeros = vec![Fr::zero(); depth + 1];
    for d in 0..depth {
        zeros[d + 1] = domain_node(1, zeros[d], zeros[d]).expect("domain_node");
    }
    zeros
}

/// A single-leaf `document_existence` witness mirroring
/// `snapshot.rs::build_snapshot_path` (see `tests/zk_prove_existence.rs`).
pub fn existence_witness(leaf: Fr, leaf_index: u64, tree_size: u64) -> ExistenceWitness {
    let zeros = empty_subtree_hashes(EXISTENCE_DEPTH);
    let path_elements: Vec<Fr> = (0..EXISTENCE_DEPTH).map(|d| zeros[d]).collect();
    let path_indices: Vec<u8> = (0..EXISTENCE_DEPTH)
        .map(|i| ((leaf_index >> i) & 1) as u8)
        .collect();
    let root = compute_merkle_root(leaf, &path_elements, &path_indices, 1).expect("root");
    ExistenceWitness::new(
        root,
        leaf_index,
        tree_size,
        leaf,
        path_elements,
        path_indices,
    )
    .expect("existence witness")
}

/// A `non_existence` witness over an all-empty SMT (the key's leaf is the
/// empty sentinel). Mirrors `tests/zk_prove_non_existence.rs`.
pub fn non_existence_witness(key: [u8; 32]) -> NonExistenceWitness {
    let path_elements: Vec<Fr> = vec![Fr::zero(); SMT_DEPTH];
    // Derive indices exactly as the witness/circuit does, to compute the root.
    let mut idx = vec![0u8; SMT_DEPTH];
    for (b_idx, &byte) in key.iter().enumerate() {
        for bit_i in 0..8usize {
            let bit = (byte >> (7 - bit_i)) & 1;
            idx[255 - (b_idx * 8 + bit_i)] = bit;
        }
    }
    let root = compute_merkle_root(Fr::zero(), &path_elements, &idx, 1).expect("root");
    NonExistenceWitness::new(root, key, path_elements).expect("non_existence witness")
}

/// Build a full 1024-leaf depth-10 Poseidon tree (domain=1) and return
/// `(root, per_leaf_paths, per_leaf_indices)`. Mirrors `zk_prove_redaction.rs`.
fn redaction_tree(leaves: &[Fr]) -> (Fr, Vec<Vec<Fr>>, Vec<Vec<u8>>) {
    assert_eq!(leaves.len(), REDACTION_MAX_LEAVES);
    let mut levels: Vec<Vec<Fr>> = vec![leaves.to_vec()];
    for d in 0..REDACTION_DEPTH {
        let prev = &levels[d];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(domain_node(1, chunk[0], chunk[1]).expect("domain_node"));
        }
        levels.push(next);
    }
    let root = levels[REDACTION_DEPTH][0];
    let mut paths = Vec::with_capacity(REDACTION_MAX_LEAVES);
    let mut indices = Vec::with_capacity(REDACTION_MAX_LEAVES);
    for i in 0..REDACTION_MAX_LEAVES {
        let mut path = Vec::with_capacity(REDACTION_DEPTH);
        let mut idx_bits = Vec::with_capacity(REDACTION_DEPTH);
        let mut cur = i;
        for level in levels.iter().take(REDACTION_DEPTH) {
            path.push(level[cur ^ 1]);
            idx_bits.push((cur & 1) as u8);
            cur >>= 1;
        }
        paths.push(path);
        indices.push(idx_bits);
    }
    (root, paths, indices)
}

/// A valid `redaction_validity` witness revealing even-indexed leaves, signed
/// by a deterministic test issuer. Mirrors `tests/zk_prove_redaction.rs`.
pub fn redaction_witness() -> RedactionWitness {
    use olympus_tauri_lib::zk::poseidon::redaction_commitment;
    use olympus_tauri_lib::zk::witness::baby_jubjub;

    let leaves: Vec<Fr> = (1u64..=REDACTION_MAX_LEAVES as u64).map(Fr::from).collect();
    let (root, paths, indices) = redaction_tree(&leaves);
    let mask: Vec<bool> = (0..REDACTION_MAX_LEAVES).map(|i| i % 2 == 0).collect();
    let recipient_id = Fr::from(0xC0FFEE_u64);

    let issuer_priv = [0xA5u8; 32];
    let issuer_pub = baby_jubjub::BabyJubJubPubKey::from_private(&issuer_priv).expect("issuer pub");
    let commit = redaction_commitment(mask.iter().filter(|&&b| b).count() as u64, &leaves, &mask)
        .expect("commit");
    let nullifier_msg = hash_n(&[root, commit, recipient_id]).expect("nullifier");
    let issuer_sig = baby_jubjub::sign(&issuer_priv, nullifier_msg).expect("issuer sign");

    RedactionWitness::new(
        root,
        leaves,
        mask,
        paths,
        indices,
        recipient_id,
        issuer_pub,
        issuer_sig,
    )
    .expect("redaction witness")
}

/// A valid `unified_canonicalization_inclusion_root_sign` witness, leaf at
/// index 0 of both the depth-20 Merkle tree and depth-256 ledger SMT. Mirrors
/// `tests/zk_prove_unified.rs`.
pub fn unified_witness() -> UnifiedWitness {
    use olympus_tauri_lib::zk::witness::unified::{MAX_SECTIONS, MERKLE_DEPTH, SMT_DEPTH as U_SMT};

    let zeros = empty_subtree_hashes(U_SMT);

    let section_count: u64 = 2;
    let section_lengths: Vec<u64> = {
        let mut v = vec![0u64; MAX_SECTIONS];
        v[0] = 42;
        v[1] = 87;
        v
    };
    let document_sections: Vec<Fr> = (0..MAX_SECTIONS as u64)
        .map(|i| Fr::from(i * 0x1000))
        .collect();
    let section_hashes: Vec<Fr> = document_sections
        .iter()
        .map(|s| hash_n(&[*s]).expect("section hash"))
        .collect();

    // canonicalHash: acc = sectionCount; then domain-3 chain over (len, hash).
    let mut acc = Fr::from(section_count);
    for i in 0..MAX_SECTIONS {
        acc = domain_node(3, acc, Fr::from(section_lengths[i])).expect("canon len");
        acc = domain_node(3, acc, section_hashes[i]).expect("canon hash");
    }
    let canonical_hash = acc;

    let merkle_path: Vec<Fr> = (0..MERKLE_DEPTH).map(|i| zeros[i]).collect();
    let merkle_indices = vec![0u8; MERKLE_DEPTH];
    let merkle_root =
        compute_merkle_root(canonical_hash, &merkle_path, &merkle_indices, 1).expect("merkle root");
    let leaf_index = 0u64;
    let tree_size = 1u64;

    let ledger_path: Vec<Fr> = (0..U_SMT).map(|i| zeros[i]).collect();
    let ledger_indices = vec![0u8; U_SMT];
    let ledger_root =
        compute_merkle_root(merkle_root, &ledger_path, &ledger_indices, 1).expect("ledger root");

    let priv_key = [0x42u8; 32];
    let checkpoint_timestamp = 1_700_000_000u64;
    let pubkey = BabyJubJubPubKey::from_private(&priv_key).expect("pubkey");
    let signature = UnifiedWitness::sign_checkpoint(&priv_key, ledger_root, checkpoint_timestamp)
        .expect("sign_checkpoint");

    UnifiedWitness::new(
        canonical_hash,
        merkle_root,
        ledger_root,
        tree_size,
        checkpoint_timestamp,
        pubkey,
        document_sections,
        section_count,
        section_lengths,
        section_hashes,
        merkle_path,
        merkle_indices,
        leaf_index,
        ledger_path,
        ledger_indices,
        signature,
    )
    .expect("unified witness")
}

/// Resolve the unified circuit's committed vkey path (it is ceremony-produced
/// and not part of the embedded `unified_verifier()` unless a real ceremony has
/// run). Returns `None` when the file is absent or still a placeholder.
pub fn unified_vkey_path() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("keys")
        .join("verification_keys")
        .join("unified_canonicalization_inclusion_root_sign_vkey.json");
    if !p.is_file() {
        return None;
    }
    match std::fs::read_to_string(&p) {
        Ok(s) if s.contains("\"placeholder\"") => None,
        Ok(_) => Some(p),
        Err(_) => None,
    }
}

/// Tiny helper so consumers can `let _ = path_exists(p)` without importing Path.
pub fn path_exists(p: &Path) -> bool {
    p.is_file()
}
