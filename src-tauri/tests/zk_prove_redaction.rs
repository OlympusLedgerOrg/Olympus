//! Round-trip test for the native `redaction_validity` prover (ADR-0025).
//!
//! Builds a 1024-leaf depth-10 Poseidon Merkle tree from a contiguous
//! [1, 2, ..., 1024] leaf set, exercises both a subset-reveal and a
//! full-reveal redaction, generates a proof, verifies it, and checks
//! the tampered-input negative case.
//!
//! Requires (from `bash proofs/setup_circuits.sh`):
//!   * proofs/build/redaction_validity_js/redaction_validity.wasm
//!   * proofs/build/redaction_validity.r1cs
//!   * proofs/build/redaction_validity_final.ark.zkey
//!
//! Run:  cargo test -p olympus-tauri --test zk_prove_redaction -- --nocapture

use std::path::PathBuf;

use ark_bn254::Fr;
use ark_ff::PrimeField;
use olympus_tauri_lib::zk::pdf_objects::{extract_objects, witness_inputs};
use olympus_tauri_lib::zk::poseidon::domain_node;
use olympus_tauri_lib::zk::prove::prove_redaction;
use olympus_tauri_lib::zk::verify::redaction_verifier;
use olympus_tauri_lib::zk::witness::RedactionWitness;

// ADR-0025 geometry: must mirror parameters.circom + witness/redaction.rs.
const MAX_LEAVES: usize = 1024;
const DEPTH: usize = 10;

fn build_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("proofs")
        .join("build")
}

fn artifacts(build: &std::path::Path) -> Option<(PathBuf, PathBuf, PathBuf)> {
    let wasm = build
        .join("redaction_validity_js")
        .join("redaction_validity.wasm");
    let r1cs = build.join("redaction_validity.r1cs");
    let ark_zkey = build.join("redaction_validity_final.ark.zkey");
    if wasm.is_file() && r1cs.is_file() && ark_zkey.is_file() {
        Some((wasm, r1cs, ark_zkey))
    } else {
        None
    }
}

/// Build a complete 1024-leaf depth-10 Poseidon Merkle tree (domain=1).
/// Returns (root, per_leaf_paths, per_leaf_path_indices).
fn build_tree(leaves: &[Fr]) -> (Fr, Vec<Vec<Fr>>, Vec<Vec<u8>>) {
    assert_eq!(leaves.len(), MAX_LEAVES);

    let mut levels: Vec<Vec<Fr>> = Vec::with_capacity(DEPTH + 1);
    levels.push(leaves.to_vec());
    for d in 0..DEPTH {
        let prev = &levels[d];
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(domain_node(1, chunk[0], chunk[1]).expect("domain_node"));
        }
        levels.push(next);
    }
    let root = levels[DEPTH][0];

    let mut paths = Vec::with_capacity(MAX_LEAVES);
    let mut indices = Vec::with_capacity(MAX_LEAVES);
    for i in 0..MAX_LEAVES {
        let mut path = Vec::with_capacity(DEPTH);
        let mut idx_bits = Vec::with_capacity(DEPTH);
        let mut cur = i;
        for level in levels.iter().take(DEPTH) {
            let bit = (cur & 1) as u8;
            let sibling_pos = cur ^ 1;
            path.push(level[sibling_pos]);
            idx_bits.push(bit);
            cur >>= 1;
        }
        paths.push(path);
        indices.push(idx_bits);
    }
    (root, paths, indices)
}

#[test]
fn prove_and_verify_redaction_roundtrip() {
    let build = build_dir();
    let Some((wasm, r1cs, ark_zkey)) = artifacts(&build) else {
        eprintln!(
            "[skip] redaction artifacts missing under {}.\n\
             Run `bash proofs/setup_circuits.sh` first.",
            build.display()
        );
        return;
    };

    let leaves: Vec<Fr> = (1u64..=MAX_LEAVES as u64).map(Fr::from).collect();
    let (root, paths, indices) = build_tree(&leaves);

    // Subset reveal: exercise concrete corner-case indices (first, near-start,
    // middle, last) so a regression in the fold construction surfaces.
    let mut mask = vec![false; MAX_LEAVES];
    for i in [0_usize, 100, 500, 1023] {
        mask[i] = true;
    }
    let recipient_id = Fr::from(0xC0FFEE_u64);

    // Audit M-2: the redaction circuit requires an in-circuit
    // EdDSA-Poseidon signature from a trusted issuer over the nullifier.
    let issuer_priv = [0xA5u8; 32];
    let issuer_pub =
        olympus_tauri_lib::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&issuer_priv)
            .expect("issuer pubkey");
    let nullifier_msg = {
        let commit = olympus_tauri_lib::zk::poseidon::redaction_commitment(
            mask.iter().filter(|&&b| b).count() as u64,
            &leaves,
            &mask,
        )
        .expect("commit");
        olympus_tauri_lib::zk::poseidon::hash_n(&[root, commit, recipient_id]).expect("nullifier")
    };
    let issuer_sig = olympus_tauri_lib::zk::witness::baby_jubjub::sign(&issuer_priv, nullifier_msg)
        .expect("issuer sign");

    let witness = RedactionWitness::new(
        root,
        leaves.clone(),
        mask,
        paths,
        indices,
        recipient_id,
        issuer_pub,
        issuer_sig,
    )
    .expect("redaction witness construction");
    witness
        .verify_all_paths()
        .expect("every leaf path must reach originalRoot");

    let (proof, public_inputs) =
        prove_redaction(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_redaction");

    // Verify the prover's public-signal order matches what the witness
    // claims (output `nullifier` first, then declared public inputs).
    assert_eq!(public_inputs, witness.public_signals());

    let verifier = redaction_verifier().expect("verifier init");
    let valid = verifier
        .verify_proof(&proof, &public_inputs)
        .expect("verify call");
    assert!(valid, "redaction round-trip must verify");
}

#[test]
fn tampered_redacted_commitment_fails() {
    let build = build_dir();
    let Some((wasm, r1cs, ark_zkey)) = artifacts(&build) else {
        eprintln!("[skip] redaction artifacts missing (see prove_and_verify_redaction_roundtrip)");
        return;
    };

    let leaves: Vec<Fr> = (1u64..=MAX_LEAVES as u64).map(Fr::from).collect();
    let (root, paths, indices) = build_tree(&leaves);
    // Full reveal exercises the all-ones mask path (popcount == MAX_LEAVES).
    let mask: Vec<bool> = vec![true; MAX_LEAVES];
    let recipient_id = Fr::from(7u64);

    let issuer_priv = [0xA5u8; 32];
    let issuer_pub =
        olympus_tauri_lib::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&issuer_priv)
            .expect("issuer pubkey");
    let nullifier_msg = {
        let commit = olympus_tauri_lib::zk::poseidon::redaction_commitment(
            mask.iter().filter(|&&b| b).count() as u64,
            &leaves,
            &mask,
        )
        .expect("commit");
        olympus_tauri_lib::zk::poseidon::hash_n(&[root, commit, recipient_id]).expect("nullifier")
    };
    let issuer_sig = olympus_tauri_lib::zk::witness::baby_jubjub::sign(&issuer_priv, nullifier_msg)
        .expect("issuer sign");
    let witness = RedactionWitness::new(
        root,
        leaves,
        mask,
        paths,
        indices,
        recipient_id,
        issuer_pub,
        issuer_sig,
    )
    .expect("witness construction");

    let (proof, mut public_inputs) =
        prove_redaction(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_redaction");

    // Corrupt redactedCommitment (index 2 in [nullifier, originalRoot,
    // redactedCommitment, revealedCount, issuerAx, issuerAy]) and confirm the
    // verifier rejects.
    public_inputs[2] = Fr::from(0xDEAD_BEEF_u64);
    let verifier = redaction_verifier().expect("verifier init");
    let valid = verifier
        .verify_proof(&proof, &public_inputs)
        .expect("verify call");
    assert!(!valid, "tampered redactedCommitment must NOT verify");
}

// ── Object-level producer path (ADR-0026) ──────────────────────────────────────
//
// Regression guard for the class of bug in #1226: the *producer* must build a
// witness from the real object-extraction manifest that the circuit accepts.
// The synthetic-tree tests above prove the circuit works on a hand-built tree;
// this drives the actual `extract_objects` → `witness_inputs` path that backs a
// `/redaction/issue` call, so a producer/circuit geometry mismatch (the #1226
// failure mode) surfaces here in CI instead of in production.

/// Fixed server blinding secret (mirrors the `pdf_objects` unit fixtures).
const TEST_BLIND_SECRET: &[u8] = &[0x5au8; 32];

/// Minimal valid traditional-xref PDF. Mirrors `pdf_objects::tests::build_pdf`,
/// which is `#[cfg(test)]`-private to that module and so unreachable from an
/// integration-test crate.
fn build_pdf(bodies: &[&str]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(b"%PDF-1.4\n");
    let mut offsets = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        offsets.push(buf.len());
        buf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        buf.extend_from_slice(body.as_bytes());
        buf.extend_from_slice(b"\nendobj\n");
    }
    let xref_off = buf.len();
    let n = bodies.len() + 1; // include free object 0
    buf.extend_from_slice(format!("xref\n0 {n}\n").as_bytes());
    buf.extend_from_slice(b"0000000000 65535 f \n");
    for off in &offsets {
        buf.extend_from_slice(format!("{:010} 00000 n \n", off).as_bytes());
    }
    buf.extend_from_slice(format!("trailer\n<< /Size {n} /Root 1 0 R >>\n").as_bytes());
    buf.extend_from_slice(format!("startxref\n{xref_off}\n%%EOF\n").as_bytes());
    buf
}

/// Parse a 64-hex Poseidon root into `Fr` (big-endian, reduced) — same as the
/// `/redaction/issue` handler's `original_root` decode.
fn fr_from_hex(h: &str) -> Fr {
    let bytes = hex::decode(h).expect("hex root");
    let mut padded = [0u8; 32];
    let off = 32usize.saturating_sub(bytes.len());
    padded[off..].copy_from_slice(&bytes);
    Fr::from_be_bytes_mod_order(&padded)
}

#[test]
fn prove_and_verify_redaction_from_object_manifest() {
    let build = build_dir();
    let Some((wasm, r1cs, ark_zkey)) = artifacts(&build) else {
        eprintln!("[skip] redaction artifacts missing (see prove_and_verify_redaction_roundtrip)");
        return;
    };

    // Real producer extraction: a 3-object PDF → object manifest (ADR-0026).
    let pdf = build_pdf(&[
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ]);
    let manifest = extract_objects(&pdf, TEST_BLIND_SECRET).expect("extract_objects");
    assert_eq!(manifest.objects.len(), 3, "three in-use objects");

    let (leaves, paths, indices) = witness_inputs(&manifest).expect("witness_inputs");
    let root = fr_from_hex(&manifest.original_root_hex);

    // Redact object 2 (index 1); reveal objects 1 and 3. Zero-padding stays
    // hidden (mask false) as the circuit + ingest commit require.
    let mut mask = vec![false; MAX_LEAVES];
    mask[0] = true;
    mask[2] = true;
    let revealed = mask.iter().filter(|&&b| b).count();
    assert_eq!(revealed, 2);

    let recipient_id = Fr::from(0xC0FFEE_u64);
    let issuer_priv = [0xA5u8; 32];
    let issuer_pub =
        olympus_tauri_lib::zk::witness::baby_jubjub::BabyJubJubPubKey::from_private(&issuer_priv)
            .expect("issuer pubkey");
    let commit =
        olympus_tauri_lib::zk::poseidon::redaction_commitment(revealed as u64, &leaves, &mask)
            .expect("commit");
    let nullifier_msg =
        olympus_tauri_lib::zk::poseidon::hash_n(&[root, commit, recipient_id]).expect("nullifier");
    let issuer_sig = olympus_tauri_lib::zk::witness::baby_jubjub::sign(&issuer_priv, nullifier_msg)
        .expect("issuer sign");

    let witness = RedactionWitness::new(
        root, leaves, mask, paths, indices, recipient_id, issuer_pub, issuer_sig,
    )
    .expect("redaction witness from object manifest");
    // The extracted manifest's root MUST equal the witness tree root — the exact
    // producer/circuit-geometry contract that #1226 violated.
    witness
        .verify_all_paths()
        .expect("object-manifest leaf paths must reach manifest.original_root");

    let (proof, mut public_inputs) =
        prove_redaction(&witness, &wasm, &r1cs, &ark_zkey).expect("prove_redaction");
    assert_eq!(public_inputs, witness.public_signals());

    let verifier = redaction_verifier().expect("verifier init");
    assert!(
        verifier
            .verify_proof(&proof, &public_inputs)
            .expect("verify call"),
        "object-manifest redaction proof must verify"
    );

    // Negative: corrupt originalRoot (signal index 1) → verification must fail.
    public_inputs[1] = Fr::from(0xDEAD_BEEF_u64);
    assert!(
        !verifier
            .verify_proof(&proof, &public_inputs)
            .expect("verify call"),
        "tampered originalRoot must NOT verify"
    );
}
