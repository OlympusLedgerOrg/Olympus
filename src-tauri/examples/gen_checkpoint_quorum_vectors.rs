//! Generate the checkpoint-quorum golden vectors consumed by the differential
//! verifiers (`verifiers/rust`, `verifiers/javascript`).
//!
//! Deterministic — fixed private keys, no randomness — so re-running reproduces
//! byte-identical output. Each case's `expected` block is computed by the
//! authoritative Rust verifier (`verify_checkpoint_quorum`) and the message by
//! `checkpoint_quorum_message`, so the vector can never silently disagree with
//! the implementation it pins.
//!
//! Usage:
//!   cargo run -p olympus-desktop --example gen_checkpoint_quorum_vectors
//! Writes:
//!   verifiers/test_vectors/checkpoint_quorum_vectors.json

use ark_bn254::Fr;
use serde_json::{json, Value};

use olympus_tauri_lib::quorum::checkpoint::{
    checkpoint_quorum_message, cosign_checkpoint, signer_from_private, verify_checkpoint_quorum,
    CHECKPOINT_QUORUM_PREFIX,
};
use olympus_tauri_lib::quorum::{CollectedSignature, QuorumSigner};
use olympus_tauri_lib::zk::proof::fr_to_decimal;

fn signer_json(s: &QuorumSigner) -> Value {
    json!({ "x": s.x, "y": s.y })
}

fn cosig_json(c: &CollectedSignature) -> Value {
    json!({
        "x": c.signer.x,
        "y": c.signer.y,
        "r8x": c.r8x,
        "r8y": c.r8y,
        "s": c.s,
    })
}

/// Assemble one case: the verify-time `(root, threshold, signers)` plus the
/// presented `cosignatures`, with `expected` derived from the live verifier.
fn case(
    name: &str,
    doc: &str,
    root: &Fr,
    threshold: usize,
    signers: &[QuorumSigner],
    cosignatures: &[CollectedSignature],
) -> Value {
    let status = verify_checkpoint_quorum(root, signers, threshold, cosignatures);
    let message = fr_to_decimal(&checkpoint_quorum_message(root, threshold, signers));
    json!({
        "name": name,
        "doc": doc,
        "root": fr_to_decimal(root),
        "threshold": threshold,
        "signers": signers.iter().map(signer_json).collect::<Vec<_>>(),
        "cosignatures": cosignatures.iter().map(cosig_json).collect::<Vec<_>>(),
        "expected": {
            "message": message,
            "satisfied": status.satisfied,
            "valid_signatures": status.valid_signatures,
            "total_signers": status.total_signers,
        },
    })
}

fn main() {
    // Deterministic signer key material.
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    let k3 = [3u8; 32];
    let k_out = [99u8; 32];

    let s1 = signer_from_private(&k1).expect("s1");
    let s2 = signer_from_private(&k2).expect("s2");
    let s3 = signer_from_private(&k3).expect("s3");

    let set3 = vec![s1.clone(), s2.clone(), s3.clone()];
    let set2 = vec![s1.clone(), s2.clone()];
    let set1 = vec![s1.clone()];

    let cosign = |k: &[u8; 32], root: &Fr, t: usize, set: &[QuorumSigner]| {
        cosign_checkpoint(k, root, t, set).expect("cosign")
    };

    let mut cases: Vec<Value> = Vec::new();

    // 1. Honest 2-of-3.
    let root = Fr::from(100u64);
    cases.push(case(
        "valid_2_of_3",
        "Two of three pinned signers co-sign root over (root, t=2, set3); quorum satisfied.",
        &root,
        2,
        &set3,
        &[cosign(&k1, &root, 2, &set3), cosign(&k2, &root, 2, &set3)],
    ));

    // 2. One valid signature, threshold 2 — not satisfied.
    let root = Fr::from(101u64);
    cases.push(case(
        "one_of_three_insufficient",
        "Only one member co-signs; 1 < threshold 2, so not satisfied.",
        &root,
        2,
        &set3,
        &[cosign(&k1, &root, 2, &set3)],
    ));

    // 3. A non-member's valid signature is ignored.
    let root = Fr::from(102u64);
    let outsider = cosign(&k_out, &root, 2, &set2); // signs the same message, but key not pinned
    cases.push(case(
        "non_member_ignored",
        "An outsider produces a valid signature over the message, but its key is not in the pinned set, so it does not count.",
        &root,
        2,
        &set2,
        &[cosign(&k1, &root, 2, &set2), outsider],
    ));

    // 4. Duplicate signer counts once.
    let root = Fr::from(103u64);
    cases.push(case(
        "duplicate_signer_counts_once",
        "The same signer submits two valid signatures; distinctness keys on the pubkey, so it counts once.",
        &root,
        2,
        &set2,
        &[cosign(&k1, &root, 2, &set2), cosign(&k1, &root, 2, &set2)],
    ));

    // 5. Signature over the wrong root.
    let root = Fr::from(104u64);
    let wrong_root = Fr::from(999u64);
    cases.push(case(
        "wrong_root_rejected",
        "The signature is over a different root; against the verify-time root it does not verify.",
        &root,
        1,
        &set1,
        &[cosign(&k1, &wrong_root, 1, &set1)],
    ));

    // 6. Tampered S component.
    let root = Fr::from(105u64);
    let mut tampered = cosign(&k1, &root, 1, &set1);
    tampered.s = "12345".to_owned();
    cases.push(case(
        "tampered_signature_rejected",
        "A valid signature whose S scalar has been mutated must not verify.",
        &root,
        1,
        &set1,
        &[tampered],
    ));

    // 7. Threshold downgrade: signed at t=2, verified at t=1.
    let root = Fr::from(106u64);
    cases.push(case(
        "threshold_downgrade_breaks_quorum",
        "Signatures were made over threshold=2; verifying at threshold=1 changes the bound message, so none verify (R3-01 binding).",
        &root,
        1,
        &set3,
        &[cosign(&k1, &root, 2, &set3), cosign(&k2, &root, 2, &set3)],
    ));

    // 8. Zero threshold is never vacuously satisfied.
    let root = Fr::from(107u64);
    cases.push(case(
        "zero_threshold_not_satisfied",
        "A genuinely valid signature is present, but threshold 0 must never be 'satisfied'.",
        &root,
        0,
        &set1,
        &[cosign(&k1, &root, 0, &set1)],
    ));

    let domain = std::str::from_utf8(CHECKPOINT_QUORUM_PREFIX).expect("ascii domain");
    let doc = json!({
        "version": 1,
        "description": "Checkpoint-quorum (OLY:CHECKPOINT:QUORUM:V1) M-of-N BJJ-EdDSA co-signatures over a ledger root. Golden vectors for the differential verifiers; mirror src-tauri/src/quorum/checkpoint.rs (ADR-0032).",
        "domain": domain,
        "message_construction": "msg = Fr_le(BLAKE3( domain || u32be(len(root_dec))||root_dec || u32be(threshold) || u32be(N) || for each canonical-sorted signer: u32be(len(x))||x||u32be(len(y))||y )). root_dec/x/y are canonical decimal BN254 field elements; signers are sorted by (x,y) decimal; Fr_le reduces the 32-byte BLAKE3 digest as a little-endian integer mod the BN254 scalar field r. The signed value is this message under BabyJubJub EdDSA-Poseidon.",
        "scheme": "BabyJubJub-EdDSA-Poseidon over BN254",
        "cases": cases,
    });

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_path = std::path::Path::new(manifest_dir)
        .join("..")
        .join("verifiers")
        .join("test_vectors")
        .join("checkpoint_quorum_vectors.json");
    let pretty = serde_json::to_string_pretty(&doc).expect("serialize vectors") + "\n";
    std::fs::write(&out_path, pretty.as_bytes()).unwrap_or_else(|e| {
        panic!("write {}: {e}", out_path.display());
    });
    println!(
        "wrote {} checkpoint-quorum cases -> {}",
        doc["cases"].as_array().map(|a| a.len()).unwrap_or(0),
        out_path.display()
    );
}
