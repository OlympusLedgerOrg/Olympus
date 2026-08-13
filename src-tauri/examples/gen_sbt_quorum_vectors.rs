// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generate the SBT-credential-quorum golden vectors consumed by the
//! differential verifiers (`verifiers/rust`, `verifiers/javascript`).
//!
//! This mirrors `gen_checkpoint_quorum_vectors.rs`, but for the
//! security-load-bearing **SBT credential** quorum (`OLY:SBT:QUORUM:V2`) — the
//! M-of-N co-signature set that drives credential-based scope elevation (audit
//! L6). Where the checkpoint generator co-signs a ledger checkpoint
//! `(chain_id, epoch, root)`, this co-signs a credential's `commit_id`.
//!
//! Deterministic — fixed private keys, fixed credential provenance, no
//! randomness — so re-running reproduces byte-identical output. Each case's
//! `expected` block is computed by the authoritative Rust verifier
//! (`quorum::verify_quorum`) and the message by `quorum::quorum_cosign_message`,
//! so the vector can never silently disagree with the implementation it pins
//! (audit R3-01, `OLY:SBT:QUORUM:V2`). `commit_id` is derived by the real
//! `api::credentials::compute_commit_id` (domain `OLY:SBT:V1`) so the bound
//! object is a genuine credential commitment, not a synthetic byte string.
//!
//! Usage:
//!   cargo run -p olympus-desktop --no-default-features --example gen_sbt_quorum_vectors
//! Writes:
//!   verifiers/test_vectors/sbt_quorum_vectors.json

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde_json::{json, Value};

use olympus_tauri_lib::api::credentials::compute_commit_id;
use olympus_tauri_lib::quorum::checkpoint::cosign_checkpoint;
use olympus_tauri_lib::quorum::{
    quorum_cosign_message, verify_quorum, CollectedSignature, QuorumSigner, QUORUM_COSIGN_PREFIX,
};
use olympus_tauri_lib::zk::proof::fr_to_decimal;
use olympus_tauri_lib::zk::witness::baby_jubjub::{self, BabyJubJubPubKey};

/// Derive a signer's canonical decimal `(x, y)` pubkey from a 32-byte BJJ
/// private key. Domain-agnostic — the same pubkey signs in any quorum domain.
fn signer_from_private(priv_key: &[u8; 32]) -> QuorumSigner {
    let pk = BabyJubJubPubKey::from_private(priv_key).expect("derive BJJ pubkey");
    QuorumSigner {
        x: fr_to_decimal(&pk.x),
        y: fr_to_decimal(&pk.y),
    }
}

/// Co-sign the SBT quorum message for `(commit_id, threshold, signers)` with a
/// BJJ private key — the SBT analogue of `cosign_checkpoint`, mirroring the
/// module's own test helper. `signer` carries the co-signer's advertised
/// identity (normally that key's own pubkey, but decoupled here so negative
/// vectors can present a signature under a mismatched or foreign label).
fn cosign_sbt(
    priv_key: &[u8; 32],
    signer: &QuorumSigner,
    commit_id: &[u8; 32],
    threshold: u32,
    signers: &[QuorumSigner],
) -> CollectedSignature {
    let msg = quorum_cosign_message(commit_id, threshold as usize, signers);
    let sig = baby_jubjub::sign(priv_key, msg).expect("BJJ-EdDSA sign");
    CollectedSignature {
        signer: signer.clone(),
        r8x: fr_to_decimal(&sig.r8x),
        r8y: fr_to_decimal(&sig.r8y),
        s: fr_to_decimal(&sig.s),
    }
}

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

/// Assemble one case: the verify-time `(commit_id, threshold, signers)` plus the
/// presented `cosignatures`, with `expected` derived from the live verifier.
fn case(
    name: &str,
    doc: &str,
    commit_id: &[u8; 32],
    threshold: u32,
    signers: &[QuorumSigner],
    cosignatures: &[CollectedSignature],
) -> Value {
    let status = verify_quorum(commit_id, signers, threshold as usize, cosignatures);
    let message = fr_to_decimal(&quorum_cosign_message(
        commit_id,
        threshold as usize,
        signers,
    ));
    json!({
        "name": name,
        "doc": doc,
        "commit_id": hex::encode(commit_id),
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
    // Deterministic signer key material (same seeds as the checkpoint generator).
    let k1 = [1u8; 32];
    let k2 = [2u8; 32];
    let k3 = [3u8; 32];
    let k_out = [99u8; 32];
    let k_attacker = [7u8; 32];

    let s1 = signer_from_private(&k1);
    let s2 = signer_from_private(&k2);
    let s3 = signer_from_private(&k3);
    let attacker = signer_from_private(&k_attacker);

    let set3 = vec![s1.clone(), s2.clone(), s3.clone()];
    let set2 = vec![s1.clone(), s2.clone()];
    let set1 = vec![s1.clone()];

    // Genuine credential commit_ids via the real `compute_commit_id`
    // (`OLY:SBT:V1`): a fixed press-accreditation holder + type, with the
    // per-case label folded into `details` so each case pins a distinct,
    // deterministic commitment. The quorum message consumes only the resulting
    // 64-char hex `commit_id` (see `commit_id_construction`); the offline
    // verifiers treat it as the opaque bound object, exactly as the checkpoint
    // verifiers treat `(chain_id, epoch, root)`.
    let commit_for = |label: &str| {
        compute_commit_id(
            "did:olympus:alice",
            "press-accreditation",
            1_700_000_000,
            &json!({ "role": "journalist", "case": label }),
        )
        .expect("compute_commit_id (JCS)")
    };

    let mut cases: Vec<Value> = Vec::new();

    // 1. Honest 2-of-3 — quorum satisfied.
    let cid_valid = commit_for("valid_2_of_3");
    cases.push(case(
        "valid_2_of_3",
        "Two of three pinned signers co-sign the credential commit_id; quorum satisfied.",
        &cid_valid,
        2,
        &set3,
        &[
            cosign_sbt(&k1, &s1, &cid_valid, 2, &set3),
            cosign_sbt(&k2, &s2, &cid_valid, 2, &set3),
        ],
    ));

    // 2. Reordering the pinned set does NOT change the message (canonical sort),
    //    so the same two signatures still satisfy — order-independence, not an
    //    attack. Reuses case 1's commit_id, so `expected.message` is identical.
    let reordered = vec![s3.clone(), s1.clone(), s2.clone()];
    cases.push(case(
        "signer_reorder_still_satisfied",
        "The pinned set is presented in a different order; the message is normalized+sorted before hashing, so it is byte-identical to valid_2_of_3 and the same two signatures still satisfy.",
        &cid_valid,
        2,
        &reordered,
        &[
            cosign_sbt(&k1, &s1, &cid_valid, 2, &set3),
            cosign_sbt(&k2, &s2, &cid_valid, 2, &set3),
        ],
    ));

    // 3. One valid signature, threshold 2 — not satisfied.
    let cid = commit_for("one_of_three_insufficient");
    cases.push(case(
        "one_of_three_insufficient",
        "Only one member co-signs; 1 < threshold 2, so not satisfied.",
        &cid,
        2,
        &set3,
        &[cosign_sbt(&k1, &s1, &cid, 2, &set3)],
    ));

    // 4. A non-member's valid signature is ignored.
    let cid = commit_for("non_member_ignored");
    cases.push(case(
        "non_member_ignored",
        "An outsider produces a valid signature over the message, but its key is not in the pinned set, so it does not count toward the quorum.",
        &cid,
        2,
        &set2,
        &[
            cosign_sbt(&k1, &s1, &cid, 2, &set2),
            cosign_sbt(&k_out, &signer_from_private(&k_out), &cid, 2, &set2),
        ],
    ));

    // 5. Duplicate signer counts once (below threshold after dedup).
    let cid = commit_for("duplicate_signer_counts_once");
    cases.push(case(
        "duplicate_signer_counts_once",
        "The same signer submits two valid signatures; distinctness keys on the pubkey, so it counts once — 1 < threshold 2.",
        &cid,
        2,
        &set2,
        &[
            cosign_sbt(&k1, &s1, &cid, 2, &set2),
            cosign_sbt(&k1, &s1, &cid, 2, &set2),
        ],
    ));

    // 6. Signature over a different commit_id — the credential binding.
    let cid = commit_for("wrong_commit_id_rejected");
    let other_cid = commit_for("wrong_commit_id_rejected__other");
    cases.push(case(
        "wrong_commit_id_rejected",
        "The signature was made over a different credential commit_id; against the verify-time commit_id it does not verify (credential binding).",
        &cid,
        1,
        &set1,
        &[cosign_sbt(&k1, &s1, &other_cid, 1, &set1)],
    ));

    // 7. Signer-set tamper: an attacker key swapped into the pinned set (R3-01).
    //    s1/s2 remain members, so the failure is the changed bound message, not
    //    a membership miss.
    let cid = commit_for("signer_set_tampered_rejected");
    let tampered_set = vec![s1.clone(), s2.clone(), attacker.clone()];
    cases.push(case(
        "signer_set_tampered_rejected",
        "Signatures were made over the pinned set {s1,s2,s3}; verifying against {s1,s2,attacker} changes the bound message, so the honest signatures no longer verify even though their signers are still members (R3-01 signer-set binding).",
        &cid,
        2,
        &tampered_set,
        &[
            cosign_sbt(&k1, &s1, &cid, 2, &set3),
            cosign_sbt(&k2, &s2, &cid, 2, &set3),
        ],
    ));

    // 8. Signer-set shrink: a pinned signer dropped at verify time (R3-01).
    let cid = commit_for("signer_set_dropped_rejected");
    cases.push(case(
        "signer_set_dropped_rejected",
        "Signatures were made over the pinned set {s1,s2,s3}; dropping s3 to {s1,s2} changes the bound message, so none of the collected signatures verify (R3-01 signer-set binding).",
        &cid,
        2,
        &set2,
        &[
            cosign_sbt(&k1, &s1, &cid, 2, &set3),
            cosign_sbt(&k2, &s2, &cid, 2, &set3),
        ],
    ));

    // 9. Threshold downgrade: signed at t=2, verified at t=1 (R3-01).
    let cid = commit_for("threshold_downgrade_breaks_quorum");
    cases.push(case(
        "threshold_downgrade_breaks_quorum",
        "Signatures were made over threshold=2; verifying at threshold=1 changes the bound message, so none verify (R3-01 threshold binding).",
        &cid,
        1,
        &set3,
        &[
            cosign_sbt(&k1, &s1, &cid, 2, &set3),
            cosign_sbt(&k2, &s2, &cid, 2, &set3),
        ],
    ));

    // 10. Tampered S component.
    let cid = commit_for("tampered_signature_rejected");
    let mut tampered = cosign_sbt(&k1, &s1, &cid, 1, &set1);
    tampered.s = "12345".to_owned();
    cases.push(case(
        "tampered_signature_rejected",
        "A valid signature whose S scalar has been mutated must not verify.",
        &cid,
        1,
        &set1,
        &[tampered],
    ));

    // 11. Zero threshold is never vacuously satisfied.
    let cid = commit_for("zero_threshold_not_satisfied");
    cases.push(case(
        "zero_threshold_not_satisfied",
        "A genuinely valid signature is present, but threshold 0 must never be 'satisfied'.",
        &cid,
        0,
        &set1,
        &[cosign_sbt(&k1, &s1, &cid, 0, &set1)],
    ));

    // 12. Cross-domain replay: a checkpoint-domain co-signature by a pinned SBT
    //     signer must NOT count toward an SBT quorum. s1 IS a member here, so
    //     the rejection is enforced by the disjoint domain tag changing the
    //     signed message — not by a membership miss. (threshold=1/1-signer
    //     isolates the domain-separation rejection at the core `verify_quorum`
    //     level; the live SBT acceptance path additionally requires M>=2/N>=2.)
    let cid_x = commit_for("cross_domain_checkpoint_sig_rejected");
    let cp_chain = Fr::from(7u64);
    let cp_root = Fr::from_le_bytes_mod_order(&cid_x);
    let cp_sig = cosign_checkpoint(&k1, &cp_chain, 1, &cp_root, 1, &set1)
        .expect("checkpoint-domain co-signature");
    cases.push(case(
        "cross_domain_checkpoint_sig_rejected",
        "A signature made under OLY:CHECKPOINT:QUORUM:V2 (over a checkpoint whose root is derived from these commit_id bytes) is replayed as an OLY:SBT:QUORUM:V2 co-signature. Its signer is a pinned member, but the disjoint domain tag makes the signed message differ, so it does not verify and the quorum stays unsatisfied.",
        &cid_x,
        1,
        &set1,
        &[cp_sig],
    ));

    let domain = std::str::from_utf8(QUORUM_COSIGN_PREFIX).expect("ascii domain");
    let doc = json!({
        "version": 2,
        "description": "SBT credential quorum (OLY:SBT:QUORUM:V2) M-of-N BJJ-EdDSA co-signatures over a credential commit_id. Golden vectors for the differential verifiers; mirror src-tauri/src/quorum/mod.rs (audit R3-01 / L6).",
        "domain": domain,
        "message_construction": "msg = Fr_le(BLAKE3( domain || u32be(len(commit_id_hex))||commit_id_hex || u32be(threshold) || u32be(N) || for each canonical-sorted signer: u32be(len(x))||x||u32be(len(y))||y )). commit_id_hex is the lowercase hex of the 32-byte commit_id, so its u32 length prefix counts the 64 hex CHARACTERS, not the 32 raw bytes; x/y are canonical decimal BN254 field elements; signers are deduped and sorted by (x,y) decimal string; threshold and N are u32 big-endian; Fr_le reduces the 32-byte BLAKE3 digest as a little-endian integer mod the BN254 scalar field r. The signed value is this message under BabyJubJub EdDSA-Poseidon.",
        "commit_id_construction": "commit_id = compute_commit_id(holder_key, credential_type, issued_at_unix, details) per src-tauri/src/api/credentials/crypto.rs (domain OLY:SBT:V1). The quorum message and the offline verifiers consume only the resulting commit_id hex as the opaque bound object; they do NOT recompute it (that is a separate domain).",
        "scheme": "BabyJubJub-EdDSA-Poseidon over BN254",
        "cases": cases,
    });

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let out_path = std::path::Path::new(manifest_dir)
        .join("..")
        .join("verifiers")
        .join("test_vectors")
        .join("sbt_quorum_vectors.json");
    let pretty = serde_json::to_string_pretty(&doc).expect("serialize vectors") + "\n";
    std::fs::write(&out_path, pretty.as_bytes()).unwrap_or_else(|e| {
        panic!("write {}: {e}", out_path.display());
    });
    println!(
        "wrote {} SBT-quorum (V2) cases -> {}",
        doc["cases"].as_array().map(|a| a.len()).unwrap_or(0),
        out_path.display()
    );
}
