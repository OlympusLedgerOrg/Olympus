//! Cross-crate parity test: signer (src-tauri) ↔ verifier (olympus-crypto).
//!
//! The desktop crate produces a `LedgerSnapshot` via BJJ EdDSA-Poseidon
//! signing; `olympus-crypto::ledger_snapshot::verify_snapshot` is the
//! standalone relying-party verifier. The two implement the same digest
//! and signature wire format independently — without an end-to-end test
//! a silent drift (a tweaked domain tag, a swapped fold order, a different
//! Fr→BigInt convention) would only show up at runtime when real verify
//! requests started rejecting real signatures.
//!
//! This test produces a real snapshot in src-tauri's signer, hands the
//! result to the verifier crate, and asserts acceptance — plus negative
//! controls so any "always-true" mutation in the verifier dies too.

use ark_bn254::Fr;
use ark_ff::PrimeField;

// Reach the desktop's helpers via the library crate.
use olympus_tauri_lib::zk::chunk::{chunk_tree_from_bytes, fr_to_hex};
use olympus_tauri_lib::zk::snapshot::snapshot_new_record;
use olympus_tauri_lib::zk::witness::baby_jubjub::BabyJubJubPubKey;

use olympus_crypto::ledger_snapshot::{verify_snapshot, LedgerSnapshot as VerifierSnapshot};

/// Translate the desktop's signed `LedgerSnapshot` into the verifier crate's
/// shape (same fields, different type because each crate owns its own struct).
fn to_verifier_shape(
    snap: &olympus_tauri_lib::zk::snapshot::LedgerSnapshot,
) -> VerifierSnapshot {
    VerifierSnapshot {
        snapshot_root: snap.snapshot_root.clone(),
        snapshot_index: snap.snapshot_index,
        snapshot_size: snap.snapshot_size,
        path_elements_hex: snap.path_elements_hex.clone(),
        path_indices: snap.path_indices.clone(),
        signature_r8x: snap.signature_r8x.clone(),
        signature_r8y: snap.signature_r8y.clone(),
        signature_s: snap.signature_s.clone(),
    }
}

#[test]
fn desktop_signer_verifies_in_olympus_crypto() {
    // Deterministic 32-byte key — well-formed for babyjubjub-rs.
    let bjj_priv: [u8; 32] = [
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f, 0x40,
    ];
    let pubkey = BabyJubJubPubKey::from_private(&bjj_priv).expect("pubkey");

    // Build a small but realistic snapshot: a few prior leaves so the path is
    // exercised non-trivially, plus a real chunk-tree root for the new leaf.
    let prior: Vec<Fr> = (0..3).map(|i| Fr::from(i as u64 + 100)).collect();
    let tree = chunk_tree_from_bytes(b"cross-crate parity doc").expect("chunk tree");
    let content_hash = "5a".repeat(32);
    let original_root_hex = fr_to_hex(tree.original_root);

    let snap = snapshot_new_record(
        &bjj_priv,
        &prior,
        tree.original_root,
        prior.len() as u64,
        &content_hash,
        &original_root_hex,
    )
    .expect("sign snapshot");

    // Authority pubkey comes from the same priv key — verifier needs (x, y).
    let v_snap = to_verifier_shape(&snap);
    assert!(
        verify_snapshot(&v_snap, &content_hash, &original_root_hex, pubkey.x, pubkey.y),
        "olympus-crypto verifier must accept a snapshot produced by src-tauri's signer; \
         signer/verifier digest or signature shape have drifted",
    );

    // Negative: wrong content_hash → digest changes → reject.
    assert!(!verify_snapshot(
        &v_snap,
        &"99".repeat(32),
        &original_root_hex,
        pubkey.x,
        pubkey.y,
    ));

    // Negative: wrong pubkey → reject.
    let imposter_priv: [u8; 32] = [0x77; 32];
    let imposter = BabyJubJubPubKey::from_private(&imposter_priv).unwrap();
    assert!(!verify_snapshot(
        &v_snap,
        &content_hash,
        &original_root_hex,
        imposter.x,
        imposter.y,
    ));

    // Negative: tamper with snapshot_root → path no longer reconstructs.
    let mut tampered = v_snap.clone();
    tampered.snapshot_root = "00".repeat(32);
    assert!(!verify_snapshot(
        &tampered,
        &content_hash,
        &original_root_hex,
        pubkey.x,
        pubkey.y,
    ));

    // Sanity: the path the desktop produces is exactly SNAPSHOT_DEPTH long —
    // catches a future refactor that accidentally truncates or pads it.
    use olympus_crypto::ledger_snapshot::SNAPSHOT_DEPTH;
    assert_eq!(v_snap.path_elements_hex.len(), SNAPSHOT_DEPTH);
    assert_eq!(v_snap.path_indices.len(), SNAPSHOT_DEPTH);

    // Bonus: snapshot fields parse as valid 32-byte BE hex Fr — catches an
    // accidental encoding change (e.g. LE vs BE, length-prefixed, decimal).
    for h in [
        &v_snap.snapshot_root,
        &v_snap.signature_r8x,
        &v_snap.signature_r8y,
        &v_snap.signature_s,
    ] {
        let bytes = hex::decode(h).expect("hex");
        assert_eq!(bytes.len(), 32, "snapshot fields must be 32-byte BE hex");
        // Reduction never panics for any 32-byte input.
        let _: Fr = Fr::from_be_bytes_mod_order(&bytes);
    }
}
