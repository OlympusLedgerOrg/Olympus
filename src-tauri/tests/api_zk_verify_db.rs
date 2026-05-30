//! HTTP integration coverage for `POST /zk/verify` (`src-tauri/src/api/zk.rs`).
//!
//! Complements the `zk_prove_*` suite (which exercises real proving +
//! verification with resolved artifacts). These tests pin the **pre-vkey
//! guards** that fire before any verifier is constructed, so they need
//! neither a resolved `proofs_dir` nor a valid proof:
//!
//! * auth gating (401 without a key)
//! * public-signal parse errors (400)
//! * unknown circuit (400)
//! * the audit **H-2** `treeSize == 0` invariant for `document_existence`
//!   and the unified circuit — an inclusion proof with `treeSize == 0`
//!   against a non-empty root must be rejected (400) regardless of whether
//!   the pairing would otherwise check out.
//!
//! Request shape is camelCase: `circuit`, `proofJson` (a JSON *string*),
//! `publicSignals` (decimal-string field elements).

mod common;

use serde_json::{json, Value};

#[tokio::test]
async fn verify_without_auth_is_401() {
    let h = common::boot().await;
    let resp = common::post_json_no_auth(
        &h.client,
        &common::url(h, "/zk/verify"),
        &json!({
            "circuit": "document_existence",
            "proofJson": "{}",
            "publicSignals": ["1", "0", "1"],
        }),
    )
    .await;
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn verify_rejects_malformed_signals() {
    let h = common::boot().await;
    // `parse_signals_slice` fails on a non-numeric signal — 400, before
    // any circuit match or verifier init.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/zk/verify"),
        &h.api_key,
        &json!({
            "circuit": "document_existence",
            "proofJson": "{}",
            "publicSignals": ["not_a_number"],
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn verify_rejects_unknown_circuit() {
    let h = common::boot().await;
    // Signals parse fine; the circuit name has no match arm → 400.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/zk/verify"),
        &h.api_key,
        &json!({
            "circuit": "totally_made_up_circuit",
            "proofJson": "{}",
            "publicSignals": ["1", "2", "3"],
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.expect("JSON");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown circuit"),
        "expected 'unknown circuit' error, got {body}"
    );
}

#[tokio::test]
async fn verify_enforces_h2_empty_tree_invariant_existence() {
    let h = common::boot().await;
    // document_existence signal order: [root, leafIndex, treeSize].
    // treeSize=0 with a non-empty root must be rejected (audit H-2) — this
    // fires before existence_verifier() is built, so no proofs_dir needed.
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/zk/verify"),
        &h.api_key,
        &json!({
            "circuit": "document_existence",
            "proofJson": "{}",
            "publicSignals": ["1", "0", "0"], // root=1 (non-empty), leafIndex=0, treeSize=0
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.expect("JSON");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("treeSize=0"),
        "expected H-2 treeSize=0 rejection, got {body}"
    );
}

#[tokio::test]
async fn verify_enforces_h2_empty_tree_invariant_unified() {
    let h = common::boot().await;
    // unified signal order: [canonicalHash, merkleRoot, ledgerRoot, treeSize].
    // The bounds check is gated on merkleRoot (idx 1) + treeSize (idx 3).
    let resp = common::post_json_with_key(
        &h.client,
        &common::url(h, "/zk/verify"),
        &h.api_key,
        &json!({
            "circuit": "unified_canonicalization_inclusion_root_sign",
            "proofJson": "{}",
            "publicSignals": ["7", "1", "2", "0"], // merkleRoot=1 (non-empty), treeSize=0
        }),
    )
    .await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await.expect("JSON");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("treeSize=0"),
        "expected H-2 treeSize=0 rejection, got {body}"
    );
}
