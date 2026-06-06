//! Admin-gated `GET /api/admin/checkpoints/{id}/bundle` — emit the
//! checkpoint bundle JSON documented in `docs/checkpoint-bundle-schema.md`
//! and referenced by `docs/court-evidence.md` §3.
//!
//! Red-team C1 closure: the documented `node verify.js verify-checkpoint
//! --bundle <bundle.json>` command had no producer. This route reads the
//! `own_checkpoints` row by id, re-derives the BJJ pubkey coordinates
//! from the AppState authority key (so the bundle includes raw `(Ax,Ay)`
//! the JS verifier can plug into the EdDSA-Poseidon verify formula), and
//! returns a v1 bundle.json.
//!
//! All cryptographic fields the JS verifier hashes/signs are returned as
//! strings (decimal Fr or lowercase hex). Numeric fields the cryptography
//! commits to are NEVER serialised as JSON numbers — IEEE-754 would
//! round-trip ledger_root or tree_size incorrectly through JS BigInt.

use ark_ff::PrimeField;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::get,
    Json, Router,
};
use num_bigint::BigUint;
use serde::Serialize;
use uuid::Uuid;

use crate::state::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

// ── Response schema (v1) ──────────────────────────────────────────────────────
//
// Mirrors `docs/checkpoint-bundle-schema.md`. Field names are
// stable wire format — renaming any of them is a schema bump.

#[derive(Serialize)]
pub struct CheckpointBundle {
    pub schema: &'static str,
    pub checkpoint: CheckpointFields,
    pub bjj_eddsa_poseidon: BjjEddsa,
    pub ed25519: Ed25519Block,
    pub anchor_hash: AnchorHashBlock,
    pub groth16: Groth16Block,
}

#[derive(Serialize)]
pub struct CheckpointFields {
    pub id: Uuid,
    pub ledger_root: String,
    pub tree_size: String,
    pub checkpoint_timestamp: String,
    pub authority_pubkey_hash: String,
}

#[derive(Serialize)]
pub struct BjjEddsa {
    pub scheme: &'static str,
    pub pubkey: BjjPubkey,
    pub signature: BjjSig,
    pub message: String,
    pub message_doc: &'static str,
}

#[derive(Serialize)]
pub struct BjjPubkey {
    pub x: String,
    pub y: String,
}

#[derive(Serialize)]
pub struct BjjSig {
    pub r8x: String,
    pub r8y: String,
    pub s: String,
}

#[derive(Serialize)]
pub struct Ed25519Block {
    pub scheme: &'static str,
    pub pubkey_hex: String,
    pub signature_hex: String,
    pub message_hex: String,
    pub message_doc: &'static str,
}

#[derive(Serialize)]
pub struct AnchorHashBlock {
    pub algorithm: &'static str,
    pub domain: &'static str,
    pub value_hex: String,
    pub recompute_doc: &'static str,
}

#[derive(Serialize)]
pub struct Groth16Block {
    pub scheme: &'static str,
    pub circuit: &'static str,
    pub vkey_ref: &'static str,
    pub proof: serde_json::Value,
    pub public_signals: serde_json::Value,
}

// ── Handler ───────────────────────────────────────────────────────────────────

async fn get_checkpoint_bundle(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<CheckpointBundle>, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    crate::api::middleware::auth::require_admin_auth(&headers, pool, &state.bjj_trusted_issuers)
        .await?;

    let row = crate::anchoring::own_checkpoint::fetch_by_id(pool, id)
        .await
        .map_err(|e| {
            tracing::error!("checkpoint bundle: fetch_by_id {id}: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
        })?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "Checkpoint not found."))?;

    // Reject if any required signed-field is missing — court bundle
    // semantics require every layer; a partial bundle would silently
    // fail one of the JS verifier's four checks.
    let (Some(authority_hash), Some(r8x), Some(r8y), Some(s), Some(ed_pk), Some(ed_sig)) = (
        row.authority_pubkey_hash.as_deref(),
        row.sig_r8x.as_deref(),
        row.sig_r8y.as_deref(),
        row.sig_s.as_deref(),
        row.ed25519_pubkey_hex.as_deref(),
        row.ed25519_signature_hex.as_deref(),
    ) else {
        return Err(err(
            StatusCode::CONFLICT,
            "Checkpoint is incomplete (missing BJJ or Ed25519 signature). \
             Bundles require both signature layers; this row was emitted \
             before OLYMPUS_INGEST_SIGNING_KEY / BJJ authority key was \
             configured.",
        ));
    };

    let (Some(proof), Some(signals)) = (row.groth16_proof.as_ref(), row.public_signals.as_ref())
    else {
        return Err(err(
            StatusCode::CONFLICT,
            "Checkpoint has no Groth16 proof. Bundles require a complete \
             document_existence proof; this row was emitted before \
             OLYMPUS_PROOFS_DIR was configured / setup_circuits.sh ran.",
        ));
    };

    // Re-derive BJJ (Ax, Ay) from the in-memory authority key and assert
    // they hash to `authority_pubkey_hash` — defence in depth: a tampered
    // own_checkpoints row whose authority_pubkey_hash disagrees with the
    // current authority key is refused rather than silently emit a
    // mis-matched pubkey in the bundle.
    let pk = state.bjj_authority_pubkey.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority key not loaded; cannot emit bundle.",
        )
    })?;
    let recomputed_hash = bjj_pubkey_hash_decimal(&pk).map_err(|e| {
        tracing::error!("checkpoint bundle: poseidon(pk) failed: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Pubkey hash failed.")
    })?;
    if recomputed_hash != authority_hash {
        return Err(err(
            StatusCode::CONFLICT,
            "Stored authority_pubkey_hash does not match the current BJJ \
             authority key. The signing identity has rotated since this \
             checkpoint was emitted; bundle export refuses to substitute \
             pubkey coords from a different key.",
        ));
    }

    Ok(Json(CheckpointBundle {
        schema: "olympus-checkpoint-bundle/v1",
        checkpoint: CheckpointFields {
            id: row.id,
            ledger_root: row.ledger_root.clone(),
            tree_size: row.tree_size.to_string(),
            checkpoint_timestamp: row.checkpoint_timestamp.to_string(),
            authority_pubkey_hash: authority_hash.to_owned(),
        },
        bjj_eddsa_poseidon: BjjEddsa {
            scheme: "BabyJubJub-EdDSA-Poseidon",
            pubkey: BjjPubkey {
                x: fr_to_decimal(&pk.x),
                y: fr_to_decimal(&pk.y),
            },
            signature: BjjSig {
                r8x: r8x.to_owned(),
                r8y: r8y.to_owned(),
                s: s.to_owned(),
            },
            // The BJJ EdDSA-Poseidon "message" in the federation flow is
            // exactly the Poseidon snapshot root (ledger_root). Documented
            // here verbatim so the JS verifier doesn't have to guess.
            message: row.ledger_root.clone(),
            message_doc: "Poseidon BJJ-EdDSA signs `ledger_root` (the Poseidon snapshot \
                 root, decimal Fr). Verify with iden3 BJJ EdDSA-Poseidon: \
                 8·S·B == 8·R + 8·Poseidon(R,A,M)·A.",
        },
        ed25519: Ed25519Block {
            scheme: "Ed25519 (RFC 8032)",
            pubkey_hex: ed_pk.to_owned(),
            signature_hex: ed_sig.to_owned(),
            message_hex: hex::encode(row.anchor_hash),
            message_doc: "Ed25519 signs `anchor_hash`. Verify with any RFC 8032 \
                 implementation: ed25519_verify(pubkey, signature, anchor_hash).",
        },
        anchor_hash: AnchorHashBlock {
            algorithm: "BLAKE3",
            domain: "OLY:CHECKPOINT_ANCHOR:V1",
            value_hex: hex::encode(row.anchor_hash),
            recompute_doc: "BLAKE3(OLY:CHECKPOINT_ANCHOR:V1 | '|' | ledger_root_utf8 | '|' | \
                 tree_size_be_8 | '|' | checkpoint_timestamp_be_8 | '|' | \
                 authority_pubkey_hash_utf8 | '|' | sig_r8x_utf8 | '|' | \
                 sig_r8y_utf8 | '|' | sig_s_utf8). See \
                 docs/checkpoint-bundle-schema.md.",
        },
        groth16: Groth16Block {
            scheme: "Groth16 over BN254 (snarkjs format)",
            circuit: "document_existence",
            vkey_ref: "proofs/keys/verification_keys/document_existence_vkey.json",
            proof: proof.clone(),
            public_signals: serde_json::Value::Array(
                signals
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        },
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

use crate::zk::proof::fr_to_decimal;

/// `Poseidon(Ax, Ay)` over BN254, returned as decimal Fr — reuses
/// `BabyJubJubPubKey::authority_hash` so the bundle producer cannot
/// drift from the signer / federation verifier on Poseidon parameters.
fn bjj_pubkey_hash_decimal(
    pk: &crate::zk::witness::baby_jubjub::BabyJubJubPubKey,
) -> Result<String, String> {
    let hash = pk
        .authority_hash()
        .map_err(|e| format!("authority_hash: {e}"))?;
    Ok(fr_to_decimal(&hash))
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/api/admin/checkpoints/{id}/bundle",
        get(get_checkpoint_bundle),
    )
}
