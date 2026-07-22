//! Admin-gated `GET /api/admin/checkpoints/{id}/bundle` — emit the
//! checkpoint bundle JSON documented in `docs/checkpoint-bundle-schema.md`
//! and referenced by `docs/court-evidence.md` §3.
//!
//! Red-team C1 closure: the documented `node verify.js verify-checkpoint
//! --bundle <bundle.json>` command had no producer. This route reads the
//! `own_checkpoints` row by id, validates its pinned historical signing key and
//! signatures, and returns a v3 bundle with an append-consistency witness.
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

// ── Response schema (v3) ──────────────────────────────────────────────────────
//
// Mirrors `docs/checkpoint-bundle-schema.md`. Field names are
// stable wire format — renaming any of them is a schema bump.

#[derive(Serialize)]
pub struct CheckpointBundle {
    pub schema: &'static str,
    pub checkpoint: CheckpointFields,
    pub bjj_eddsa_poseidon: BjjEddsa,
    pub append_transition: AppendTransitionBlock,
    pub ed25519: Ed25519Block,
    pub anchor_hash: AnchorHashBlock,
    pub groth16: Groth16Block,
}

#[derive(Serialize)]
pub struct AppendTransitionBlock {
    pub scheme: &'static str,
    pub previous_root_hex: String,
    pub current_root: String,
    pub previous_tree_size: String,
    pub current_tree_size: String,
    pub appended_leaf_hex: String,
    pub path: serde_json::Value,
    pub signature: BjjSig,
    pub message: String,
    pub message_doc: &'static str,
}

#[derive(Serialize)]
pub struct CheckpointFields {
    pub id: Uuid,
    pub format_version: String,
    pub checkpoint_scope: String,
    pub shard_id: String,
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

    let (Some(checkpoint_scope), Some(shard_id)) =
        (row.checkpoint_scope.as_deref(), row.shard_id.as_deref())
    else {
        return Err(err(
            StatusCode::CONFLICT,
            "Legacy checkpoint has no authenticated shard scope and cannot be exported as a v3 bundle.",
        ));
    };
    if row.format_version != i16::from(crate::anchoring::CHECKPOINT_FORMAT_VERSION)
        || checkpoint_scope != crate::anchoring::CHECKPOINT_SCOPE_SHARD
    {
        return Err(err(
            StatusCode::CONFLICT,
            "Only explicitly shard-scoped checkpoint format v2 rows can be exported.",
        ));
    }

    // Use the public key pinned on this immutable checkpoint, not the node's
    // current authority key. Historical evidence must remain exportable after
    // a legitimate key rotation.
    let (Some(pk_x), Some(pk_y)) = (
        row.authority_pubkey_x.as_deref(),
        row.authority_pubkey_y.as_deref(),
    ) else {
        return Err(err(
            StatusCode::CONFLICT,
            "Checkpoint predates persisted signing-key coordinates and cannot be exported without historical key metadata.",
        ));
    };
    let pk = crate::zk::witness::baby_jubjub::BabyJubJubPubKey {
        x: crate::zk::proof::parse_fr(pk_x).map_err(|_| {
            err(
                StatusCode::CONFLICT,
                "Stored authority pubkey x is invalid.",
            )
        })?,
        y: crate::zk::proof::parse_fr(pk_y).map_err(|_| {
            err(
                StatusCode::CONFLICT,
                "Stored authority pubkey y is invalid.",
            )
        })?,
    };
    crate::zk::witness::baby_jubjub::validate_pubkey_subgroup(&pk).map_err(|_| {
        err(
            StatusCode::CONFLICT,
            "Stored authority public key is not in the BabyJubJub prime-order subgroup.",
        )
    })?;
    let recomputed_hash = bjj_pubkey_hash_decimal(&pk).map_err(|e| {
        tracing::error!("checkpoint bundle: poseidon(pk) failed: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Pubkey hash failed.")
    })?;
    if recomputed_hash != authority_hash {
        return Err(err(
            StatusCode::CONFLICT,
            "Stored authority_pubkey_hash does not match the checkpoint's pinned signing public key.",
        ));
    }

    let (
        Some(previous_root),
        Some(appended_leaf),
        Some(transition_path),
        Some(transition_r8x),
        Some(transition_r8y),
        Some(transition_s),
    ) = (
        row.transition_original_root.as_deref(),
        row.transition_leaf.as_deref(),
        row.transition_path.as_ref(),
        row.transition_sig_r8x.as_deref(),
        row.transition_sig_r8y.as_deref(),
        row.transition_sig_s.as_deref(),
    )
    else {
        return Err(err(
            StatusCode::CONFLICT,
            "Checkpoint lacks a complete signed append-consistency witness.",
        ));
    };
    let transition_message = crate::anchoring::own_checkpoint::verify_append_transition(
        previous_root,
        appended_leaf,
        transition_path,
        &row.ledger_root,
        row.tree_size,
        &pk,
        (transition_r8x, transition_r8y, transition_s),
    )
    .map_err(|e| {
        tracing::error!("checkpoint bundle: invalid append transition: {e}");
        err(
            StatusCode::CONFLICT,
            "Checkpoint append-consistency witness is invalid.",
        )
    })?;

    let ledger_root_fr = crate::zk::proof::parse_fr(&row.ledger_root).map_err(|e| {
        tracing::error!("checkpoint bundle: stored ledger root is invalid: {e}");
        err(
            StatusCode::CONFLICT,
            "Stored ledger root is not canonical decimal Fr.",
        )
    })?;
    if fr_to_decimal(&ledger_root_fr) != row.ledger_root {
        return Err(err(
            StatusCode::CONFLICT,
            "Stored ledger root is not canonical decimal Fr.",
        ));
    }
    let authority_hash_fr = crate::zk::proof::parse_fr(authority_hash).map_err(|e| {
        tracing::error!("checkpoint bundle: stored authority hash is invalid: {e}");
        err(
            StatusCode::CONFLICT,
            "Stored authority hash is not canonical decimal Fr.",
        )
    })?;
    let signed_message = crate::anchoring::checkpoint_signing_message_v2(
        checkpoint_scope,
        shard_id,
        &ledger_root_fr,
        row.tree_size,
        row.checkpoint_timestamp,
        &authority_hash_fr,
    );
    let parse_checkpoint_sig = |name: &str, value: &str| {
        let parsed = crate::zk::proof::parse_fr(value).map_err(|_| {
            err(
                StatusCode::CONFLICT,
                &format!("Stored checkpoint signature {name} is invalid."),
            )
        })?;
        if fr_to_decimal(&parsed) != value {
            return Err(err(
                StatusCode::CONFLICT,
                &format!("Stored checkpoint signature {name} is not canonical decimal."),
            ));
        }
        Ok(parsed)
    };
    let checkpoint_signature = crate::zk::witness::baby_jubjub::BabyJubJubSignature {
        r8x: parse_checkpoint_sig("r8x", r8x)?,
        r8y: parse_checkpoint_sig("r8y", r8y)?,
        s: parse_checkpoint_sig("s", s)?,
    };
    if !crate::zk::witness::baby_jubjub::verify_signature(
        &pk,
        &checkpoint_signature,
        signed_message,
    ) {
        return Err(err(
            StatusCode::CONFLICT,
            "Stored checkpoint BJJ signature does not verify under its pinned authority key.",
        ));
    }
    let recomputed_anchor_hash = crate::anchoring::checkpoint_anchor_hash_v2(
        checkpoint_scope,
        shard_id,
        &row.ledger_root,
        row.tree_size,
        row.checkpoint_timestamp,
        authority_hash,
        Some(r8x),
        Some(r8y),
        Some(s),
    );
    if recomputed_anchor_hash != row.anchor_hash {
        return Err(err(
            StatusCode::CONFLICT,
            "Stored checkpoint anchor hash does not match its signed statement.",
        ));
    }

    let ed_pubkey_bytes: [u8; 32] = hex::decode(ed_pk)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| {
            err(
                StatusCode::CONFLICT,
                "Stored Ed25519 public key is invalid.",
            )
        })?;
    let ed_signature_bytes: [u8; 64] = hex::decode(ed_sig)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| err(StatusCode::CONFLICT, "Stored Ed25519 signature is invalid."))?;
    if hex::encode(ed_pubkey_bytes) != ed_pk || hex::encode(ed_signature_bytes) != ed_sig {
        return Err(err(
            StatusCode::CONFLICT,
            "Stored Ed25519 key or signature is not canonical lowercase hexadecimal.",
        ));
    }
    let ed_verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&ed_pubkey_bytes).map_err(|_| {
            err(
                StatusCode::CONFLICT,
                "Stored Ed25519 public key is invalid.",
            )
        })?;
    let ed_signature = ed25519_dalek::Signature::from_bytes(&ed_signature_bytes);
    ed_verifying_key
        .verify_strict(&row.anchor_hash, &ed_signature)
        .map_err(|_| {
            err(
                StatusCode::CONFLICT,
                "Stored Ed25519 signature does not verify over the checkpoint anchor hash.",
            )
        })?;

    Ok(Json(CheckpointBundle {
        schema: "olympus-checkpoint-bundle/v3",
        checkpoint: CheckpointFields {
            id: row.id,
            format_version: row.format_version.to_string(),
            checkpoint_scope: checkpoint_scope.to_owned(),
            shard_id: shard_id.to_owned(),
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
            message: fr_to_decimal(&signed_message),
            message_doc: "BJJ-EdDSA signs Fr_le(BLAKE3(OLY:CHECKPOINT:STATEMENT:V2 || \
                 version || lp(scope) || lp(shard_id) || lp(ledger_root_dec) || \
                 tree_size_i64be || checkpoint_timestamp_i64be || \
                 lp(authority_pubkey_hash_dec))). Verify with iden3 BJJ EdDSA-Poseidon: \
                 8·S·B == 8·R + 8·Poseidon(R,A,M)·A.",
        },
        append_transition: AppendTransitionBlock {
            scheme: "Poseidon-one-leaf-append + BabyJubJub-EdDSA",
            previous_root_hex: previous_root.to_owned(),
            current_root: row.ledger_root.clone(),
            previous_tree_size: row.tree_size.saturating_sub(1).to_string(),
            current_tree_size: row.tree_size.to_string(),
            appended_leaf_hex: appended_leaf.to_owned(),
            path: transition_path.clone(),
            signature: BjjSig {
                r8x: transition_r8x.to_owned(),
                r8y: transition_r8y.to_owned(),
                s: transition_s.to_owned(),
            },
            message: fr_to_decimal(&transition_message),
            message_doc: "Fold zero and appended_leaf over path to reconstruct previous/current roots; BJJ-EdDSA signs reduce_mod_l(BLAKE3(OLY:SNAPSHOT:PERSIST:V1 || lp(previous_root_be32) || lp(current_root_be32) || lp(current_tree_size_u64be))).",
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
            domain: "OLY:CHECKPOINT_ANCHOR:V2",
            value_hex: hex::encode(row.anchor_hash),
            recompute_doc: "BLAKE3(OLY:CHECKPOINT_ANCHOR:V2 || version_u8 || lp(scope) || \
                 lp(shard_id) || lp(ledger_root_dec) || tree_size_i64be || \
                 checkpoint_timestamp_i64be || lp(authority_pubkey_hash_dec) || \
                 lp(sig_r8x_dec) || lp(sig_r8y_dec) || lp(sig_s_dec)). See \
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
