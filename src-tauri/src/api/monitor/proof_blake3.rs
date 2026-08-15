// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! `GET /monitor/proof/blake3/{content_hash}` — ADR-0044 follow-up: serves a
//! BLAKE3 CD-HS-ST parser-bound SMT membership proof against the shard's
//! signed `SmtRootAttestation`, closing the gap `monitor::proof` (the
//! Poseidon witness endpoint) explicitly left open — "nothing signs the
//! BLAKE3 tree's root" is no longer true as of ADR-0044, and
//! `PersistentSmt::prove` finally has a production caller.
//!
//! Serves the proof against the shard's **subtree** root
//! (`PersistentSmt::shard_subtree_root`), the root `SmtRootAttestation`
//! actually signs — not the tree's global 256-depth root `prove()`'s own
//! `root_hash` field carries. `server_reports_valid` is therefore computed
//! via `olympus_crypto::smt::verify_*_proof_against_shard_root`, which folds
//! only the leaf-side 192 siblings, not the full-depth verifiers
//! `monitor::proof` module doc still correctly uses for the Poseidon tree.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use olympus_crypto::smt::{
    verify_existence_proof_against_shard_root, verify_nonexistence_proof_against_shard_root, Proof,
};
use olympus_crypto::trust_list::TrustRole;

use crate::anchoring::{self, own_checkpoint};
use crate::api::ingest::snapshot_evidence::fetch_record_identity_row;
use crate::api::middleware::auth::RateLimit;
use crate::api::trusted_issuers::issuers_for_role;
use crate::smt::{PersistentSmt, PgBackend};
use crate::state::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

fn hex_to_bytes32(h: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(h).map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored blake3_smt_root is not valid hex.",
        )
    })?;
    bytes.try_into().map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored blake3_smt_root is not 32 bytes.",
        )
    })
}

/// The raw evidence for one committed record's BLAKE3 SMT membership, ready
/// for fully offline verification against
/// `olympus_crypto::smt::verify_proof_against_shard_root` — a caller needs
/// nothing else from this server. `proof` is the *full* 256-sibling proof as
/// produced by `PersistentSmt::prove` (untruncated — truncation to the
/// shard-scoped 192 siblings happens at verify time, not here, so this stays
/// self-describing and directly reusable for other purposes).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorBlake3ProofResponse {
    pub content_hash: String,
    pub shard_id: String,
    pub proof: Proof,
    /// The `own_checkpoints.id` this proof is anchored to.
    pub checkpoint_id: String,
    /// The signed shard-subtree root the proof verifies against — NOT
    /// `proof`'s own embedded `root_hash` (the tree's global root).
    pub blake3_smt_root: String,
    pub ledger_root: String,
    pub tree_size: i64,
    pub signature_r8x: String,
    pub signature_r8y: String,
    pub signature_s: String,
    /// Whether this server's own trusted-issuer set verifies the attestation
    /// signature AND the proof folds to the attested shard root. A monitor
    /// should not need to trust this field — it can and should recompute it
    /// — but it lets a client fast-path the common case.
    pub server_reports_valid: bool,
}

pub(super) async fn get_blake3_proof(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(content_hash): Path<String>,
) -> Result<Json<MonitorBlake3ProofResponse>, ApiError> {
    let content_hash = content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let identity = fetch_record_identity_row(pool, &content_hash)
        .await
        .map_err(|e| {
            tracing::error!("monitor: get_blake3_proof: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "content_hash is not present in the ledger.",
            )
        })?;

    // Reject a negative version rather than coercing it — a data-integrity
    // impossibility (ingest already refuses these, `parser_smt.rs`), not a
    // client error, so this is a 500 rather than a 422.
    let version_u64 = u64::try_from(identity.version).map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored record has a negative version; cannot address the parser-SMT tree.",
        )
    })?;
    let rk = olympus_crypto::record_key(&identity.record_type, &identity.record_id, version_u64);
    let key = olympus_crypto::smt::shard_record_key(&identity.shard_id, &rk);

    let tree = PersistentSmt::open_deferred(PgBackend::new(pool.clone()));
    let proof = tree.prove(&key).await.map_err(|e| {
        tracing::error!("monitor: get_blake3_proof: prove failed: {e}");
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to build the SMT membership proof.",
        )
    })?;

    let checkpoint = own_checkpoint::latest_smt_attestation_for_shard(
        pool,
        anchoring::CHECKPOINT_SCOPE_SHARD,
        &identity.shard_id,
    )
    .await
    .map_err(|e| {
        tracing::error!("monitor: get_blake3_proof: {e}");
        err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
    })?
    .ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "No BLAKE3 SMT root attestation exists yet for this shard — the checkpoint \
             producer hasn't signed a root covering it. See GET /monitor/proof/{content_hash} \
             for the Poseidon witness in the meantime.",
        )
    })?;

    // `latest_smt_attestation_for_shard`'s WHERE clause requires all four of
    // these to be non-NULL, so this is unreachable in practice — fail closed
    // with a clear 500 rather than panic if that invariant is ever violated.
    let (Some(blake3_smt_root), Some(sig_r8x), Some(sig_r8y), Some(sig_s)) = (
        checkpoint.blake3_smt_root.as_deref(),
        checkpoint.blake3_smt_sig_r8x.as_deref(),
        checkpoint.blake3_smt_sig_r8y.as_deref(),
        checkpoint.blake3_smt_sig_s.as_deref(),
    ) else {
        tracing::error!(
            "monitor: get_blake3_proof: checkpoint {} matched the attestation query but is \
             missing an attestation field",
            checkpoint.id
        );
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Checkpoint attestation is unexpectedly incomplete.",
        ));
    };

    let shard_root_bytes = hex_to_bytes32(blake3_smt_root)?;
    let proof_folds_to_shard_root = match &proof {
        Proof::Existence(p) => {
            verify_existence_proof_against_shard_root(p, &identity.shard_id, &shard_root_bytes)
        }
        Proof::NonExistence(p) => {
            verify_nonexistence_proof_against_shard_root(p, &identity.shard_id, &shard_root_bytes)
        }
    };

    // Same trust-anchor policy as `monitor::proof`: every CheckpointAuthority-
    // role trusted issuer, window-checked at the checkpoint's own timestamp.
    let attestation_signature_valid = !state.bjj_trusted_issuers.is_empty()
        && issuers_for_role(&state.bjj_trusted_issuers, TrustRole::CheckpointAuthority)
            .filter(|issuer| issuer.covers(checkpoint.checkpoint_timestamp))
            .any(|issuer| {
                own_checkpoint::verify_smt_root_attestation(
                    &identity.shard_id,
                    &checkpoint.ledger_root,
                    checkpoint.tree_size,
                    blake3_smt_root,
                    &issuer.pubkey,
                    (sig_r8x, sig_r8y, sig_s),
                )
                .is_ok()
            });

    Ok(Json(MonitorBlake3ProofResponse {
        content_hash,
        shard_id: identity.shard_id,
        proof,
        checkpoint_id: checkpoint.id.to_string(),
        blake3_smt_root: blake3_smt_root.to_owned(),
        ledger_root: checkpoint.ledger_root,
        tree_size: checkpoint.tree_size,
        signature_r8x: sig_r8x.to_owned(),
        signature_r8y: sig_r8y.to_owned(),
        signature_s: sig_s.to_owned(),
        server_reports_valid: proof_folds_to_shard_root && attestation_signature_valid,
    }))
}
