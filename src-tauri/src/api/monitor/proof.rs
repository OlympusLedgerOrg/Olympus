// SPDX-FileCopyrightText: 2026 Olympus Contributors
// SPDX-License-Identifier: Apache-2.0

//! `GET /monitor/proof/{content_hash}` — ADR-0021 Monitor API
//! "get-proof-by-hash" equivalent: the raw, offline-verifiable Poseidon
//! ledger-snapshot inclusion witness for a committed record.
//!
//! Reuses `api::ingest::snapshot_evidence` (the exact row-fetch and JSON
//! parsing `POST /ingest/proofs/verify` uses) so this endpoint and that one
//! can never disagree about what a stored snapshot means — this one just
//! returns the witness itself instead of only a verdict.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use olympus_crypto::ledger_snapshot::verify_snapshot;

use crate::api::ingest::snapshot_evidence::{fetch_snapshot_row, parse_stored_snapshot};
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

/// The raw evidence for one committed record, ready for fully offline
/// verification against `olympus_crypto::ledger_snapshot::verify_snapshot`
/// (or the independent `verifiers/rust` / `verifiers/javascript`
/// reimplementations) — a caller needs nothing else from this server.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonitorProofResponse {
    pub content_hash: String,
    pub proof_id: String,
    pub shard_id: String,
    /// The snapshot leaf — this record's own chunk-tree root, in canonical
    /// `fr_to_hex` form. The value `verify_snapshot`'s `original_root`
    /// parameter expects.
    pub original_root: String,
    pub snapshot_root: String,
    pub snapshot_index: u64,
    pub snapshot_size: u64,
    /// `SNAPSHOT_DEPTH` (20) sibling hashes, leaf→root order.
    pub path_elements_hex: Vec<String>,
    /// `SNAPSHOT_DEPTH` direction bits (0 = left child at that level).
    pub path_indices: Vec<u8>,
    pub signature_r8x: String,
    pub signature_r8y: String,
    pub signature_s: String,
    /// Present for a V2 (timestamped) snapshot; `None` for a legacy V1 row
    /// with no signature-covered signing time.
    pub signed_at_unix: Option<i64>,
    /// Whether this server's own trusted-issuer set (the
    /// `CheckpointAuthority`-role entries `POST /ingest/proofs/verify` also
    /// checks) verifies this witness. A monitor should not need to trust
    /// this field — it can and should recompute it — but it is included so a
    /// client can fast-path the common case and only fall back to full
    /// offline verification when it disagrees.
    pub server_reports_valid: bool,
}

pub(super) async fn get_proof(
    State(state): State<AppState>,
    _rl: RateLimit,
    Path(content_hash): Path<String>,
) -> Result<Json<MonitorProofResponse>, ApiError> {
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

    let row = fetch_snapshot_row(pool, &content_hash)
        .await
        .map_err(|e| {
            tracing::error!("monitor: get_proof: {e}");
            err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
        })?
        .ok_or_else(|| {
            err(
                StatusCode::NOT_FOUND,
                "content_hash is not present in the ledger.",
            )
        })?;

    if row.snapshot_sig_legacy {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record carries a pre-BJJ (Ed25519-era) snapshot signature this Monitor API \
             cannot serve as a verifiable witness. See POST /ingest/proofs/verify for detail.",
        ));
    }

    let (original_root, snapshot_root, snapshot_index, snapshot_size, snapshot_path, snapshot_sig) =
        match (
            row.original_root,
            row.snapshot_root,
            row.snapshot_index,
            row.snapshot_size,
            row.snapshot_path,
            row.snapshot_sig,
        ) {
            (Some(or), Some(sr), Some(si), Some(sz), Some(sp), Some(sg)) => {
                (or, sr, si, sz, sp, sg)
            }
            _ => {
                return Err(err(
                    StatusCode::SERVICE_UNAVAILABLE,
                    crate::api::ingest::snapshot_evidence::pending_detail(&row.record_type),
                ))
            }
        };

    let snapshot = parse_stored_snapshot(
        &snapshot_root,
        snapshot_index,
        snapshot_size,
        &snapshot_path,
        &snapshot_sig,
    )
    .map_err(|detail| {
        tracing::error!(
            content_hash = %content_hash,
            "monitor: get_proof: stored snapshot is malformed: {detail}"
        );
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored snapshot evidence is malformed — refusing to serve a broken witness.",
        )
    })?;

    // Same trust-anchor policy as `POST /ingest/proofs/verify`: every
    // CheckpointAuthority-role trusted issuer, window-checked at the
    // witness's own authenticated signing time when it has one.
    let server_reports_valid = !state.bjj_trusted_issuers.is_empty()
        && crate::api::trusted_issuers::issuers_for_role(
            &state.bjj_trusted_issuers,
            olympus_crypto::trust_list::TrustRole::CheckpointAuthority,
        )
        .filter(|issuer| snapshot.signed_at_unix.is_none_or(|t| issuer.covers(t)))
        .any(|issuer| {
            verify_snapshot(
                &snapshot,
                &content_hash,
                &original_root,
                issuer.pubkey.x,
                issuer.pubkey.y,
            )
        });

    Ok(Json(MonitorProofResponse {
        content_hash,
        proof_id: row.proof_id,
        shard_id: row.shard_id,
        original_root,
        snapshot_root: snapshot.snapshot_root,
        snapshot_index: snapshot.snapshot_index,
        snapshot_size: snapshot.snapshot_size,
        path_elements_hex: snapshot.path_elements_hex,
        path_indices: snapshot.path_indices,
        signature_r8x: snapshot.signature_r8x,
        signature_r8y: snapshot.signature_r8y,
        signature_s: snapshot.signature_s,
        signed_at_unix: snapshot.signed_at_unix,
        server_reports_valid,
    }))
}
