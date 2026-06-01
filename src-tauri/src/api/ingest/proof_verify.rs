//! `POST /ingest/proofs/verify` — offline snapshot proof-bundle verification.
//! Split out of the ingest module.

use axum::{
    extract::State,
    http::StatusCode,
    Json,
};

use super::*;
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

// ── Route: POST /ingest/proofs/verify ────────────────────────────────────────

pub(super) async fn verify_proof_bundle(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<ProofVerifyRequest>,
) -> Result<Json<ProofVerifyResponse>, ApiError> {
    use olympus_crypto::ledger_snapshot::{verify_snapshot, LedgerSnapshot as CryptoSnapshot};

    let content_hash = body.content_hash.trim().to_lowercase();
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

    // Pull the row + every snapshot column in one go. NULL snapshot columns
    // mean the record exists but the inclusion witness hasn't been built
    // (legacy rows from pre-migration-0029 or the removed pre-H-5 JSON
    // commit path — new ingests through /ingest/files always populate the
    // snapshot atomically with the row INSERT). That's `Pending`, NOT
    // `Invalid`.
    #[derive(sqlx::FromRow)]
    struct Row {
        proof_id: String,
        record_type: String,
        original_root: Option<String>,
        snapshot_root: Option<String>,
        snapshot_index: Option<i64>,
        snapshot_size: Option<i64>,
        snapshot_path: Option<serde_json::Value>,
        snapshot_sig: Option<String>,
        snapshot_sig_legacy: bool,
    }
    let row_opt: Option<Row> = sqlx::query_as::<_, Row>(
        // Audit A1: earliest-wins — content_hash is per-shard unique only.
        "SELECT proof_id, record_type, original_root, snapshot_root, snapshot_index, \
                snapshot_size, snapshot_path, snapshot_sig, snapshot_sig_legacy \
         FROM ingest_records WHERE content_hash = $1 \
         ORDER BY ts ASC, proof_id ASC LIMIT 1",
    )
    .bind(&content_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // Helper to assemble a response — keeps the legacy fields populated from
    // the new authoritative ones so existing clients don't 500.
    #[allow(clippy::too_many_arguments)] // wide ProofVerifyResponse shape; refactoring out of scope here
    fn build(
        body_proof_id: Option<String>,
        row_proof_id: Option<String>,
        content_hash: String,
        status: SnapshotVerifyStatus,
        detail: &str,
        snapshot_root: Option<String>,
        snapshot_index: Option<u64>,
        snapshot_size: Option<u64>,
    ) -> ProofVerifyResponse {
        let merkle_proof_valid = match status {
            SnapshotVerifyStatus::Verified => Some(true),
            SnapshotVerifyStatus::Invalid => Some(false),
            SnapshotVerifyStatus::Pending | SnapshotVerifyStatus::Unknown => None,
        };
        let known_to_server = row_proof_id.is_some();
        let merkle_root = snapshot_root.clone().unwrap_or_else(zero_root);
        ProofVerifyResponse {
            proof_id: body_proof_id.or(row_proof_id),
            content_hash,
            status,
            detail: detail.to_owned(),
            known_to_server,
            snapshot_root: snapshot_root.clone(),
            snapshot_index,
            snapshot_size,
            merkle_proof_valid,
            merkle_root,
            poseidon_root: snapshot_root,
        }
    }

    let row = match row_opt {
        Some(r) => r,
        None => {
            return Ok(Json(build(
                body.proof_id,
                None,
                content_hash,
                SnapshotVerifyStatus::Unknown,
                "content_hash is not present in the ledger.",
                None,
                None,
                None,
            )));
        }
    };

    // Legacy Ed25519-era snapshot: the attestation bytes are preserved on
    // disk (so a future operator restoring the old authority pubkey can
    // cross-check offline) but the current BJJ verifier can't validate
    // them. Surface as pending with a clear reason so clients don't
    // misread it as a cryptographic failure.
    if row.snapshot_sig_legacy {
        return Ok(Json(build(
            body.proof_id,
            Some(row.proof_id),
            content_hash,
            SnapshotVerifyStatus::Pending,
            "Record carries a pre-BJJ (Ed25519-era) snapshot signature that the current \
             verifier cannot validate. The attestation data is preserved; the record will \
             need to be re-snapshotted under the BJJ authority for an inclusion witness.",
            row.snapshot_root.clone(),
            row.snapshot_index.map(|i| i as u64),
            row.snapshot_size.map(|i| i as u64),
        )));
    }

    // Snapshot columns are all-or-nothing — if any required field is NULL we
    // can't verify, but the record IS known. Surface `pending` with a reason
    // that distinguishes legacy non-file records (no chunkable bytes) from
    // legacy-file rows that simply need re-upload to back-fill.
    let (
        original_root,
        snapshot_root_str,
        snapshot_index_i,
        snapshot_size_i,
        snapshot_path_json,
        snapshot_sig_hex,
    ) = match (
        row.original_root.as_deref(),
        row.snapshot_root.as_deref(),
        row.snapshot_index,
        row.snapshot_size,
        row.snapshot_path.as_ref(),
        row.snapshot_sig.as_deref(),
    ) {
        (Some(or), Some(sr), Some(si), Some(sz), Some(sp), Some(sg)) => (
            or.to_owned(),
            sr.to_owned(),
            si,
            sz,
            sp.clone(),
            sg.to_owned(),
        ),
        _ => {
            let detail = if row.record_type != "file" && row.record_type != "redaction" {
                "Record exists but has no Poseidon snapshot — non-file records \
                     (legacy JSON commits from the pre-H-5 route) are not anchored \
                     in the chunked ledger tree."
            } else {
                "Record exists but has no Poseidon snapshot yet — legacy row from \
                     before atomic-ingest. Re-upload the original bytes through \
                     /ingest/files to back-fill the snapshot columns."
            };
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Pending,
                detail,
                None,
                None,
                None,
            )));
        }
    };

    // Parse the stored snapshot_path JSON shape produced by
    // `build_snapshot_in_tx`: { path_elements: [hex…], path_indices: [u8…] }.
    let path_obj = match snapshot_path_json.as_object() {
        Some(o) => o,
        None => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_path is not a JSON object.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    let path_elements_hex: Vec<String> = match path_obj
        .get("path_elements")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(|s| s.to_owned()))
                .collect()
        }) {
        Some(v) => v,
        None => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_path.path_elements is missing or malformed.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    let path_indices: Vec<u8> =
        match path_obj
            .get("path_indices")
            .and_then(|v| v.as_array())
            .and_then(|a| {
                // Each index is a binary-tree direction bit (0 or 1). Reject
                // non-integers and out-of-domain values instead of silently
                // truncating with `as u8` (e.g. 256 -> 0) or dropping bad
                // elements — corruption must surface as `Invalid`, below.
                a.iter()
                    .map(|e| match e.as_u64() {
                        Some(n) if n <= 1 => Some(n as u8),
                        _ => None,
                    })
                    .collect::<Option<Vec<u8>>>()
            }) {
            Some(v) => v,
            None => {
                return Ok(Json(build(
                    body.proof_id,
                    Some(row.proof_id),
                    content_hash,
                    SnapshotVerifyStatus::Invalid,
                    "Stored snapshot_path.path_indices is missing or malformed.",
                    Some(snapshot_root_str),
                    Some(snapshot_index_i as u64),
                    Some(snapshot_size_i as u64),
                )))
            }
        };

    // The stored `snapshot_sig` is a JSON object — see
    // `build_snapshot_in_tx` for the producer shape.
    let sig_json: serde_json::Value = match serde_json::from_str(&snapshot_sig_hex) {
        Ok(v) => v,
        Err(_) => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_sig is not valid JSON.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    // Algorithm discriminator MUST match the producer (`build_snapshot_in_tx`).
    // Without this gate, an attacker who can write to `snapshot_sig` could swap in
    // r8x/r8y/s values from a different signature scheme and the verifier would
    // happily attempt BJJ verification on them — a confused-deputy on the sig
    // family. The discriminator binds the on-disk payload to this verifier.
    match sig_json.get("alg").and_then(|v| v.as_str()) {
        Some(SNAPSHOT_SIG_ALG) => {}
        _ => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_sig has wrong or missing alg discriminator.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    }
    let (sig_r8x, sig_r8y, sig_s) = match (
        sig_json.get("r8x").and_then(|v| v.as_str()),
        sig_json.get("r8y").and_then(|v| v.as_str()),
        sig_json.get("s").and_then(|v| v.as_str()),
    ) {
        (Some(x), Some(y), Some(s)) => (x.to_owned(), y.to_owned(), s.to_owned()),
        _ => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                "Stored snapshot_sig is missing r8x/r8y/s.",
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };

    let snapshot = CryptoSnapshot {
        snapshot_root: snapshot_root_str.clone(),
        snapshot_index: snapshot_index_i as u64,
        snapshot_size: snapshot_size_i as u64,
        path_elements_hex,
        path_indices,
        signature_r8x: sig_r8x,
        signature_r8y: sig_r8y,
        signature_s: sig_s,
    };

    // Trust anchor: try every entry in the trusted-issuer set, not just the
    // current authority pubkey. This is the symmetric counterpart of the
    // redaction-side issuer check — it makes rotation work (an old snapshot
    // signed by a now-retired key still verifies if that key is in the
    // trusted set with a `valid_until` covering the snapshot's signing time)
    // and lets federation members verify snapshots signed by their peers.
    //
    // The bootstrap-minted key is always entry 0 of `bjj_trusted_issuers`,
    // so the default single-operator case keeps the exact previous behavior.
    if state.bjj_trusted_issuers.is_empty() {
        tracing::error!("verify_proof_bundle: trusted-issuer set is empty");
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Snapshot signing key is not configured on this server; cannot verify.",
        ));
    }
    let ok = state.bjj_trusted_issuers.iter().any(|issuer| {
        verify_snapshot(
            &snapshot,
            &content_hash,
            &original_root,
            issuer.pubkey.x,
            issuer.pubkey.y,
        )
    });
    let (status, detail) = if ok {
        (
            SnapshotVerifyStatus::Verified,
            "Snapshot path reconstructs the stored ledger root and the authority \
          signature is valid.",
        )
    } else {
        (
            SnapshotVerifyStatus::Invalid,
            "Stored snapshot failed verification: path reconstruction or authority \
          signature check did not pass.",
        )
    };

    Ok(Json(build(
        body.proof_id,
        Some(row.proof_id),
        content_hash,
        status,
        detail,
        Some(snapshot_root_str),
        Some(snapshot_index_i as u64),
        Some(snapshot_size_i as u64),
    )))
}
