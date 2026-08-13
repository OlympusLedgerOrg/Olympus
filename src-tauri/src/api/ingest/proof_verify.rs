//! `POST /ingest/proofs/verify` — offline snapshot proof-bundle verification.
//! Split out of the ingest module.

use axum::{extract::State, http::StatusCode, Json};

use super::snapshot_evidence::{fetch_snapshot_row, parse_stored_snapshot, pending_detail};
use super::*;
use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

// ── Route: POST /ingest/proofs/verify ────────────────────────────────────────

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
        proof_id: row_proof_id.or(body_proof_id),
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

pub(super) async fn verify_proof_bundle(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<ProofVerifyRequest>,
) -> Result<Json<ProofVerifyResponse>, ApiError> {
    use olympus_crypto::ledger_snapshot::verify_snapshot;

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

    // NULL snapshot columns mean the record exists but the inclusion witness
    // hasn't been built (legacy rows from pre-migration-0029 or the removed
    // pre-H-5 JSON commit path — new ingests through /ingest/files always
    // populate the snapshot atomically with the row INSERT). That's
    // `Pending`, NOT `Invalid`.
    let row_opt = fetch_snapshot_row(pool, &content_hash)
        .await
        .map_err(db_err)?;

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
            let detail = pending_detail(&row.record_type);
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

    // Parse the stored snapshot_path/snapshot_sig JSON shapes produced by
    // `build_snapshot_in_tx` — shared with `api::monitor::proof`, see
    // `snapshot_evidence::parse_stored_snapshot`'s doc comment.
    let snapshot = match parse_stored_snapshot(
        &snapshot_root_str,
        snapshot_index_i,
        snapshot_size_i,
        &snapshot_path_json,
        &snapshot_sig_hex,
    ) {
        Ok(s) => s,
        Err(detail) => {
            return Ok(Json(build(
                body.proof_id,
                Some(row.proof_id),
                content_hash,
                SnapshotVerifyStatus::Invalid,
                detail,
                Some(snapshot_root_str),
                Some(snapshot_index_i as u64),
                Some(snapshot_size_i as u64),
            )))
        }
    };
    let signed_at_unix = snapshot.signed_at_unix;

    // Trust anchor: try every entry in the trusted-issuer set that grants
    // the `CheckpointAuthority` role (ADR-0041 role separation — e.g. a
    // ceremony-coordinator-only entry cannot vouch for a snapshot), not just
    // the current authority pubkey. This is the symmetric counterpart of the
    // redaction-side issuer check — it makes rotation work and lets
    // federation members verify snapshots signed by their peers.
    //
    // Validity windows: a V2 snapshot carries an authenticated `signed_at`
    // (folded into the signing digest, so it cannot be edited to slide into
    // a retired key's window), and each candidate issuer must `covers()` that
    // signing time — an old snapshot signed by a now-retired key still
    // verifies when the retired key's registry window covers it. Legacy V1
    // rows have no signature-covered signing time, so no window is evaluated
    // for them (an unauthenticated DB timestamp must not enter the trust
    // decision); they keep the pre-window behavior of matching any
    // checkpoint-authority key.
    //
    // The bootstrap-minted key is always entry 0 of `bjj_trusted_issuers`
    // and carries all roles, so the default single-operator case keeps the
    // exact previous behavior.
    if state.bjj_trusted_issuers.is_empty() {
        tracing::error!("verify_proof_bundle: trusted-issuer set is empty");
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Snapshot signing key is not configured on this server; cannot verify.",
        ));
    }
    let ok = crate::api::trusted_issuers::issuers_for_role(
        &state.bjj_trusted_issuers,
        olympus_crypto::trust_list::TrustRole::CheckpointAuthority,
    )
    .filter(|issuer| signed_at_unix.is_none_or(|t| issuer.covers(t)))
    .any(|issuer| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_prefers_authoritative_row_proof_id() {
        let resp = build(
            Some("caller-supplied".to_owned()),
            Some("row-proof".to_owned()),
            "a".repeat(64),
            SnapshotVerifyStatus::Verified,
            "ok",
            Some("b".repeat(64)),
            Some(0),
            Some(1),
        );

        assert_eq!(resp.proof_id.as_deref(), Some("row-proof"));
        assert!(resp.known_to_server);
        assert_eq!(resp.merkle_proof_valid, Some(true));
    }

    #[test]
    fn build_echoes_body_proof_id_only_for_unknown_content() {
        let resp = build(
            Some("caller-supplied".to_owned()),
            None,
            "a".repeat(64),
            SnapshotVerifyStatus::Unknown,
            "missing",
            None,
            None,
            None,
        );

        assert_eq!(resp.proof_id.as_deref(), Some("caller-supplied"));
        assert!(!resp.known_to_server);
        assert_eq!(resp.merkle_proof_valid, None);
    }
}
