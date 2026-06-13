//! `POST /credentials/{id}/revoke` — authority-signed revocation. Pure
//! code-motion from `credentials/mod.rs`; the revocation digest
//! (`OLY:SBT:REVOKE:V1`) is built in `super::crypto::compute_revoke_digest`
//! and is untouched.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::witness::baby_jubjub;

use super::crypto::{compute_revoke_digest, digest_to_fr, fr_to_decimal};
use super::types::{CredentialRow, CredentialView};
use super::{db_err, db_or_503, err, require_admin, ApiError};

pub(super) async fn revoke_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<String>,
) -> Result<Json<CredentialView>, ApiError> {
    let pool = db_or_503(&state)?;
    require_admin(pool, &auth).await?;

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "credential not found"))?;
    if row.revoked_at.is_some() {
        return Err(err(StatusCode::CONFLICT, "credential is already revoked"));
    }

    let bjj_key = state.bjj_authority_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority key not loaded",
        )
    })?;

    let revoked_at_unix = chrono::Utc::now().timestamp();
    let digest = compute_revoke_digest(&row.commit_id, revoked_at_unix);
    let msg_fr = digest_to_fr(&digest);
    let sig = baby_jubjub::sign(&bjj_key, msg_fr).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("BJJ sign (revoke): {e}"),
        )
    })?;
    let revoked_at_naive = chrono::DateTime::from_timestamp(revoked_at_unix, 0)
        .map(|t| t.naive_utc())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad timestamp"))?;

    sqlx::query(
        "UPDATE key_credentials
            SET revoked_at = $1,
                revoked_sig_r8x = $2,
                revoked_sig_r8y = $3,
                revoked_sig_s   = $4
          WHERE id = $5",
    )
    .bind(revoked_at_naive)
    .bind(fr_to_decimal(&sig.r8x))
    .bind(fr_to_decimal(&sig.r8y))
    .bind(fr_to_decimal(&sig.s))
    .bind(&id)
    .execute(pool)
    .await
    .map_err(db_err)?;

    let updated: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    Ok(Json(updated.into()))
}
