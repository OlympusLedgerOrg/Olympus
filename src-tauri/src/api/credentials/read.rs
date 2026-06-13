//! `GET /credentials/{id}` and `GET /credentials?holder=..&type=..` —
//! admin-scoped credential reads. Pure code-motion from `credentials/mod.rs`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;

use super::types::{CredentialRow, CredentialView};
use super::{db_err, db_or_503, err, ApiError};

pub(super) async fn get_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<String>,
) -> Result<Json<CredentialView>, ApiError> {
    // Audit M-1: raw credential rows expose the holder BJJ key, issuer
    // pubkey, signatures, the quorum signer set, and (for non-committed
    // credentials) the plaintext `details`. `read`/`verify` are the default
    // scopes minted to every self-registered account, so gating retrieval on
    // them let any low-privilege key enumerate and disclose the entire
    // credential table (`?holder=` is caller-supplied). Credential
    // inspection is an operator capability — require `admin`. Public,
    // un-privileged transparency verification remains available via
    // `POST /credentials/{id}/verify`, which returns only validity booleans.
    if !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'admin'",
        ));
    }
    let pool = db_or_503(&state)?;
    let row: Option<CredentialRow> = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    row.map(|r| Json(r.into()))
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "credential not found"))
}

#[derive(Debug, Deserialize)]
pub(super) struct ListQuery {
    holder: Option<String>,
    #[serde(rename = "type")]
    credential_type: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    100
}

pub(super) async fn list_credentials(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Audit M-1: raw credential rows expose the holder BJJ key, issuer
    // pubkey, signatures, the quorum signer set, and (for non-committed
    // credentials) the plaintext `details`. `read`/`verify` are the default
    // scopes minted to every self-registered account, so gating retrieval on
    // them let any low-privilege key enumerate and disclose the entire
    // credential table (`?holder=` is caller-supplied). Credential
    // inspection is an operator capability — require `admin`. Public,
    // un-privileged transparency verification remains available via
    // `POST /credentials/{id}/verify`, which returns only validity booleans.
    if !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'admin'",
        ));
    }
    let pool = db_or_503(&state)?;
    let limit = crate::api::pagination::clamp_with_log("GET /credentials", q.limit, 1, 500);

    // Dynamic predicate composition — sqlx-style, with bind args.
    let rows: Vec<CredentialRow> = match (q.holder.as_deref(), q.credential_type.as_deref()) {
        (Some(h), Some(t)) => {
            sqlx::query_as(
                "SELECT * FROM key_credentials
             WHERE holder_key = $1 AND credential_type = $2
             ORDER BY issued_at DESC LIMIT $3",
            )
            .bind(h)
            .bind(t)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
        (Some(h), None) => {
            sqlx::query_as(
                "SELECT * FROM key_credentials
             WHERE holder_key = $1
             ORDER BY issued_at DESC LIMIT $2",
            )
            .bind(h)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
        (None, Some(t)) => {
            sqlx::query_as(
                "SELECT * FROM key_credentials
             WHERE credential_type = $1
             ORDER BY issued_at DESC LIMIT $2",
            )
            .bind(t)
            .bind(limit)
            .fetch_all(pool)
            .await
        }
        (None, None) => {
            sqlx::query_as(
                "SELECT * FROM key_credentials
             ORDER BY issued_at DESC LIMIT $1",
            )
            .bind(limit)
            .fetch_all(pool)
            .await
        }
    }
    .map_err(db_err)?;
    let view: Vec<CredentialView> = rows.into_iter().map(Into::into).collect();
    Ok(Json(json!({ "credentials": view })))
}
