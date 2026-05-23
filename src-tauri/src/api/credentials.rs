//! Olympus-native Soulbound Tokens (SBTs).
//!
//! Every credential row is BJJ-EdDSA-signed by the federation authority
//! key at issue time and (when revoked) again at revocation time. Anyone
//! holding the federation BJJ public key can re-verify the credential
//! offline — no contact with the Olympus node required, no blockchain.
//!
//! Wire shape
//! ----------
//! A credential is uniquely identified by `commit_id`:
//!
//! ```text
//! commit_id = BLAKE3(
//!     "OLY:SBT:V1"
//!     | len(holder_key) || holder_key
//!     | len(credential_type) || credential_type
//!     | issued_at_unix (BE i64)
//!     | len(details_canonical_json) || details_canonical_json
//! )
//! ```
//!
//! `details` is serialised with serde_json's default object ordering —
//! verifiers must match byte-for-byte. The signature is over the
//! commit_id reinterpreted as a BN254 `Fr` field element (via
//! `from_le_bytes_mod_order`), which is the same domain the in-circuit
//! verifier expects.
//!
//! Routes
//! ------
//! * `POST /credentials` — issue (scope: admin).
//! * `GET /credentials/{id}` — read with signatures attached.
//! * `GET /credentials?holder=..&type=..` — list, optionally filtered.
//! * `POST /credentials/{id}/revoke` — revoke (admin scope).
//! * `POST /credentials/{id}/verify` — server-side re-verify (debugging
//!   convenience; the real check is offline against the BJJ pubkey).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

fn require_admin(auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if auth.has_scope("admin") {
        Ok(())
    } else {
        Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'admin'",
        ))
    }
}

// ── Commit-hash helper ──────────────────────────────────────────────────────

/// Compute the deterministic `commit_id` for a credential.
///
/// Length-prefixing every variable-length component prevents
/// field-boundary collisions: a malicious issuer can't construct two
/// `(holder, type, details)` triples that hash to the same `commit_id`
/// by shuffling delimiters.
pub fn compute_commit_id(
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    details: &serde_json::Value,
) -> [u8; 32] {
    let details_bytes = serde_json::to_vec(details).unwrap_or_default();
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:SBT:V1");
    h.update(&(holder_key.len() as u32).to_be_bytes());
    h.update(holder_key.as_bytes());
    h.update(&(credential_type.len() as u32).to_be_bytes());
    h.update(credential_type.as_bytes());
    h.update(&issued_at_unix.to_be_bytes());
    h.update(&(details_bytes.len() as u32).to_be_bytes());
    h.update(&details_bytes);
    *h.finalize().as_bytes()
}

/// Compute the deterministic revocation digest. Separated from
/// `commit_id` so a stolen issued-signature can't be replayed as a
/// revocation.
fn compute_revoke_digest(commit_id_hex: &str, revoked_at_unix: i64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"OLY:SBT:REVOKE:V1");
    h.update(&(commit_id_hex.len() as u32).to_be_bytes());
    h.update(commit_id_hex.as_bytes());
    h.update(&revoked_at_unix.to_be_bytes());
    *h.finalize().as_bytes()
}

/// Reduce 32 bytes (BLAKE3 digest) into a BN254 scalar `Fr` exactly the
/// way the in-circuit verifier expects.
fn digest_to_fr(digest: &[u8; 32]) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    ark_bn254::Fr::from_le_bytes_mod_order(digest)
}

fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

fn parse_fr_decimal(s: &str) -> Option<ark_bn254::Fr> {
    use ark_ff::PrimeField;
    let bu: num_bigint::BigUint = s.parse().ok()?;
    let bytes = bu.to_bytes_be();
    Some(ark_bn254::Fr::from_be_bytes_mod_order(&bytes))
}

// ── DB row + wire types ─────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct CredentialRow {
    id: String,
    holder_key: String,
    credential_type: String,
    issued_at: chrono::NaiveDateTime,
    revoked_at: Option<chrono::NaiveDateTime>,
    issuer: String,
    commit_id: String,
    details: serde_json::Value,
    issuer_pubkey_x: Option<String>,
    issuer_pubkey_y: Option<String>,
    issued_sig_r8x: Option<String>,
    issued_sig_r8y: Option<String>,
    issued_sig_s: Option<String>,
    revoked_sig_r8x: Option<String>,
    revoked_sig_r8y: Option<String>,
    revoked_sig_s: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignaturePayload {
    r8x: String,
    r8y: String,
    s: String,
}

#[derive(Debug, Serialize)]
struct CredentialView {
    id: String,
    holder_key: String,
    credential_type: String,
    issued_at: String,
    revoked_at: Option<String>,
    issuer: String,
    commit_id: String,
    details: serde_json::Value,
    issuer_pubkey: Option<SignaturePayload>, // reused shape: (x, y) but `s` always empty
    issued_signature: Option<SignaturePayload>,
    revoked_signature: Option<SignaturePayload>,
}

impl From<CredentialRow> for CredentialView {
    fn from(r: CredentialRow) -> Self {
        let issuer_pubkey = match (r.issuer_pubkey_x.as_deref(), r.issuer_pubkey_y.as_deref()) {
            (Some(x), Some(y)) => Some(SignaturePayload {
                r8x: x.to_owned(),
                r8y: y.to_owned(),
                s: String::new(),
            }),
            _ => None,
        };
        let issued_signature = match (
            r.issued_sig_r8x.as_deref(),
            r.issued_sig_r8y.as_deref(),
            r.issued_sig_s.as_deref(),
        ) {
            (Some(x), Some(y), Some(s)) => Some(SignaturePayload {
                r8x: x.to_owned(),
                r8y: y.to_owned(),
                s: s.to_owned(),
            }),
            _ => None,
        };
        let revoked_signature = match (
            r.revoked_sig_r8x.as_deref(),
            r.revoked_sig_r8y.as_deref(),
            r.revoked_sig_s.as_deref(),
        ) {
            (Some(x), Some(y), Some(s)) => Some(SignaturePayload {
                r8x: x.to_owned(),
                r8y: y.to_owned(),
                s: s.to_owned(),
            }),
            _ => None,
        };
        CredentialView {
            id: r.id,
            holder_key: r.holder_key,
            credential_type: r.credential_type,
            issued_at: r.issued_at.and_utc().to_rfc3339(),
            revoked_at: r.revoked_at.map(|t| t.and_utc().to_rfc3339()),
            issuer: r.issuer,
            commit_id: r.commit_id,
            details: r.details,
            issuer_pubkey,
            issued_signature,
            revoked_signature,
        }
    }
}

// ── POST /credentials ───────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct IssueRequest {
    holder_key: String,
    credential_type: String,
    #[serde(default)]
    details: serde_json::Value,
    /// Optional override; defaults to "olympus:federation".
    #[serde(default)]
    issuer: Option<String>,
}

async fn issue_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<IssueRequest>,
) -> Result<(StatusCode, Json<CredentialView>), ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;

    if body.holder_key.trim().is_empty() {
        return Err(err(StatusCode::UNPROCESSABLE_ENTITY, "holder_key required"));
    }
    if body.credential_type.trim().is_empty() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "credential_type required",
        ));
    }
    let details = if body.details.is_null() {
        serde_json::json!({})
    } else {
        body.details
    };

    let bjj_key = state.bjj_authority_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority key not loaded — set OLYMPUS_BJJ_AUTHORITY_KEY",
        )
    })?;
    let bjj_pubkey = state.bjj_authority_pubkey.as_ref().ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority pubkey not loaded",
        )
    })?;

    let issued_at_unix = chrono::Utc::now().timestamp();
    let commit_id_bytes = compute_commit_id(
        &body.holder_key,
        &body.credential_type,
        issued_at_unix,
        &details,
    );
    let commit_id_hex = hex::encode(commit_id_bytes);
    let msg_fr = digest_to_fr(&commit_id_bytes);
    let sig = baby_jubjub::sign(&bjj_key, msg_fr)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    let id = Uuid::new_v4().to_string();
    let issuer = body.issuer.unwrap_or_else(|| "olympus:federation".to_owned());
    let issued_at_naive = chrono::DateTime::from_timestamp(issued_at_unix, 0)
        .map(|t| t.naive_utc())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad timestamp"))?;

    sqlx::query(
        "INSERT INTO key_credentials
             (id, holder_key, credential_type, issued_at, issuer,
              sbt_nontransferable, commit_id, details,
              issuer_pubkey_x, issuer_pubkey_y,
              issued_sig_r8x, issued_sig_r8y, issued_sig_s)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7,
                 $8, $9, $10, $11, $12)",
    )
    .bind(&id)
    .bind(&body.holder_key)
    .bind(&body.credential_type)
    .bind(issued_at_naive)
    .bind(&issuer)
    .bind(&commit_id_hex)
    .bind(&details)
    .bind(fr_to_decimal(&bjj_pubkey.x))
    .bind(fr_to_decimal(&bjj_pubkey.y))
    .bind(fr_to_decimal(&sig.r8x))
    .bind(fr_to_decimal(&sig.r8y))
    .bind(fr_to_decimal(&sig.s))
    .execute(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB readback: {e}")))?;
    Ok((StatusCode::CREATED, Json(row.into())))
}

// ── GET /credentials/{id} ───────────────────────────────────────────────────

async fn get_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<String>,
) -> Result<Json<CredentialView>, ApiError> {
    if !auth.has_scope("read") && !auth.has_scope("verify") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks 'read', 'verify', or 'admin'",
        ));
    }
    let pool = db_or_503(&state)?;
    let row: Option<CredentialRow> =
        sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
            .bind(&id)
            .fetch_optional(pool)
            .await
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    row.map(|r| Json(r.into()))
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "credential not found"))
}

// ── GET /credentials?holder=..&type=.. ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ListQuery {
    holder: Option<String>,
    #[serde(rename = "type")]
    credential_type: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
}
fn default_limit() -> i64 {
    100
}

async fn list_credentials(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !auth.has_scope("read") && !auth.has_scope("verify") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks 'read', 'verify', or 'admin'",
        ));
    }
    let pool = db_or_503(&state)?;
    let limit = q.limit.clamp(1, 500);

    // Dynamic predicate composition — sqlx-style, with bind args.
    let rows: Vec<CredentialRow> = match (q.holder.as_deref(), q.credential_type.as_deref()) {
        (Some(h), Some(t)) => sqlx::query_as(
            "SELECT * FROM key_credentials
             WHERE holder_key = $1 AND credential_type = $2
             ORDER BY issued_at DESC LIMIT $3",
        )
        .bind(h)
        .bind(t)
        .bind(limit)
        .fetch_all(pool)
        .await,
        (Some(h), None) => sqlx::query_as(
            "SELECT * FROM key_credentials
             WHERE holder_key = $1
             ORDER BY issued_at DESC LIMIT $2",
        )
        .bind(h)
        .bind(limit)
        .fetch_all(pool)
        .await,
        (None, Some(t)) => sqlx::query_as(
            "SELECT * FROM key_credentials
             WHERE credential_type = $1
             ORDER BY issued_at DESC LIMIT $2",
        )
        .bind(t)
        .bind(limit)
        .fetch_all(pool)
        .await,
        (None, None) => sqlx::query_as(
            "SELECT * FROM key_credentials
             ORDER BY issued_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await,
    }
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    let view: Vec<CredentialView> = rows.into_iter().map(Into::into).collect();
    Ok(Json(json!({ "credentials": view })))
}

// ── POST /credentials/{id}/revoke ───────────────────────────────────────────

async fn revoke_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<String>,
) -> Result<Json<CredentialView>, ApiError> {
    require_admin(&auth)?;
    let pool = db_or_503(&state)?;

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "credential not found"))?;
    if row.revoked_at.is_some() {
        return Err(err(
            StatusCode::CONFLICT,
            "credential is already revoked",
        ));
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
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    let updated: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;
    Ok(Json(updated.into()))
}

// ── POST /credentials/{id}/verify ───────────────────────────────────────────

#[derive(Debug, Serialize)]
struct VerifyResponse {
    commit_id_matches: bool,
    issued_signature_valid: bool,
    revoked_signature_valid: Option<bool>,
    is_revoked: bool,
}

async fn verify_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<String>,
) -> Result<Json<VerifyResponse>, ApiError> {
    if !auth.has_scope("verify") && !auth.has_scope("read") && !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks 'verify', 'read', or 'admin'",
        ));
    }
    let pool = db_or_503(&state)?;

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "credential not found"))?;

    // 1. Recompute commit_id from the row's claimed fields and compare.
    let issued_unix = row.issued_at.and_utc().timestamp();
    let recomputed = compute_commit_id(
        &row.holder_key,
        &row.credential_type,
        issued_unix,
        &row.details,
    );
    let commit_id_matches = hex::encode(recomputed) == row.commit_id;

    // 2. Verify the BJJ signature over commit_id, using the issuer
    //    pubkey stored on the row. If the row lacks a signature
    //    (legacy bootstrap-minted row), report false.
    let issued_signature_valid = (|| -> Option<bool> {
        let x = parse_fr_decimal(row.issuer_pubkey_x.as_deref()?)?;
        let y = parse_fr_decimal(row.issuer_pubkey_y.as_deref()?)?;
        let r8x = parse_fr_decimal(row.issued_sig_r8x.as_deref()?)?;
        let r8y = parse_fr_decimal(row.issued_sig_r8y.as_deref()?)?;
        let s = parse_fr_decimal(row.issued_sig_s.as_deref()?)?;
        Some(baby_jubjub::verify_signature(
            &BabyJubJubPubKey { x, y },
            &BabyJubJubSignature { r8x, r8y, s },
            digest_to_fr(&recomputed),
        ))
    })()
    .unwrap_or(false);

    // 3. If revoked, verify the revocation signature too.
    let is_revoked = row.revoked_at.is_some();
    let revoked_signature_valid = if is_revoked {
        Some(
            (|| -> Option<bool> {
                let x = parse_fr_decimal(row.issuer_pubkey_x.as_deref()?)?;
                let y = parse_fr_decimal(row.issuer_pubkey_y.as_deref()?)?;
                let r8x = parse_fr_decimal(row.revoked_sig_r8x.as_deref()?)?;
                let r8y = parse_fr_decimal(row.revoked_sig_r8y.as_deref()?)?;
                let s = parse_fr_decimal(row.revoked_sig_s.as_deref()?)?;
                let revoked_unix = row.revoked_at?.and_utc().timestamp();
                let digest = compute_revoke_digest(&row.commit_id, revoked_unix);
                Some(baby_jubjub::verify_signature(
                    &BabyJubJubPubKey { x, y },
                    &BabyJubJubSignature { r8x, r8y, s },
                    digest_to_fr(&digest),
                ))
            })()
            .unwrap_or(false),
        )
    } else {
        None
    };

    Ok(Json(VerifyResponse {
        commit_id_matches,
        issued_signature_valid,
        revoked_signature_valid,
        is_revoked,
    }))
}

// ── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/credentials", post(issue_credential).get(list_credentials))
        .route("/credentials/{id}", get(get_credential))
        .route("/credentials/{id}/revoke", post(revoke_credential))
        .route("/credentials/{id}/verify", post(verify_credential))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_id_is_deterministic_and_length_safe() {
        let a = compute_commit_id("alice", "press", 1700000000, &json!({"role": "journalist"}));
        let b = compute_commit_id("alice", "press", 1700000000, &json!({"role": "journalist"}));
        assert_eq!(a, b);
        // Length-prefixing prevents holder/type boundary collisions:
        // "ali" + "cepress" cannot collide with "alice" + "press".
        let collision_try =
            compute_commit_id("ali", "cepress", 1700000000, &json!({"role": "journalist"}));
        assert_ne!(a, collision_try);
    }

    #[test]
    fn commit_id_changes_with_any_field() {
        let base = compute_commit_id("a", "p", 1, &json!({}));
        assert_ne!(base, compute_commit_id("b", "p", 1, &json!({})));
        assert_ne!(base, compute_commit_id("a", "q", 1, &json!({})));
        assert_ne!(base, compute_commit_id("a", "p", 2, &json!({})));
        assert_ne!(base, compute_commit_id("a", "p", 1, &json!({"x": 1})));
    }

    #[test]
    fn revoke_digest_is_distinct_from_commit_id() {
        let cid = hex::encode(compute_commit_id("a", "p", 1, &json!({})));
        let rd = compute_revoke_digest(&cid, 1);
        // The two digests are derived from distinct domain tags so they
        // can never collide — an issued signature is not a valid
        // revocation signature and vice versa.
        let bytes = hex::decode(&cid).expect("hex");
        assert_ne!(&rd[..], &bytes[..]);
    }
}
