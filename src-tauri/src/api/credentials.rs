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
use crate::zk::pedersen::{self, PedersenCommitment};
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

/// Compute the deterministic `commit_id` for a Pedersen-committed
/// credential.  For committed rows the server has no cleartext `details`
/// to hash, so the commit_id binds the COMMITMENT instead — domain-tagged
/// with `OLY:SBT:COMMIT:V1` so it can never collide with a plaintext-row
/// `commit_id` (which is tagged `OLY:SBT:V1`).
///
/// `commit_id = BLAKE3(
///     "OLY:SBT:COMMIT:V1"
///     | len(holder_key) || holder_key
///     | len(credential_type) || credential_type
///     | issued_at_unix (BE i64)
///     | len(commitment_x_dec) || commitment_x_dec
///     | len(commitment_y_dec) || commitment_y_dec
/// )`
pub fn compute_commit_id_for_commitment(
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    commitment_x_dec: &str,
    commitment_y_dec: &str,
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(olympus_crypto::SBT_COMMIT_BIND_PREFIX);
    h.update(&(holder_key.len() as u32).to_be_bytes());
    h.update(holder_key.as_bytes());
    h.update(&(credential_type.len() as u32).to_be_bytes());
    h.update(credential_type.as_bytes());
    h.update(&issued_at_unix.to_be_bytes());
    h.update(&(commitment_x_dec.len() as u32).to_be_bytes());
    h.update(commitment_x_dec.as_bytes());
    h.update(&(commitment_y_dec.len() as u32).to_be_bytes());
    h.update(commitment_y_dec.as_bytes());
    *h.finalize().as_bytes()
}

/// Derive the Pedersen message scalar `m` for a credential's `details`.
///
/// `m = BLAKE3(SBT_OPEN_PREFIX | serde_json(details)) reduced mod l` where
/// `l` is the Baby Jubjub prime-subgroup order. Reduction is via
/// `from_le_bytes_mod_order` into `Fr` (mod the BN254 field) followed by
/// the explicit `< l` check inside [`pedersen::commit`] — values >= l
/// would be rejected, but with 32 bytes of BLAKE3 entropy the probability
/// is `~2⁻³`, so we accept the loss in 1-in-8 cases by re-hashing with a
/// counter until the result lands in-range.  This keeps `m` deterministic
/// per (details) without forcing callers to handle a retry.
///
/// **Caveat (acceptable for MVP, tracked for follow-up):** uses
/// `serde_json::to_vec` rather than RFC 8785 JCS canonicalisation, so
/// holders MUST send `details` to the server in the same field ordering
/// they will later hash locally for verification.  A JCS-canonicalising
/// pass can replace this without changing the API once a JCS dep lands.
fn digest_jcs_to_subgroup_scalar(details: &serde_json::Value) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    let body = serde_json::to_vec(details).unwrap_or_default();
    // 64-byte XOF output. Reducing 64 bytes (≈ 2⁵¹²) mod the ≈ 2²⁵² subgroup
    // order leaves bias < 2⁻²⁵⁶ — indistinguishable from uniform. A 32-byte
    // output would have bias ~2⁻⁴ because 2²⁵⁶ ≈ 34 · l; that's acceptable
    // for a *deterministic message digest* (no entropy concern) but we use
    // 64 bytes anyway to keep one consistent reduction recipe across the
    // codebase (matches `random_blinding`).
    let mut hasher = blake3::Hasher::new();
    hasher.update(olympus_crypto::SBT_OPEN_PREFIX);
    hasher.update(b"|");
    hasher.update(&(body.len() as u32).to_be_bytes());
    hasher.update(&body);
    let mut xof = hasher.finalize_xof();
    let mut wide = [0u8; 64];
    xof.fill(&mut wide);

    let l_dec = "2736030358979909402780800718157159386076813972158567259200215660948447373041";
    let l: num_bigint::BigUint = l_dec.parse().expect("static decimal");
    let reduced = num_bigint::BigUint::from_bytes_be(&wide) % l;
    let bytes = reduced.to_bytes_le();
    ark_bn254::Fr::from_le_bytes_mod_order(&bytes)
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
    // Pedersen commitment columns (PD-3). NULL on plaintext rows.
    commitment_x: Option<String>,
    commitment_y: Option<String>,
    commitment_version: Option<i16>,
}

#[derive(Debug, Serialize)]
struct SignaturePayload {
    r8x: String,
    r8y: String,
    s: String,
}

#[derive(Debug, Serialize)]
struct CommitmentPayload {
    x: String,
    y: String,
    version: i16,
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
    /// Pedersen commitment over `details`. Present iff the row was issued
    /// with `commit: true`; `details` in that case is an empty object and
    /// the cleartext is held only by the original opener.
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<CommitmentPayload>,
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
        let commitment = match (r.commitment_x, r.commitment_y, r.commitment_version) {
            (Some(x), Some(y), Some(version)) => Some(CommitmentPayload { x, y, version }),
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
            commitment,
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
    /// If true, the server computes a Pedersen commitment over `details`,
    /// stores the commitment instead of the cleartext, and returns the
    /// opening `(m, r)` to the caller exactly once.  Holders must persist
    /// `(m, r)` to verify the credential later — server discards them.
    #[serde(default)]
    commit: bool,
}

/// Returned exactly once on `POST /credentials` when `commit: true`. The
/// server stores only the commitment; this opening is the caller's only
/// way to verify the credential later.  Also accepted (via
/// `VerifyRequest`) on `POST /credentials/{id}/verify` to prove knowledge
/// of the cleartext attributes.
#[derive(Debug, Serialize, Deserialize)]
struct OpeningPayload {
    m: String,
    r: String,
}

/// Wrapping envelope for `POST /credentials` so the opening can ride
/// alongside the credential view without polluting the read-side shape.
#[derive(Debug, Serialize)]
struct IssueResponse {
    #[serde(flatten)]
    credential: CredentialView,
    /// Present iff the issue request had `commit: true`. Never returned by
    /// `GET /credentials/{id}` — opener-only knowledge.
    #[serde(skip_serializing_if = "Option::is_none")]
    opening: Option<OpeningPayload>,
}

async fn issue_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), ApiError> {
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

    // Pedersen-commit path: derive m from details, draw r, compute C, store
    // (C, version) and replace `details` with `{}` so the cleartext never
    // hits the DB.  commit_id is over the commitment, not the (gone) details.
    let (commit_id_bytes, stored_details, commitment_fields, opening) = if body.commit {
        let m = digest_jcs_to_subgroup_scalar(&details);
        let r = pedersen::random_blinding(&mut rand::thread_rng());
        let c = pedersen::commit(m, r)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("Pedersen commit: {e}")))?;
        let cx_dec = fr_to_decimal(&c.x);
        let cy_dec = fr_to_decimal(&c.y);
        let cid = compute_commit_id_for_commitment(
            &body.holder_key,
            &body.credential_type,
            issued_at_unix,
            &cx_dec,
            &cy_dec,
        );
        let opening = OpeningPayload {
            m: fr_to_decimal(&m),
            r: fr_to_decimal(&r),
        };
        (cid, serde_json::json!({}), Some((cx_dec, cy_dec, 1i16)), Some(opening))
    } else {
        let cid = compute_commit_id(
            &body.holder_key,
            &body.credential_type,
            issued_at_unix,
            &details,
        );
        (cid, details.clone(), None, None)
    };
    let commit_id_hex = hex::encode(commit_id_bytes);
    let msg_fr = digest_to_fr(&commit_id_bytes);
    let sig = baby_jubjub::sign(&bjj_key, msg_fr)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    let id = Uuid::new_v4().to_string();
    let issuer = body.issuer.unwrap_or_else(|| "olympus:federation".to_owned());
    let issued_at_naive = chrono::DateTime::from_timestamp(issued_at_unix, 0)
        .map(|t| t.naive_utc())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad timestamp"))?;

    let (cx_param, cy_param, cv_param): (Option<String>, Option<String>, Option<i16>) =
        match commitment_fields {
            Some((x, y, v)) => (Some(x), Some(y), Some(v)),
            None => (None, None, None),
        };

    sqlx::query(
        "INSERT INTO key_credentials
             (id, holder_key, credential_type, issued_at, issuer,
              sbt_nontransferable, commit_id, details,
              issuer_pubkey_x, issuer_pubkey_y,
              issued_sig_r8x, issued_sig_r8y, issued_sig_s,
              commitment_x, commitment_y, commitment_version)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7,
                 $8, $9, $10, $11, $12,
                 $13, $14, $15)",
    )
    .bind(&id)
    .bind(&body.holder_key)
    .bind(&body.credential_type)
    .bind(issued_at_naive)
    .bind(&issuer)
    .bind(&commit_id_hex)
    .bind(&stored_details)
    .bind(fr_to_decimal(&bjj_pubkey.x))
    .bind(fr_to_decimal(&bjj_pubkey.y))
    .bind(fr_to_decimal(&sig.r8x))
    .bind(fr_to_decimal(&sig.r8y))
    .bind(fr_to_decimal(&sig.s))
    .bind(&cx_param)
    .bind(&cy_param)
    .bind(cv_param)
    .execute(pool)
    .await
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB: {e}")))?;

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("DB readback: {e}")))?;
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            credential: row.into(),
            opening,
        }),
    ))
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

#[derive(Debug, Deserialize, Default)]
struct VerifyRequest {
    /// Required when the row was issued with `commit: true` — the
    /// `(m, r)` opening the original holder received. Without it, server
    /// can verify the BJJ signature on `commit_id` but cannot prove the
    /// caller knows the cleartext attributes.
    #[serde(default)]
    opening: Option<OpeningPayload>,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    commit_id_matches: bool,
    issued_signature_valid: bool,
    revoked_signature_valid: Option<bool>,
    is_revoked: bool,
    /// Present iff the row has a Pedersen commitment.  `Some(true)` means
    /// the caller's `opening` produced the stored commitment.  `Some(false)`
    /// means it did not.  `None` means the row is plaintext and no opening
    /// check was performed.
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment_opens: Option<bool>,
}

async fn verify_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(id): Path<String>,
    body: Option<Json<VerifyRequest>>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
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

    // 1. Recompute commit_id. Pedersen-committed rows bind the commitment
    //    fields; plaintext rows bind the `details` JSON. Dispatch on
    //    commitment_version so the two domains never get conflated (the
    //    domain tags OLY:SBT:V1 vs OLY:SBT:COMMIT:V1 make them
    //    structurally disjoint, but the recompute call has to match).
    let issued_unix = row.issued_at.and_utc().timestamp();
    let recomputed = match (
        row.commitment_version,
        row.commitment_x.as_deref(),
        row.commitment_y.as_deref(),
    ) {
        (Some(1), Some(cx), Some(cy)) => compute_commit_id_for_commitment(
            &row.holder_key,
            &row.credential_type,
            issued_unix,
            cx,
            cy,
        ),
        _ => compute_commit_id(
            &row.holder_key,
            &row.credential_type,
            issued_unix,
            &row.details,
        ),
    };
    let commit_id_matches = hex::encode(recomputed) == row.commit_id;

    // 1b. If the row is Pedersen-committed and the caller supplied an
    //     opening, recompute commit(m, r) and compare to the stored
    //     commitment. Two failure modes both return Some(false):
    //       - opening fields don't parse as Fr
    //       - commit(m, r) returns ScalarOutOfRange (m or r >= l)
    //       - recomputed point != stored point
    //     Plaintext rows return None (no commitment to verify).
    let commitment_opens = if row.commitment_version == Some(1) {
        let stored_x = row.commitment_x.as_deref().and_then(parse_fr_decimal);
        let stored_y = row.commitment_y.as_deref().and_then(parse_fr_decimal);
        let opening_pair = req.opening.as_ref().and_then(|o| {
            Some((parse_fr_decimal(&o.m)?, parse_fr_decimal(&o.r)?))
        });
        Some(match (stored_x, stored_y, opening_pair) {
            (Some(sx), Some(sy), Some((m, r))) => match pedersen::commit(m, r) {
                Ok(c) => c == PedersenCommitment { x: sx, y: sy },
                Err(_) => false,
            },
            _ => false,
        })
    } else {
        None
    };

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
        commitment_opens,
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

    // ── Pedersen commitment helpers (PD-3) ─────────────────────────────────

    #[test]
    fn digest_jcs_to_subgroup_scalar_is_deterministic() {
        // Same `details` → same `m`. Property the commitment scheme relies
        // on for holder-side verification.
        let d = json!({"role": "journalist", "tier": 2});
        assert_eq!(
            digest_jcs_to_subgroup_scalar(&d),
            digest_jcs_to_subgroup_scalar(&d)
        );
    }

    #[test]
    fn digest_jcs_to_subgroup_scalar_lands_in_subgroup() {
        // The digest MUST be in [0, l) so pedersen::commit accepts it
        // without the subgroup-scalar guard rejecting (which it would for
        // ~1-in-8 raw Fr values). Verify by trying to commit with r=0.
        let d = json!({"x": 1});
        let m = digest_jcs_to_subgroup_scalar(&d);
        // commit(m, 0) must NOT return ScalarOutOfRange for m.
        assert!(pedersen::commit(m, ark_bn254::Fr::from(0u64)).is_ok());
    }

    #[test]
    fn commit_ids_have_disjoint_domains() {
        // The plaintext-row commit_id (OLY:SBT:V1 tag) and the
        // committed-row commit_id (OLY:SBT:COMMIT:V1 tag) must NEVER
        // collide, even for inputs designed to confuse them. A plaintext
        // row whose `details` happens to contain the same bytes as a
        // commitment's `(x_dec, y_dec)` pair must produce a different
        // commit_id.
        let plain = compute_commit_id("alice", "press", 17, &json!({"x": "1", "y": "2"}));
        let committed = compute_commit_id_for_commitment("alice", "press", 17, "1", "2");
        assert_ne!(plain, committed,
            "domain tags must keep plaintext and committed commit_ids structurally disjoint");
    }

    #[test]
    fn commit_id_for_commitment_changes_with_every_field() {
        // Each input field is hashed in — flipping any one must change the
        // output. Catches accidental input shadowing or length-prefix bugs.
        let base = compute_commit_id_for_commitment("alice", "press", 17, "1", "2");
        assert_ne!(base, compute_commit_id_for_commitment("alic", "epress", 17, "1", "2"));
        assert_ne!(base, compute_commit_id_for_commitment("alice", "presS", 17, "1", "2"));
        assert_ne!(base, compute_commit_id_for_commitment("alice", "press", 18, "1", "2"));
        assert_ne!(base, compute_commit_id_for_commitment("alice", "press", 17, "11", "2"));
        assert_ne!(base, compute_commit_id_for_commitment("alice", "press", 17, "1", "22"));
    }

    #[test]
    fn issue_request_commit_defaults_to_false() {
        // Backward compat: requests omitting `commit` must keep the
        // plaintext path. A test pinned on the deserialised default
        // prevents anyone from quietly flipping the default.
        let body: IssueRequest = serde_json::from_value(json!({
            "holder_key": "alice",
            "credential_type": "press",
            "details": {"x": 1}
        }))
        .expect("deserialize");
        assert!(!body.commit);
    }

    #[test]
    fn opening_round_trips_through_commit_verify() {
        // End-to-end without touching DB / HTTP: m comes from details,
        // r is a fresh random, commit(m, r) == C, verify with the same
        // opening recovers C, verify with a wrong opening does not.
        let details = json!({"role": "journalist", "verified": true});
        let m = digest_jcs_to_subgroup_scalar(&details);
        let r = pedersen::random_blinding(&mut rand::thread_rng());
        let c = pedersen::commit(m, r).expect("commit");
        // Correct opening verifies.
        assert!(pedersen::verify(&c, m, r).expect("verify"));
        // Modifying r breaks verify.
        assert!(!pedersen::verify(&c, m, r + ark_bn254::Fr::from(1u64)).expect("verify"));
    }
}
