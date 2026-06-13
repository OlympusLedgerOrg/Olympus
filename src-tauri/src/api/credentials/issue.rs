//! `POST /credentials` — issue a credential (plaintext, Pedersen-committed,
//! and/or M-of-N quorum). Pure code-motion from `credentials/mod.rs`.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::quorum::{self, QuorumStatus};
use crate::state::AppState;
use crate::zk::pedersen;
use crate::zk::witness::baby_jubjub;

use super::crypto::{
    compute_commit_id, compute_commit_id_for_commitment, digest_jcs_to_subgroup_scalar,
    digest_to_fr, fr_to_decimal,
};
use super::quorum::build_quorum;
use super::types::{CredentialRow, CredentialView};
use super::{db_err, db_or_503, err, require_admin, ApiError};

#[derive(Debug, Deserialize)]
pub(super) struct IssueRequest {
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
    /// If true, issue as an M-of-N federation quorum credential: the issuing
    /// node co-signs with its trusted peers (over Tor) until `quorum_threshold`
    /// valid signatures are collected from the pinned signer set. Fails closed
    /// (409) if the quorum can't be reached.
    #[serde(default)]
    quorum: bool,
    /// Quorum threshold `M`. Defaults to `OLYMPUS_FEDERATION_QUORUM_THRESHOLD`
    /// (or 1) when omitted. Must be `>= 1` and `<=` the pinned signer-set size.
    #[serde(default)]
    quorum_threshold: Option<u32>,
}

/// Returned exactly once on `POST /credentials` when `commit: true`. The
/// server stores only the commitment; this opening is the caller's only
/// way to verify the credential later.  Also accepted (via
/// `VerifyRequest`) on `POST /credentials/{id}/verify` to prove knowledge
/// of the cleartext attributes.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct OpeningPayload {
    pub(super) m: String,
    pub(super) r: String,
}

/// Wrapping envelope for `POST /credentials` so the opening can ride
/// alongside the credential view without polluting the read-side shape.
#[derive(Debug, Serialize)]
pub(super) struct IssueResponse {
    #[serde(flatten)]
    credential: CredentialView,
    /// Present iff the issue request had `commit: true`. Never returned by
    /// `GET /credentials/{id}` — opener-only knowledge.
    #[serde(skip_serializing_if = "Option::is_none")]
    opening: Option<OpeningPayload>,
    /// Present iff the issue request had `quorum: true` — the live quorum
    /// status (valid / threshold / total) computed at issue time.
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_status: Option<QuorumStatus>,
}

pub(super) async fn issue_credential(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<IssueRequest>,
) -> Result<(StatusCode, Json<IssueResponse>), ApiError> {
    let pool = db_or_503(&state)?;
    require_admin(pool, &auth).await?;

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
        let c = pedersen::commit(m, r).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Pedersen commit: {e}"),
            )
        })?;
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
        (
            cid,
            serde_json::json!({}),
            Some((cx_dec, cy_dec, 1i16)),
            Some(opening),
        )
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
    let issuer = body
        .issuer
        .unwrap_or_else(|| "olympus:federation".to_owned());
    let issued_at_naive = chrono::DateTime::from_timestamp(issued_at_unix, 0)
        .map(|t| t.naive_utc())
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad timestamp"))?;

    let (cx_param, cy_param, cv_param): (Option<String>, Option<String>, Option<i16>) =
        match commitment_fields {
            Some((x, y, v)) => (Some(x), Some(y), Some(v)),
            None => (None, None, None),
        };

    // Federation quorum (opt-in). Assemble the signer set, collect the local +
    // peer co-signatures, verify the threshold is met, and (best-effort) build
    // the ZK quorum proof. Co-signers recompute commit_id from the commitment
    // coords (committed rows) or the cleartext details (plaintext rows).
    let commitment_ref = cx_param.as_deref().zip(cy_param.as_deref());
    let details_ref = if commitment_ref.is_some() {
        None
    } else {
        Some(&details)
    };
    let quorum_built = if body.quorum {
        Some(
            build_quorum(
                &state,
                pool,
                &bjj_key,
                bjj_pubkey,
                &commit_id_bytes,
                body.quorum_threshold,
                &body.holder_key,
                &body.credential_type,
                issued_at_unix,
                details_ref,
                commitment_ref,
            )
            .await?,
        )
    } else {
        None
    };
    let (q_threshold, q_signers, q_proof, q_signals): (
        Option<i32>,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
        Option<serde_json::Value>,
    ) = match &quorum_built {
        Some(q) => (
            Some(q.threshold),
            Some(q.signers_json.clone()),
            q.proof.clone(),
            q.proof_signals.clone(),
        ),
        None => (None, None, None, None),
    };

    // Red-team: the UNIQUE constraint on `commit_id` (migration 0040)
    // turns two concurrent issuances of the same `(holder, type,
    // issued_at_second, details)` tuple — which compute identical
    // `commit_id` values — into a constraint hit on the second caller
    // instead of a duplicate-row pair. Use `ON CONFLICT (commit_id) DO
    // NOTHING RETURNING id` so the race is idempotent: if a concurrent
    // request already inserted, fall through to the existing row and
    // return its `id` instead of producing an opaque 500.
    let inserted_id: Option<(String,)> = sqlx::query_as(
        "INSERT INTO key_credentials
             (id, holder_key, credential_type, issued_at, issuer,
              sbt_nontransferable, commit_id, details,
              issuer_pubkey_x, issuer_pubkey_y,
              issued_sig_r8x, issued_sig_r8y, issued_sig_s,
              commitment_x, commitment_y, commitment_version,
              quorum_threshold, quorum_signers, quorum_proof, quorum_proof_signals)
         VALUES ($1, $2, $3, $4, $5, TRUE, $6, $7,
                 $8, $9, $10, $11, $12,
                 $13, $14, $15,
                 $16, $17, $18, $19)
         ON CONFLICT (commit_id) DO NOTHING
         RETURNING id",
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
    .bind(q_threshold)
    .bind(&q_signers)
    .bind(&q_proof)
    .bind(&q_signals)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    // If `inserted_id` is None, a concurrent issuance already wrote a
    // row with this `commit_id`. Resolve the existing row's `id` so
    // downstream code (quorum-sig persistence, response shape) operates
    // on the canonical row regardless of which caller won the race.
    let won_insert = inserted_id.is_some();
    let id = match inserted_id {
        Some((existing_id,)) => existing_id,
        None => {
            let existing: (String,) =
                sqlx::query_as("SELECT id FROM key_credentials WHERE commit_id = $1 LIMIT 1")
                    .bind(&commit_id_hex)
                    .fetch_one(pool)
                    .await
                    .map_err(db_err)?;
            tracing::info!(
                "credentials: idempotent issue — concurrent caller already inserted commit_id={commit_id_hex}; returning existing row id={}",
                existing.0
            );
            existing.0
        }
    };

    // Quorum side-effects belong ONLY to the caller that actually inserted the
    // row. That writer owns the row's `quorum_*` columns ($16-$19 above) and
    // its collected-signature set, so persisting + advertising its quorum
    // state is correct. On the idempotent lost-race path (`won_insert ==
    // false`) the canonical row was written by the *winning* caller with ITS
    // quorum options; persisting THIS request's `q.collected` against that row
    // would cross-contaminate the winner's signature set, and reporting THIS
    // request's `quorum_status` would misdescribe the stored row. So skip both
    // and let the returned canonical row speak for itself.
    let quorum_status = if won_insert {
        if let Some(q) = &quorum_built {
            // Best-effort: the credential row is already committed; a failure
            // here only loses the per-signer detail, not the credential.
            if let Err(e) = quorum::store_quorum_signatures(pool, &id, &q.collected).await {
                tracing::warn!("quorum: failed to persist collected signatures: {e}");
            }
        }
        quorum_built.as_ref().map(|q| q.status.clone())
    } else {
        None
    };

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(db_err)?;
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            credential: row.into(),
            opening,
            quorum_status,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
