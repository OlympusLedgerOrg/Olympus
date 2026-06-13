//! `POST /credentials/{id}/verify` — server-side re-verification (signature,
//! commitment opening, quorum). Pure code-motion from `credentials/mod.rs`.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::quorum::{self, QuorumStatus};
use crate::state::AppState;
use crate::zk::pedersen::{self, PedersenCommitment};
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

use super::crypto::{
    compute_commit_id, compute_commit_id_for_commitment, compute_revoke_digest, digest_to_fr,
    parse_fr_decimal,
};
use super::issue::OpeningPayload;
use super::types::CredentialRow;
use super::{db_err, db_or_503, err, ApiError};

#[derive(Debug, Deserialize, Default)]
pub(super) struct VerifyRequest {
    /// Required when the row was issued with `commit: true` — the
    /// `(m, r)` opening the original holder received. Without it, server
    /// can verify the BJJ signature on `commit_id` but cannot prove the
    /// caller knows the cleartext attributes.
    #[serde(default)]
    opening: Option<OpeningPayload>,
}

#[derive(Debug, Serialize)]
pub(super) struct VerifyResponse {
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
    /// Present iff the row is a quorum credential. Reports how many of the
    /// pinned signers' stored co-signatures verify over the (recomputed)
    /// quorum message, and whether the threshold is met.
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum: Option<QuorumStatus>,
}

pub(super) async fn verify_credential(
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
        .map_err(db_err)?
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
        let opening_pair = req
            .opening
            .as_ref()
            .and_then(|o| Some((parse_fr_decimal(&o.m)?, parse_fr_decimal(&o.r)?)));
        Some(match (stored_x, stored_y, opening_pair) {
            (Some(sx), Some(sy), Some((m, r))) => {
                // Audit defence-in-depth: even though the stored coords
                // came out of `pedersen::commit` at issue time, validate
                // the reconstructed point is on BabyJubjub AND in the
                // prime-order subgroup before equality-comparing. A
                // database-tier compromise that swapped in a cofactor
                // variant would otherwise produce a misleading "matched"
                // for one out of eight openings.
                let stored_point = BabyJubJubPubKey { x: sx, y: sy };
                if baby_jubjub::validate_pubkey_subgroup(&stored_point).is_err() {
                    false
                } else {
                    match pedersen::commit(m, r) {
                        Ok(c) => c == PedersenCommitment { x: sx, y: sy },
                        // `commit` enforces m,r in [0, l); any range error
                        // here means the (already strictly-parsed) opening
                        // was in-field but outside the BJJ subgroup order.
                        Err(_) => false,
                    }
                }
            }
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

    // 4. Quorum: if this is a quorum credential, verify the stored
    //    co-signatures against the pinned signer set over the recomputed
    //    commit_id's quorum message. Fail closed on a corrupt signer set
    //    (empty signers → 0 valid → not satisfied).
    let quorum = if let Some(threshold) = row.quorum_threshold {
        let signers = row
            .quorum_signers
            .as_ref()
            .map(quorum::signers_from_json)
            .unwrap_or_default();
        let sigs = quorum::load_quorum_signatures(pool, &row.id)
            .await
            .map_err(db_err)?;
        Some(quorum::verify_quorum(
            &recomputed,
            &signers,
            threshold.max(0) as usize,
            &sigs,
        ))
    } else {
        None
    };

    Ok(Json(VerifyResponse {
        commit_id_matches,
        issued_signature_valid,
        revoked_signature_valid,
        is_revoked,
        commitment_opens,
        quorum,
    }))
}
