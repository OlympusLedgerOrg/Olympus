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
    /// **The authoritative verdict.** `true` iff the credential is genuinely
    /// valid *right now* against a trusted root: `commit_id` recomputes,
    /// the issued BJJ signature verifies, the issuer is in the configured
    /// trusted-issuer set (and was authorised at `issued_at`), the credential
    /// is not revoked, any supplied commitment opening matches, and — for a
    /// quorum credential — the M-of-N threshold is met (audit H-1/H-2).
    ///
    /// The individual booleans below are diagnostics. Relying parties MUST key
    /// off `valid`, not off `issued_signature_valid`/`quorum.satisfied` alone:
    /// those report internal self-consistency of the row only and do not anchor
    /// trust or account for revocation.
    valid: bool,
    /// `true` iff `(issuer_pubkey_x, issuer_pubkey_y)` on the row matches an
    /// entry in the node's trusted-issuer set whose validity window covers the
    /// credential's `issued_at` (audit H-1). Without this, a row whose
    /// signatures are merely internally self-consistent — e.g. forged by a
    /// database-tier attacker who chose their own issuer keypair — would
    /// otherwise report `issued_signature_valid: true`.
    issuer_trusted: bool,
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
        if threshold <= 0 {
            // A non-positive stored threshold is a corrupt row: `threshold.max(0)
            // as usize` would collapse it to 0, making `valid_signatures >= 0`
            // trivially true and reporting "quorum satisfied" with no signatures.
            // Fail closed instead of letting a bad DB value forge satisfaction.
            tracing::warn!(
                credential_id = %row.id,
                stored_threshold = threshold,
                "non-positive quorum_threshold encountered in DB; failing closed"
            );
            Some(QuorumStatus {
                threshold: 0,
                total_signers: 0,
                valid_signatures: 0,
                satisfied: false,
            })
        } else {
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
                threshold as usize,
                &sigs,
            ))
        }
    } else {
        None
    };

    // 5. Trust anchoring (audit H-1). The issued/quorum signatures above are
    //    verified against material stored *on the row*, which only proves the
    //    row is internally self-consistent. Anchor that to a configured trust
    //    root: the issuer pubkey must be in `state.bjj_trusted_issuers` and
    //    have been authorised at `issued_at`. This mirrors the privilege path
    //    `auth::resolve_sbt_scopes`, so the public verifier is no longer weaker
    //    than the scope resolver. For a quorum credential, the issuing
    //    authority is also the first pinned signer, so anchoring the issuer
    //    roots the whole quorum set in a trusted key.
    let issuer_trusted = match (row.issuer_pubkey_x.as_deref(), row.issuer_pubkey_y.as_deref()) {
        (Some(ix), Some(iy)) => state
            .bjj_trusted_issuers
            .iter()
            .any(|t| t.x_dec == ix && t.y_dec == iy && t.covers(issued_unix)),
        _ => false,
    };

    // 6. The single authoritative bit (audit H-1/H-2). Couples revocation,
    //    trust-anchoring and quorum into one verdict so a relying party can't
    //    accept a revoked-but-signature-valid or untrusted-issuer credential by
    //    reading a lower-level boolean in isolation.
    let valid = overall_valid(
        commit_id_matches,
        issued_signature_valid,
        issuer_trusted,
        is_revoked,
        commitment_opens,
        quorum.as_ref(),
    );

    Ok(Json(VerifyResponse {
        valid,
        issuer_trusted,
        commit_id_matches,
        issued_signature_valid,
        revoked_signature_valid,
        is_revoked,
        commitment_opens,
        quorum,
    }))
}

/// Fold the individual verification signals into the single authoritative
/// `valid` verdict (audit H-1/H-2). A credential is valid iff:
///   * its `commit_id` recomputes from the stored fields,
///   * the issued BJJ signature verifies,
///   * the issuer is trusted (in the configured set + within its window),
///   * it is not revoked,
///   * any supplied Pedersen opening matched (an absent opening — `None` — does
///     not invalidate; only an explicit `Some(false)` does), and
///   * for a quorum credential, the M-of-N threshold is met.
fn overall_valid(
    commit_id_matches: bool,
    issued_signature_valid: bool,
    issuer_trusted: bool,
    is_revoked: bool,
    commitment_opens: Option<bool>,
    quorum: Option<&QuorumStatus>,
) -> bool {
    commit_id_matches
        && issued_signature_valid
        && issuer_trusted
        && !is_revoked
        && commitment_opens != Some(false)
        && quorum.map_or(true, |q| q.satisfied)
}

#[cfg(test)]
mod tests {
    use super::overall_valid;
    use crate::quorum::QuorumStatus;

    fn quorum(satisfied: bool) -> QuorumStatus {
        QuorumStatus {
            threshold: 2,
            total_signers: 3,
            valid_signatures: if satisfied { 2 } else { 1 },
            satisfied,
        }
    }

    #[test]
    fn happy_path_is_valid() {
        assert!(overall_valid(true, true, true, false, None, None));
        // Supplied opening that matched.
        assert!(overall_valid(true, true, true, false, Some(true), None));
        // Satisfied quorum.
        assert!(overall_valid(true, true, true, false, None, Some(&quorum(true))));
    }

    #[test]
    fn untrusted_issuer_is_invalid() {
        // H-1: signature self-consistent but issuer not in the trusted set.
        assert!(!overall_valid(true, true, false, false, None, None));
    }

    #[test]
    fn revoked_is_invalid_even_when_signatures_and_quorum_pass() {
        // H-2: a revoked credential must never report valid, even with a
        // satisfied quorum and a valid issued signature.
        assert!(!overall_valid(true, true, true, true, None, None));
        assert!(!overall_valid(
            true,
            true,
            true,
            true,
            None,
            Some(&quorum(true))
        ));
    }

    #[test]
    fn unsatisfied_quorum_is_invalid() {
        assert!(!overall_valid(
            true,
            true,
            true,
            false,
            None,
            Some(&quorum(false))
        ));
    }

    #[test]
    fn failed_opening_is_invalid_but_absent_opening_is_ok() {
        assert!(!overall_valid(true, true, true, false, Some(false), None));
        assert!(overall_valid(true, true, true, false, None, None));
    }

    #[test]
    fn commit_mismatch_or_bad_signature_is_invalid() {
        assert!(!overall_valid(false, true, true, false, None, None));
        assert!(!overall_valid(true, false, true, false, None, None));
    }
}
