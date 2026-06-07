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
//! `details` is canonicalised with RFC 8785 JCS (via the `olympus-crypto`
//! `canonical` module), so any conformant JCS implementation reproduces the
//! same bytes regardless of field ordering. The signature is over the
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
use crate::quorum::{self, CollectedSignature, QuorumSigner, QuorumStatus};
use crate::state::AppState;
use crate::zk::pedersen::{self, PedersenCommitment};
use crate::zk::witness::baby_jubjub::{self, BabyJubJubPubKey, BabyJubJubSignature};

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(json!({ "detail": detail })))
}

/// Log a DB error internally and return a generic message to the client —
/// avoids leaking driver/schema internals (audit TOB-OLY-07).
fn db_err(e: impl std::fmt::Display) -> ApiError {
    tracing::error!("credentials DB error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error")
}

fn db_or_503(state: &AppState) -> Result<&sqlx::PgPool, ApiError> {
    state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))
}

/// Authorize an authority-level credential operation (issue / revoke).
///
/// Audit M-3: credential issuance is the most security-sensitive authority
/// action in the system — an `authority_sbt` minted here itself confers
/// scopes via the SBT scope resolver (`auth::resolve_sbt_scopes`). Gating it
/// on the `admin` *scope* alone let a `role = 'user'` key that had merely
/// been granted the admin scope (directly, or transitively via an
/// `authority_sbt`) mint further authority credentials — a self-bootstrap
/// path. We now additionally require an authority *role* on the owning user,
/// matching the role-AND-scope bar that `require_admin_auth` enforces on the
/// rest of the `/admin/*` surface.
///
/// Accepted roles are `admin` and `system`: `system` is the bootstrap
/// identity surfaced to the desktop operator (it legitimately drives
/// credential issuance — see `bootstrap::ensure_system_api_key`), and
/// `admin` is any operator-promoted user. A plain `role = 'user'` key is
/// refused even if it carries the admin scope. `auth.scopes` already unions
/// the SBT-derived scopes (the `AuthenticatedKey` extractor resolves them),
/// so the scope check here is complete without a second SBT lookup.
async fn require_admin(pool: &sqlx::PgPool, auth: &AuthenticatedKey) -> Result<(), ApiError> {
    if !auth.has_scope("admin") {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: 'admin'",
        ));
    }
    // `users.id` is VARCHAR(36) (migration 0010); bind the Uuid and cast the
    // column to text, mirroring the established pattern in `user_auth`.
    let role: Option<String> = sqlx::query_scalar("SELECT role FROM users WHERE id = $1::text")
        .bind(auth.user_id)
        .fetch_optional(pool)
        .await
        .map_err(db_err)?;
    match role.as_deref() {
        Some("admin") | Some("system") => Ok(()),
        _ => Err(err(
            StatusCode::FORBIDDEN,
            "credential operation requires an authority role (admin or system)",
        )),
    }
}

mod crypto;
mod types;

// Re-export the digest helpers consumed elsewhere in the crate so existing
// `crate::api::credentials::{compute_commit_id, ...}` paths keep resolving
// after the split (bootstrap, federation co-sign, auth, ZK manifest,
// trusted-issuers).
pub(crate) use crypto::parse_fr_decimal;
pub use crypto::{compute_commit_id, compute_commit_id_for_commitment};
use crypto::{compute_revoke_digest, digest_jcs_to_subgroup_scalar, digest_to_fr, fr_to_decimal};
use types::{CredentialRow, CredentialView};
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
    /// Present iff the issue request had `quorum: true` — the live quorum
    /// status (valid / threshold / total) computed at issue time.
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum_status: Option<QuorumStatus>,
}

/// Everything a quorum issuance produces, threaded back into the INSERT and
/// the post-insert signature persistence.
struct QuorumBuilt {
    threshold: i32,
    signers_json: serde_json::Value,
    collected: Vec<CollectedSignature>,
    status: QuorumStatus,
    proof: Option<serde_json::Value>,
    proof_signals: Option<serde_json::Value>,
}

/// Assemble the pinned signer set, gather the local + peer co-signatures, and
/// (best-effort) build the ZK quorum proof. Returns a 409 if the quorum can't
/// be reached, or a 422 if the requested threshold exceeds the signer set.
#[allow(clippy::too_many_arguments)]
async fn build_quorum(
    state: &AppState,
    pool: &sqlx::PgPool,
    bjj_key: &[u8; 32],
    bjj_pubkey: &BabyJubJubPubKey,
    commit_id_bytes: &[u8; 32],
    threshold_req: Option<u32>,
    holder_key: &str,
    credential_type: &str,
    issued_at_unix: i64,
    details_for_cosign: Option<&serde_json::Value>,
    commitment_for_cosign: Option<(&str, &str)>,
) -> Result<QuorumBuilt, ApiError> {
    let authority_signer = QuorumSigner {
        x: fr_to_decimal(&bjj_pubkey.x),
        y: fr_to_decimal(&bjj_pubkey.y),
    };

    // Pinned signer set N = authority + trusted peers (federation builds), or
    // just the authority (vanilla build — only threshold 1 is reachable).
    #[cfg(feature = "federation")]
    let pinned = quorum::trusted_signer_set(pool, bjj_pubkey)
        .await
        .map_err(db_err)?;
    #[cfg(not(feature = "federation"))]
    let pinned = vec![authority_signer.clone()];

    let threshold = threshold_req
        .unwrap_or_else(quorum::configured_threshold)
        .max(1);
    if threshold as usize > pinned.len() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "quorum_threshold {threshold} exceeds the pinned signer-set size {} \
                 (authority + trusted peers); register more peers or lower the threshold",
                pinned.len()
            ),
        ));
    }

    // The issuing node's own quorum signature is always one of the signers.
    let msg = quorum::quorum_cosign_message(commit_id_bytes);
    let local_sig = baby_jubjub::sign(bjj_key, msg).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("BJJ quorum sign: {e}"),
        )
    })?;
    // `mut` is used only in the federation build (peer co-signatures are
    // appended); the vanilla build leaves it as the lone authority signature.
    #[allow(unused_mut)]
    let mut collected = vec![CollectedSignature {
        signer: authority_signer,
        r8x: fr_to_decimal(&local_sig.r8x),
        r8y: fr_to_decimal(&local_sig.r8y),
        s: fr_to_decimal(&local_sig.s),
    }];

    // Collect co-signatures from peers over Tor (federation builds only).
    #[cfg(feature = "federation")]
    {
        let remaining = (threshold as usize).saturating_sub(collected.len());
        if remaining > 0 {
            match crate::federation::cosign::collect_cosignatures(
                state,
                commit_id_bytes,
                holder_key,
                credential_type,
                issued_at_unix,
                details_for_cosign,
                commitment_for_cosign,
                remaining,
            )
            .await
            {
                Ok(mut remote) => collected.append(&mut remote),
                Err(e) => tracing::warn!("quorum: peer co-sign collection failed: {e}"),
            }
        }
    }
    // Silence unused-variable warnings in the non-federation build (peer
    // collection is the only consumer of these).
    #[cfg(not(feature = "federation"))]
    let _ = (
        pool,
        holder_key,
        credential_type,
        issued_at_unix,
        details_for_cosign,
        commitment_for_cosign,
    );

    let status = quorum::verify_quorum(commit_id_bytes, &pinned, threshold as usize, &collected);
    if !status.satisfied {
        return Err(err(
            StatusCode::CONFLICT,
            &format!(
                "federation quorum not reached: collected {} of {} required signatures \
                 from {} pinned signers",
                status.valid_signatures, status.threshold, status.total_signers
            ),
        ));
    }

    let (proof, proof_signals) = maybe_build_quorum_proof(
        state,
        commit_id_bytes,
        &pinned,
        threshold as u64,
        &collected,
    )
    .await;

    Ok(QuorumBuilt {
        threshold: threshold as i32,
        signers_json: quorum::signers_to_json(&pinned),
        collected,
        status,
        proof,
        proof_signals,
    })
}

/// Best-effort: build a Groth16 `federation_quorum` proof. Returns
/// `(None, None)` whenever the proof can't be produced — set too large for the
/// circuit, `proofs_dir` unset, artifacts still placeholders (pre-ceremony), or
/// any prove error. The explicit signature-set remains the authoritative check;
/// the proof is an optional privacy layer.
///
/// Gated behind `quorum-circuit` (next-phase, ceremony-pending) AND `prover`
/// (the Groth16 prover that pulls in `ark-circom`). The no-op stubs below keep
/// the issuance path identical when either feature is off.
#[cfg(all(feature = "quorum-circuit", feature = "prover"))]
async fn maybe_build_quorum_proof(
    state: &AppState,
    commit_id_bytes: &[u8; 32],
    pinned: &[QuorumSigner],
    threshold: u64,
    collected: &[CollectedSignature],
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    use crate::zk::witness::quorum::QuorumProofWitness;
    use crate::zk::Circuit;

    if pinned.len() > quorum::FEDERATION_QUORUM_N {
        return (None, None);
    }
    let Some(proofs_dir) = state.proofs_dir.clone() else {
        return (None, None);
    };
    let witness =
        match QuorumProofWitness::from_quorum(commit_id_bytes, pinned, threshold, collected) {
            Ok(w) => w,
            Err(e) => {
                tracing::debug!("quorum proof: witness build skipped: {e}");
                return (None, None);
            }
        };

    let circuit = Circuit::FederationQuorum;
    let wasm = circuit.wasm_path(&proofs_dir);
    let r1cs = circuit.r1cs_path(&proofs_dir);
    let zkey = circuit.ark_zkey_path(&proofs_dir);
    // Cheap pre-flight: skip the heavy prove path when artifacts are missing or
    // still placeholder stubs (the trusted-setup ceremony hasn't run).
    for p in [&wasm, &r1cs, &zkey] {
        if !p.exists() || file_is_placeholder(p) {
            return (None, None);
        }
    }

    let signals_for_witness = witness.public_signals();
    let proof_res = tokio::task::spawn_blocking(move || {
        crate::zk::prove::prove_quorum(&witness, &wasm, &r1cs, &zkey)
    })
    .await;

    match proof_res {
        Ok(Ok((proof, _signals))) => {
            let proof_json = crate::zk::proof::proof_to_snarkjs_json(&proof);
            let signals_json = serde_json::Value::Array(
                signals_for_witness
                    .iter()
                    .map(|f| serde_json::Value::String(fr_to_decimal(f)))
                    .collect(),
            );
            (Some(proof_json), Some(signals_json))
        }
        Ok(Err(e)) => {
            tracing::warn!("quorum proof: prove_quorum failed: {e}");
            (None, None)
        }
        Err(e) => {
            tracing::warn!("quorum proof: prove join failed: {e}");
            (None, None)
        }
    }
}

/// No-op stub when `quorum-circuit` is on but the `prover` feature is off:
/// without the in-process Groth16 prover there is no prove path, so the ZK
/// attestation is simply skipped. The explicit signature set remains
/// authoritative, so quorum credentials still issue and verify.
#[cfg(all(feature = "quorum-circuit", not(feature = "prover")))]
async fn maybe_build_quorum_proof(
    _state: &AppState,
    _commit_id_bytes: &[u8; 32],
    _pinned: &[QuorumSigner],
    _threshold: u64,
    _collected: &[CollectedSignature],
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    (None, None)
}

/// No-op stub when the `quorum-circuit` feature is off: quorum credentials
/// still issue/verify via the explicit signature set, just without the
/// (next-phase) ZK attestation.
#[cfg(not(feature = "quorum-circuit"))]
async fn maybe_build_quorum_proof(
    _state: &AppState,
    _commit_id_bytes: &[u8; 32],
    _pinned: &[QuorumSigner],
    _threshold: u64,
    _collected: &[CollectedSignature],
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    (None, None)
}

/// Return true if the file begins with the `PLACEHOLDER` magic that
/// `build.rs` writes for un-built ZK artifacts. Only used by the prover-side
/// quorum proof path.
#[cfg(all(feature = "quorum-circuit", feature = "prover"))]
fn file_is_placeholder(p: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut head = [0u8; 11];
    let n = f.read(&mut head).unwrap_or(0);
    n >= 11 && &head[..11] == b"PLACEHOLDER"
}

async fn issue_credential(
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

// ── GET /credentials/{id} ───────────────────────────────────────────────────

async fn get_credential(
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

// ── POST /credentials/{id}/revoke ───────────────────────────────────────────

async fn revoke_credential(
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
    /// Present iff the row is a quorum credential. Reports how many of the
    /// pinned signers' stored co-signatures verify over the (recomputed)
    /// quorum message, and whether the threshold is met.
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum: Option<QuorumStatus>,
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

// ── Router ──────────────────────────────────────────────────────────────────

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/credentials", post(issue_credential).get(list_credentials))
        .route("/credentials/{id}", get(get_credential))
        .route("/credentials/{id}/revoke", post(revoke_credential))
        .route("/credentials/{id}/verify", post(verify_credential))
}

/// Public transparency subset of credential routes mounted on the federation
/// Tor onion service. Only `POST /credentials/{id}/verify` is exposed — it
/// returns validity booleans, never row contents.
///
/// The credential GETs (`list_credentials`, `get_credential`) are
/// deliberately NOT on the onion service: as of audit M-1 they are
/// admin-scoped (raw rows expose holder keys, issuer pubkeys, signatures and
/// details), so they belong on the local listener only — not the public
/// federation surface. Issuance and revocation are likewise excluded
/// (authority-bound mutations). Mounting only `verify` keeps the Tor surface
/// to genuinely-public transparency.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new().route("/credentials/{id}/verify", post(verify_credential))
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
