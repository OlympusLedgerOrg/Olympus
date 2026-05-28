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

/// RFC 8785 JCS canonical encoding of `details` for digest binding.
///
/// Canonicalises via `olympus_crypto::canonical` so the digest is reproducible
/// off-box by any conformant JCS implementation (the Python/JS verifiers), not
/// only by replicating serde_json's ordering. `details` is already a parsed
/// `serde_json::Value`, so this round-trips Value → JSON → canonical, which is
/// byte-exact for the scalar/string/object values SBT `details` carry. Falls
/// back to the raw serialization only if canonicalisation fails (e.g. nesting
/// beyond the shared depth cap of 64) — such details are not JCS-verifiable
/// off-box in *any* implementation, so this loses no parity versus before.
fn canonical_details_bytes(details: &serde_json::Value) -> Vec<u8> {
    let raw = serde_json::to_vec(details).unwrap_or_default();
    olympus_crypto::canonical::canonicalize_bytes(&raw).unwrap_or(raw)
}

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
    let details_bytes = canonical_details_bytes(details);
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
/// `m = (BLAKE3-XOF 64 bytes of SBT_OPEN_PREFIX | len | details) mod l` where
/// `l` is the Baby Jubjub prime-subgroup order. The 64-byte XOF output is
/// reduced via `BigUint % l` *before* `Fr::from_le_bytes_mod_order`, so the
/// resulting field element is already in `[0, l)`. The `< l` guard inside
/// [`pedersen::commit`] is therefore belt-and-suspenders, not the primary
/// in-range check. With ≥ 64 bytes of XOF entropy reduced mod l (≈ 2²⁵²)
/// the residual bias is < 2⁻²⁵⁶ — indistinguishable from uniform — so no
/// re-hash loop is needed.
///
/// `details` is encoded with RFC 8785 JCS canonicalisation (via
/// `canonical_details_bytes`), so a holder can reconstruct `m` from the
/// cleartext using any conformant JCS implementation, independent of the field
/// ordering they send.
fn digest_jcs_to_subgroup_scalar(details: &serde_json::Value) -> ark_bn254::Fr {
    use ark_ff::PrimeField;
    let body = canonical_details_bytes(details);
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

/// Parse a decimal string as a BN254 scalar `Fr`, **rejecting** any value
/// that is greater than or equal to the field modulus.
///
/// Audit: the previous implementation used `from_be_bytes_mod_order` which
/// silently reduces — a caller submitting `m + r` (where `r` is the field
/// modulus) would get back `m`, breaking the invariant that a parsed `Fr`
/// is byte-equal to the decimal a holder claims to be presenting.
///
/// This is the choke point for every Fr-shaped field on the credentials
/// surface: stored Pedersen-commitment coordinates, issuer pubkey
/// coordinates, BJJ signature `(R8.x, R8.y, S)` fields, and user-supplied
/// openings `(m, r)`. All of them must round-trip through their original
/// decimal form, so all of them must reject the non-canonical encoding.
pub(crate) fn parse_fr_decimal(s: &str) -> Option<ark_bn254::Fr> {
    use ark_ff::{BigInteger, PrimeField};
    // Reject non-canonical decimals: empty, leading '+'/'-', or leading zeros
    // (other than the literal "0"). Round-trip via `fr_to_decimal` would
    // otherwise quietly lose the leading zero and break the invariant the
    // caller relies on. Audit L-API-2.
    if s.is_empty() {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    let bu: num_bigint::BigUint = s.parse().ok()?;
    let modulus = num_bigint::BigUint::from_bytes_le(&ark_bn254::Fr::MODULUS.to_bytes_le());
    if bu >= modulus {
        return None;
    }
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
    // Federation quorum columns (migration 0032). NULL on single-sig rows.
    quorum_threshold: Option<i32>,
    quorum_signers: Option<serde_json::Value>,
    quorum_proof: Option<serde_json::Value>,
    quorum_proof_signals: Option<serde_json::Value>,
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

/// Quorum summary attached to a credential view. Read-side metadata only —
/// the per-signer collected signatures live in `credential_quorum_signatures`
/// and the live satisfied/valid counts are surfaced by the verify endpoint.
#[derive(Debug, Serialize)]
struct QuorumView {
    /// Required number of valid signatures `M`.
    threshold: i32,
    /// Size of the pinned signer set `N`.
    total_signers: usize,
    /// The pinned signer set (BJJ pubkey coordinates).
    signers: Vec<QuorumSigner>,
    /// Whether a (privacy-preserving) ZK quorum proof is attached.
    has_proof: bool,
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
    /// Federation quorum metadata. Present iff the row was issued with
    /// `quorum: true` (i.e. `quorum_threshold` is non-NULL).
    #[serde(skip_serializing_if = "Option::is_none")]
    quorum: Option<QuorumView>,
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
        let quorum = r.quorum_threshold.map(|threshold| {
            let signers = r
                .quorum_signers
                .as_ref()
                .map(quorum::signers_from_json)
                .unwrap_or_default();
            QuorumView {
                threshold,
                total_signers: signers.len(),
                signers,
                has_proof: r.quorum_proof.is_some(),
            }
        });
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
            quorum,
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
/// Gated behind `quorum-circuit` (next-phase, ceremony-pending). The no-op stub
/// below keeps the issuance path identical when the feature is off.
#[cfg(feature = "quorum-circuit")]
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
            let proof_json = groth16_proof_to_json(&proof);
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
/// `build.rs` writes for un-built ZK artifacts.
#[cfg(feature = "quorum-circuit")]
fn file_is_placeholder(p: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let mut head = [0u8; 11];
    let n = f.read(&mut head).unwrap_or(0);
    n >= 11 && &head[..11] == b"PLACEHOLDER"
}

/// snarkjs-shape Groth16 proof JSON. Locally duplicated from the other
/// `*_proof_to_json` helpers in the codebase (see the note in
/// `federation::checkpoint`); a shared `zk::proof_json` module is a future
/// cleanup.
#[cfg(feature = "quorum-circuit")]
fn groth16_proof_to_json(proof: &ark_groth16::Proof<ark_bn254::Bn254>) -> serde_json::Value {
    use ark_serialize::CanonicalSerialize;
    fn g1(p: &ark_bn254::G1Affine) -> Vec<String> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let y = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        vec![x.to_string(), y.to_string(), "1".into()]
    }
    fn g2(p: &ark_bn254::G2Affine) -> Vec<Vec<String>> {
        let mut buf = Vec::new();
        p.serialize_uncompressed(&mut buf).unwrap();
        let x_c0 = num_bigint::BigUint::from_bytes_le(&buf[..32]);
        let x_c1 = num_bigint::BigUint::from_bytes_le(&buf[32..64]);
        let y_c0 = num_bigint::BigUint::from_bytes_le(&buf[64..96]);
        let y_c1 = num_bigint::BigUint::from_bytes_le(&buf[96..128]);
        vec![
            vec![x_c0.to_string(), x_c1.to_string()],
            vec![y_c0.to_string(), y_c1.to_string()],
            vec!["1".into(), "0".into()],
        ]
    }
    serde_json::json!({
        "pi_a": g1(&proof.a),
        "pi_b": g2(&proof.b),
        "pi_c": g1(&proof.c),
        "protocol": "groth16",
        "curve": "bn128",
    })
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

    sqlx::query(
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
                 $16, $17, $18, $19)",
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
    .execute(pool)
    .await
    .map_err(|e| db_err(e))?;

    // Persist the collected quorum signatures (separate table). Best-effort:
    // the credential row is already committed; a failure here only loses the
    // per-signer detail, not the credential.
    if let Some(q) = &quorum_built {
        if let Err(e) = quorum::store_quorum_signatures(pool, &id, &q.collected).await {
            tracing::warn!("quorum: failed to persist collected signatures: {e}");
        }
    }

    let row: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(|e| db_err(e))?;
    Ok((
        StatusCode::CREATED,
        Json(IssueResponse {
            credential: row.into(),
            opening,
            quorum_status: quorum_built.map(|q| q.status),
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
    let row: Option<CredentialRow> = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_optional(pool)
        .await
        .map_err(|e| db_err(e))?;
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
    .map_err(|e| db_err(e))?;
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
        .map_err(|e| db_err(e))?
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
    .map_err(|e| db_err(e))?;

    let updated: CredentialRow = sqlx::query_as("SELECT * FROM key_credentials WHERE id = $1")
        .bind(&id)
        .fetch_one(pool)
        .await
        .map_err(|e| db_err(e))?;
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
        .map_err(|e| db_err(e))?
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
            .map_err(|e| db_err(e))?;
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

/// Read/verify-only subset safe to expose over the federation Tor onion
/// service. Excludes issuance (`POST /credentials`) and revocation — both are
/// authority-bound mutations.
#[cfg(feature = "federation")]
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/credentials", get(list_credentials))
        .route("/credentials/{id}", get(get_credential))
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
        assert_ne!(
            plain, committed,
            "domain tags must keep plaintext and committed commit_ids structurally disjoint"
        );
    }

    #[test]
    fn commit_id_for_commitment_changes_with_every_field() {
        // Each input field is hashed in — flipping any one must change the
        // output. Catches accidental input shadowing or length-prefix bugs.
        let base = compute_commit_id_for_commitment("alice", "press", 17, "1", "2");
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alic", "epress", 17, "1", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "presS", 17, "1", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "press", 18, "1", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "press", 17, "11", "2")
        );
        assert_ne!(
            base,
            compute_commit_id_for_commitment("alice", "press", 17, "1", "22")
        );
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

    // ── parse_fr_decimal strict-decoding (audit M-3) ───────────────────────

    /// BN254 scalar field modulus as a decimal string.
    const FR_MODULUS_DEC: &str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";

    #[test]
    fn parse_fr_decimal_rejects_modulus() {
        // r itself must NOT silently reduce to 0. The fail-closed contract
        // is what stops a malicious holder from claiming m or r is e.g.
        // 0 while presenting `Fr::MODULUS` as the decimal form.
        assert!(parse_fr_decimal(FR_MODULUS_DEC).is_none());
    }

    #[test]
    fn parse_fr_decimal_rejects_modulus_plus_one() {
        let mut plus_one: num_bigint::BigUint = FR_MODULUS_DEC.parse().unwrap();
        plus_one += 1u32;
        assert!(parse_fr_decimal(&plus_one.to_str_radix(10)).is_none());
    }

    #[test]
    fn parse_fr_decimal_accepts_modulus_minus_one() {
        // Largest in-field value must parse and round-trip.
        let mut minus_one: num_bigint::BigUint = FR_MODULUS_DEC.parse().unwrap();
        minus_one -= 1u32;
        let s = minus_one.to_str_radix(10);
        let fr = parse_fr_decimal(&s).expect("r-1 is in-field");
        assert_eq!(fr_to_decimal(&fr), s);
    }

    #[test]
    fn parse_fr_decimal_rejects_huge_decimal() {
        let huge: num_bigint::BigUint = num_bigint::BigUint::from(1u8) << 300usize;
        assert!(parse_fr_decimal(&huge.to_str_radix(10)).is_none());
    }

    #[test]
    fn parse_fr_decimal_rejects_non_numeric() {
        assert!(parse_fr_decimal("not a number").is_none());
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
