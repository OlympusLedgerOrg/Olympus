//! `POST /redaction/issue` handler, the shared proving core
//! (`build_redaction_bundle`), and the proving / signing helpers.

use std::collections::HashSet;

use axum::{extract::State, http::StatusCode, Json};

use olympus_crypto::redaction::derive_blinding;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::pdf_objects::witness_inputs;

use super::manifest::{build_reveal_mask, load_object_manifest};
use super::types::{
    err, require_redact_scope, ApiError, RedactionIssueRequest, RedactionIssueResponse,
    RevealedSegment,
};

// ── POST /redaction/issue ─────────────────────────────────────────────────────

pub(crate) async fn issue_redaction(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<RedactionIssueRequest>,
) -> Result<Json<RedactionIssueResponse>, ApiError> {
    require_redact_scope(&auth)?;
    Ok(Json(build_redaction_bundle(&state, body).await?))
}

/// Shared proving core for `/redaction/issue` and `/redaction/redact`: load the
/// object manifest, build + prove the 1024-leaf redaction witness, and sign the
/// bundle. Callers perform the scope check first.
pub(crate) async fn build_redaction_bundle(
    state: &AppState,
    req: RedactionIssueRequest,
) -> Result<RedactionIssueResponse, ApiError> {
    use ark_ff::PrimeField;

    let content_hash = req.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }
    let content_hash_bytes = hex::decode(&content_hash).map_err(|_| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash is not valid hex.",
        )
    })?;

    // Resolve the document first: an unknown content_hash is a 404 regardless of
    // server-key configuration.
    let manifest = load_object_manifest(state, &content_hash).await?;

    // blind_secret is required to publish revealed-object blindings (and was
    // required at ingest to build the manifest in the first place).
    let blind_secret = state.redaction_blind_secret.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "OLYMPUS_REDACTION_BLIND_SECRET unavailable — cannot issue object redactions.",
        )
    })?;

    let redacted_set: HashSet<u32> = req.redacted_obj_ids.iter().copied().collect();
    let (reveal_mask, revealed_count) = build_reveal_mask(&manifest, &redacted_set)?;

    // 1024-leaf witness inputs from the committed hiding leaves.
    let (leaves, path_elements, path_indices) = witness_inputs(&manifest).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("witness_inputs: {e}"),
        )
    })?;

    let original_root_hex = manifest.original_root_hex.clone();
    let original_root_fr = {
        let decoded = hex::decode(&original_root_hex).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("original_root hex: {e}"),
            )
        })?;
        let mut padded = [0u8; 32];
        let off = 32usize.saturating_sub(decoded.len());
        padded[off..off + decoded.len()].copy_from_slice(&decoded);
        ark_bn254::Fr::from_be_bytes_mod_order(&padded)
    };

    let recipient_id_fr = parse_decimal_fr(&req.recipient_id).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("recipient_id: {e}"),
        )
    })?;
    let recipient_id_dec = crate::zk::proof::fr_to_decimal(&recipient_id_fr);

    // Audit M-2: in-circuit EdDSA-Poseidon issuer signature over the nullifier.
    let bjj_priv = state.bjj_authority_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "OLYMPUS_BJJ_AUTHORITY_KEY not configured — cannot sign redaction proofs",
        )
    })?;
    let bjj_pub = state.bjj_authority_pubkey.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "BJJ authority pubkey not available",
        )
    })?;
    // Fail fast before the expensive prove if the bundle signing key is missing.
    let signing_key = state.ingest_signing_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Redaction signing key unavailable: set OLYMPUS_INGEST_SIGNING_KEY \
             (32-byte hex), or run in dev mode where it is derived from the \
             persisted BJJ authority.",
        )
    })?;

    let nullifier_msg = crate::zk::poseidon::hash_n(&[
        original_root_fr,
        crate::zk::poseidon::redaction_commitment(revealed_count as u64, &leaves, &reveal_mask)
            .map_err(|e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("nullifier commit: {e}"),
                )
            })?,
        recipient_id_fr,
    ])
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("nullifier hash: {e}"),
        )
    })?;
    let issuer_sig = crate::zk::witness::baby_jubjub::sign(&bjj_priv, nullifier_msg)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("BJJ sign: {e}")))?;

    let witness = crate::zk::witness::RedactionWitness::new(
        original_root_fr,
        leaves,
        reveal_mask,
        path_elements,
        path_indices,
        recipient_id_fr,
        bjj_pub,
        issuer_sig,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("witness: {e}")))?;

    let (proof_json, public_signals_dec) =
        generate_redaction_proof(state.proofs_dir.clone(), witness).await?;

    let redacted_commitment_dec = public_signals_dec.get(2).cloned().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing redactedCommitment signal",
        )
    })?;

    // Audit B2: V2 length-prefixes every field + binds content_hash, so a
    // signature is pinned to exactly one document + commitment + recipient.
    let sig_payload = {
        use olympus_crypto::length_prefixed as lp;
        let mut p = Vec::new();
        p.extend_from_slice(b"OLY:REDACTION_BUNDLE:V2");
        p.extend_from_slice(&lp(content_hash.as_bytes()));
        p.extend_from_slice(&lp(original_root_hex.as_bytes()));
        p.extend_from_slice(&lp(redacted_commitment_dec.as_bytes()));
        p.extend_from_slice(&lp(recipient_id_dec.as_bytes()));
        p
    };
    let signature_hex = sign_bundle(&sig_payload, &signing_key)?;

    // Per-revealed-object blindings (deterministic, re-derived from the secret).
    // Derived from `redacted_set` (not the moved `reveal_mask`): a real object is
    // revealed iff it isn't in the redacted set.
    let revealed_segments: Vec<RevealedSegment> = manifest
        .objects
        .iter()
        .filter(|o| !redacted_set.contains(&o.obj_id))
        .map(|o| RevealedSegment {
            segment_id: o.obj_id,
            blinding_decimal: derive_blinding(
                &blind_secret,
                &content_hash_bytes,
                &o.obj_id.to_be_bytes(),
            )
            .to_string(),
        })
        .collect();

    let mut redacted_obj_ids: Vec<u32> = redacted_set.into_iter().collect();
    redacted_obj_ids.sort_unstable();

    tracing::info!(
        content_hash = %content_hash,
        recipient_id = %recipient_id_dec,
        redacted = redacted_obj_ids.len(),
        revealed_count = revealed_count,
        "redaction_issue",
    );

    Ok(RedactionIssueResponse {
        circuit: "redaction_validity".to_string(),
        content_hash,
        original_root: original_root_hex,
        proof_json,
        public_signals: public_signals_dec,
        redacted_obj_ids,
        revealed_segments,
        signature_hex,
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn parse_decimal_fr(s: &str) -> Result<ark_bn254::Fr, String> {
    use ark_ff::PrimeField;
    let bigint = num_bigint::BigUint::parse_bytes(s.trim().as_bytes(), 10)
        .ok_or_else(|| format!("not a decimal field element: {s}"))?;
    let bytes_be = bigint.to_bytes_be();
    let mut padded = [0u8; 32];
    let off = 32usize.saturating_sub(bytes_be.len());
    padded[off..off + bytes_be.len()].copy_from_slice(&bytes_be);
    Ok(ark_bn254::Fr::from_be_bytes_mod_order(&padded))
}

fn sign_bundle(payload: &[u8], signing_key: &[u8; 32]) -> Result<String, ApiError> {
    use ed25519_dalek::{Signer, SigningKey};
    let sk = SigningKey::from_bytes(signing_key);
    Ok(hex::encode(sk.sign(payload).to_bytes()))
}

#[cfg(feature = "prover")]
async fn generate_redaction_proof(
    proofs_dir: Option<std::path::PathBuf>,
    witness: crate::zk::witness::RedactionWitness,
) -> Result<(serde_json::Value, Vec<String>), ApiError> {
    use crate::zk::Circuit;
    let keys_dir = proofs_dir.unwrap_or_else(|| std::path::PathBuf::from("proofs/keys"));
    let circuit = Circuit::RedactionValidity;
    let wasm = circuit.wasm_path(&keys_dir);
    let r1cs = circuit.r1cs_path(&keys_dir);
    let zkey = circuit.ark_zkey_path(&keys_dir);
    for (label, path) in [("wasm", &wasm), ("r1cs", &r1cs), ("zkey", &zkey)] {
        if !path.exists() {
            return Err(err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!(
                    "redaction circuit artifact missing: {label} at {}",
                    path.display()
                ),
            ));
        }
    }

    let (proof, public_signals) = tokio::task::spawn_blocking(move || {
        crate::zk::prove::prove_redaction(&witness, &wasm, &r1cs, &zkey)
    })
    .await
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("prove_redaction join: {e}"),
        )
    })?
    .map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("prove_redaction: {e}"),
        )
    })?;

    Ok((
        crate::zk::proof::proof_to_snarkjs_json(&proof),
        public_signals.iter().map(fr_to_decimal).collect(),
    ))
}

#[cfg(not(feature = "prover"))]
async fn generate_redaction_proof(
    _proofs_dir: Option<std::path::PathBuf>,
    _witness: crate::zk::witness::RedactionWitness,
) -> Result<(serde_json::Value, Vec<String>), ApiError> {
    Err(err(
        StatusCode::SERVICE_UNAVAILABLE,
        "ZK prover feature not compiled in this build",
    ))
}

#[cfg(feature = "prover")]
use crate::zk::proof::fr_to_decimal;
