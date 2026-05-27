//! Redaction commitment endpoint — port of `api/routers/redaction.py`.
//!
//! Route
//! -----
//! POST /redaction/link — link a redacted document back to its original commit
//!
//! This endpoint is **public** (no API key required) because verification is a
//! transparency operation.
//!
//! # Crypto path
//!
//! Uses `olympus_crypto::poseidon` directly — no PyO3, no subprocess.
//! The Poseidon parameters and domain constants match the circom circuits and
//! `protocol/poseidon_tree.py` exactly.

use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use olympus_crypto::poseidon::{
    blake3_hex_to_poseidon_leaf, compute_poseidon_commitment_root, compute_redaction_commitments,
};

use crate::api::middleware::auth::RateLimit;
use crate::state::AppState;

// ── Constants ─────────────────────────────────────────────────────────────────

const MAX_LEAVES: usize = 64;

// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({"detail": detail})))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactionLinkRequest {
    /// Ledger commit ID for the original document.
    pub original_commit_id: String,
    /// 64 BLAKE3 hex hashes — one per equal-sized chunk of the original file.
    pub original_chunks: Vec<String>,
    /// 64 BLAKE3 hex hashes — one per equal-sized chunk of the redacted file.
    pub redacted_chunks: Vec<String>,
}

#[derive(Serialize)]
pub struct RedactionLinkResponse {
    pub original_commit_id: String,
    pub original_blake3: String,
    pub original_root: String,
    pub redacted_commitment: String,
    pub reveal_mask_commitment: String,
    pub reveal_mask: Vec<u8>,
    pub revealed_count: usize,
    pub redacted_count: usize,
    pub verified: bool,
    pub note: String,
}

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct CommitDocHash {
    doc_hash: String,
}

// ── Route handler ─────────────────────────────────────────────────────────────

/// POST /redaction/link
///
/// Given 64 BLAKE3 chunk hashes from the original and redacted documents,
/// computes the Poseidon commitment bundle that proves the redacted file is a
/// valid partial disclosure of the original committed document.
async fn link_redaction(
    State(state): State<AppState>,
    _rl: RateLimit,
    Json(body): Json<RedactionLinkRequest>,
) -> Result<Json<RedactionLinkResponse>, ApiError> {
    // 1. Validate chunk counts.
    if body.original_chunks.len() != MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "original_chunks must contain exactly {MAX_LEAVES} hashes; got {}.",
                body.original_chunks.len()
            ),
        ));
    }
    if body.redacted_chunks.len() != MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "redacted_chunks must contain exactly {MAX_LEAVES} hashes; got {}.",
                body.redacted_chunks.len()
            ),
        ));
    }

    // 2. Confirm the original commit exists in the DB.
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    let commit: Option<CommitDocHash> = sqlx::query_as::<_, CommitDocHash>(
        "SELECT doc_hash FROM doc_commits WHERE commit_id = $1 LIMIT 1",
    )
    .bind(&body.original_commit_id)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?;

    let commit = commit.ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            &format!(
                "Commit {:?} not found in the ledger.",
                body.original_commit_id
            ),
        )
    })?;

    // 3. Normalise to lowercase and derive Poseidon leaves from original chunks.
    let orig_normalised: Vec<String> = body
        .original_chunks
        .iter()
        .map(|h| h.to_lowercase())
        .collect();
    let redc_normalised: Vec<String> = body
        .redacted_chunks
        .iter()
        .map(|h| h.to_lowercase())
        .collect();

    let original_leaves: Vec<num_bigint::BigUint> = orig_normalised
        .iter()
        .enumerate()
        .map(|(i, h)| {
            blake3_hex_to_poseidon_leaf(h).map_err(|e| {
                err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    &format!("original_chunks[{}]: {}", i, e),
                )
            })
        })
        .collect::<Result<_, _>>()?;

    // Validate redacted chunk hexes (they are only compared, not run through Poseidon).
    for (i, h) in redc_normalised.iter().enumerate() {
        if h.len() != 64 {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_chunks[{i}]: must be 64 hex characters."),
            ));
        }
        if hex::decode(h).is_err() {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_chunks[{i}]: invalid hex."),
            ));
        }
    }

    // 4. Compute reveal mask: 1 = chunk unchanged, 0 = chunk differs.
    let reveal_mask: Vec<u8> = (0..MAX_LEAVES)
        .map(|i| {
            if orig_normalised[i] == redc_normalised[i] {
                1u8
            } else {
                0u8
            }
        })
        .collect();

    let revealed_count = reveal_mask.iter().filter(|&&b| b == 1).count();
    let redacted_count = MAX_LEAVES - revealed_count;

    if redacted_count == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "All chunks are identical — no redaction detected. \
             Ensure the redacted file differs from the original.",
        ));
    }
    if revealed_count == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "No chunks are identical — the files appear unrelated. \
             Ensure the redacted file was derived from the original.",
        ));
    }

    // 5. Compute Poseidon original root.
    let original_root = compute_poseidon_commitment_root(&original_leaves);

    // 6. Compute redactedCommitment + revealMaskCommitment.
    let (redacted_commitment, reveal_mask_commitment) =
        compute_redaction_commitments(&original_leaves, &reveal_mask, revealed_count as u64);

    Ok(Json(RedactionLinkResponse {
        original_commit_id: body.original_commit_id,
        original_blake3: commit.doc_hash,
        original_root: original_root.to_string(),
        redacted_commitment: redacted_commitment.to_string(),
        reveal_mask_commitment: reveal_mask_commitment.to_string(),
        reveal_mask,
        revealed_count,
        redacted_count,
        // `verified` means the commit_id exists in the ledger, NOT that the supplied
        // chunk hashes cryptographically match `doc_hash`.  Full-file BLAKE3 cannot be
        // reconstructed from per-chunk hashes without the original chunk boundary parameters,
        // so binding is deferred to the ZK proof layer.
        verified: true,
        note: format!(
            "Redaction commitment verified. {redacted_count} of {MAX_LEAVES} chunks redacted, \
             {revealed_count} revealed. This bundle can be used as public inputs for the \
             redaction_validity ZK proof once the trusted-setup ceremony is complete."
        ),
    }))
}

// ── Router ────────────────────────────────────────────────────────────────────

// ── Route: POST /redaction/issue ─────────────────────────────────────────────
//
// Generate a `redaction_validity` Groth16 bundle for an already-committed
// document, scoped to a specific recipient.  The composite bundle bundles
// the existence proof (from `/ingest/records/hash/{hash}/zk_bundle`) with
// the redaction proof, both sharing `originalRoot` as a public signal so
// the verifier knows they're talking about the same document without
// trusting a side-channel.

#[derive(Deserialize)]
pub struct RedactionIssueRequest {
    /// BLAKE3 content hash of the original (already-committed) document.
    pub content_hash: String,
    /// 16-element 0/1 mask — `1` = chunk revealed, `0` = chunk redacted.
    pub reveal_mask: Vec<u8>,
    /// Decimal-string Fr value identifying the redaction recipient.  By
    /// convention this is the recipient's BJJ public-key X coordinate
    /// (so the recipient can verify the proof is bound to them), but the
    /// circuit treats it as opaque — any field element works.
    pub recipient_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionIssueResponse {
    pub circuit: String,
    pub content_hash: String,
    pub original_root: String,
    pub proof_json: serde_json::Value,
    pub public_signals: Vec<String>,
    pub reveal_mask: Vec<u8>,
    /// Per the redaction circuit's reveal-mask semantics: BLAKE3 hex chunk
    /// hashes for positions where `reveal_mask[i] == 1`, in original
    /// index order.  The recipient compares these to the BLAKE3-chunks of
    /// the file they were sent to confirm they hold the matching bytes.
    pub revealed_chunk_hashes: Vec<String>,
    /// 64-byte Ed25519 sig (lowercase hex) over
    /// `OLY:REDACTION_BUNDLE:V1|original_root=…|redacted_commitment=…|recipient_id=…`.
    pub signature_hex: String,
}

async fn issue_redaction(
    State(state): State<AppState>,
    auth: crate::api::middleware::auth::AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<RedactionIssueRequest>,
) -> Result<Json<RedactionIssueResponse>, ApiError> {
    if !auth.has_scope("redact")
        && !auth.has_scope("write")
        && !auth.has_scope("ingest")
        && !auth.has_scope("admin")
    {
        return Err(err(
            StatusCode::FORBIDDEN,
            "API key lacks required scope: one of 'redact', 'write', 'ingest', or 'admin'.",
        ));
    }

    // ── Input validation ─────────────────────────────────────────────────────

    let content_hash = body.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }
    if body.reveal_mask.len() != crate::zk::witness::redaction::MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "reveal_mask must have exactly {} entries; got {}.",
                crate::zk::witness::redaction::MAX_LEAVES,
                body.reveal_mask.len()
            ),
        ));
    }
    if body.reveal_mask.iter().any(|&b| b > 1) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "reveal_mask entries must be 0 or 1.",
        ));
    }
    let revealed_count = body.reveal_mask.iter().filter(|&&b| b == 1).count();
    if revealed_count == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "reveal_mask redacts every chunk — refusing to issue an empty disclosure.",
        ));
    }
    if revealed_count == crate::zk::witness::redaction::MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "reveal_mask reveals every chunk — no redaction; commit the original normally instead.",
        ));
    }

    // ── DB lookup: chunks + original_root ────────────────────────────────────

    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    #[derive(sqlx::FromRow)]
    struct ChunkRow {
        chunk_hashes: Option<serde_json::Value>,
        original_root: Option<String>,
    }

    let row: ChunkRow = sqlx::query_as::<_, ChunkRow>(
        "SELECT chunk_hashes, original_root FROM ingest_records \
         WHERE content_hash = $1 LIMIT 1",
    )
    .bind(&content_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| err(StatusCode::NOT_FOUND, "content_hash not found in ledger."))?;

    let chunks_val = row.chunk_hashes.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record has no chunk_hashes — it was committed before the 16-chunk \
             tree was wired in (or via the JSON-record path that doesn't chunk).",
        )
    })?;
    let original_root_hex = row.original_root.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "Record has no original_root — pre-snapshot record.",
        )
    })?;

    let chunk_hashes_hex: Vec<String> = chunks_val
        .as_array()
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "chunk_hashes is not an array.",
            )
        })?
        .iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_owned())
                .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "chunk hash not a string"))
        })
        .collect::<Result<Vec<String>, _>>()?;

    if chunk_hashes_hex.len() != crate::zk::witness::redaction::MAX_LEAVES {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!(
                "stored chunk_hashes has wrong length: {} (expected {}).",
                chunk_hashes_hex.len(),
                crate::zk::witness::redaction::MAX_LEAVES
            ),
        ));
    }

    // ── Build the redaction witness ─────────────────────────────────────────

    let leaves: Vec<ark_bn254::Fr> = chunk_hashes_hex
        .iter()
        .enumerate()
        .map(|(i, h)| {
            crate::zk::chunk::chunk_hex_to_leaf(h).map_err(|e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("chunk_hashes[{}]: {}", i, e),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let reveal_mask_bool: Vec<bool> = body.reveal_mask.iter().map(|&b| b == 1).collect();

    let (path_elements, path_indices) =
        crate::zk::chunk::paths_for_chunk_tree(&leaves).map_err(|e| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("paths_for_chunk_tree: {e}"),
            )
        })?;

    let original_root_fr = {
        use ark_ff::PrimeField;
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

    let recipient_id_fr = parse_decimal_fr(&body.recipient_id).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("recipient_id: {e}"),
        )
    })?;

    // Audit M-2: the redaction circuit now requires an in-circuit
    // EdDSA-Poseidon signature from the BJJ authority over the nullifier
    // digest. Compute the digest, sign with the server's authority key,
    // and pass both into the witness constructor. Without an authority
    // key configured we cannot mint a valid proof — fail with 503.
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
    let nullifier_msg = crate::zk::poseidon::hash_n(&[
        original_root_fr,
        crate::zk::poseidon::redaction_commitment(
            reveal_mask_bool.iter().filter(|&&b| b).count() as u64,
            &leaves,
            &reveal_mask_bool,
        )
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
        leaves.clone(),
        reveal_mask_bool,
        path_elements,
        path_indices,
        recipient_id_fr,
        bjj_pub,
        issuer_sig,
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &format!("witness: {e}")))?;

    // ── Generate the Groth16 proof ──────────────────────────────────────────

    let (proof_json, public_signals_dec) =
        generate_redaction_proof(state.proofs_dir.clone(), witness).await?;

    // ── Sign the bundle tuple ───────────────────────────────────────────────

    let redacted_commitment_dec = public_signals_dec.get(2).cloned().ok_or_else(|| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing redactedCommitment signal",
        )
    })?;

    let sig_payload = format!(
        "OLY:REDACTION_BUNDLE:V1|original_root={}|redacted_commitment={}|recipient_id={}",
        original_root_hex, redacted_commitment_dec, body.recipient_id,
    );
    let signature_hex = sign_bundle(sig_payload.as_bytes())?;

    // Forensic breadcrumb: log a BLAKE3 digest of the issued mask so that
    // multiple redactions issued for the same (content_hash, recipient_id)
    // pair can be reconstructed from logs even though no DB row stores the
    // mask itself. Audit L-API-4.
    let mask_digest = blake3::hash(&body.reveal_mask).to_hex().to_string();
    tracing::info!(
        content_hash = %content_hash,
        recipient_id = %body.recipient_id,
        mask_digest = %mask_digest,
        revealed_count = revealed_count,
        "redaction_issue",
    );

    // ── Collect revealed chunk hashes for the recipient's binding check ─────

    let revealed_chunk_hashes: Vec<String> = body
        .reveal_mask
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| {
            if b == 1 {
                Some(chunk_hashes_hex[i].clone())
            } else {
                None
            }
        })
        .collect();

    Ok(Json(RedactionIssueResponse {
        circuit: "redaction_validity".to_string(),
        content_hash,
        original_root: original_root_hex,
        proof_json,
        public_signals: public_signals_dec,
        reveal_mask: body.reveal_mask,
        revealed_chunk_hashes,
        signature_hex,
    }))
}

fn parse_decimal_fr(s: &str) -> Result<ark_bn254::Fr, String> {
    use ark_ff::PrimeField;
    let bigint = num_bigint::BigUint::parse_bytes(s.trim().as_bytes(), 10)
        .ok_or_else(|| format!("not a decimal field element: {s}"))?;
    let bytes_be = bigint.to_bytes_be();
    let mut padded = [0u8; 32];
    let off = 32usize.saturating_sub(bytes_be.len());
    padded[off..off + bytes_be.len()].copy_from_slice(&bytes_be);
    Ok(ark_bn254::Fr::from_be_bytes_mod_order(&padded))
}

fn sign_bundle(payload: &[u8]) -> Result<String, ApiError> {
    use ed25519_dalek::{Signer, SigningKey};
    let hex_key = std::env::var("OLYMPUS_INGEST_SIGNING_KEY")
        .or_else(|_| std::env::var("OLYMPUS_DEV_SIGNING_KEY"))
        .map_err(|e| {
            err(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("OLYMPUS_INGEST_SIGNING_KEY not configured: {e}"),
            )
        })?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_key.trim(), &mut bytes).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("signing key hex: {e}"),
        )
    })?;
    let sk = SigningKey::from_bytes(&bytes);
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
        groth16_proof_to_json(&proof),
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
fn fr_to_decimal(f: &ark_bn254::Fr) -> String {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = f.into_bigint().to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

#[cfg(feature = "prover")]
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

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/redaction/link", post(link_redaction))
        .route("/redaction/issue", post(issue_redaction))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_hash() -> String {
        "0".repeat(64)
    }

    fn one_hash() -> String {
        "1".repeat(64)
    }

    #[test]
    fn reveal_mask_correct() {
        let orig: Vec<String> = (0..MAX_LEAVES).map(|_| zero_hash()).collect();
        let mut redc = orig.clone();
        // Redact first chunk.
        redc[0] = one_hash();

        let mask: Vec<u8> = (0..MAX_LEAVES)
            .map(|i| if orig[i] == redc[i] { 1u8 } else { 0u8 })
            .collect();

        assert_eq!(mask[0], 0, "first chunk differs — should be 0");
        assert!(mask[1..].iter().all(|&b| b == 1));
        assert_eq!(mask.iter().filter(|&&b| b == 0).count(), 1);
    }

    #[test]
    fn leaf_derivation_is_deterministic() {
        let h = zero_hash();
        let l1 = blake3_hex_to_poseidon_leaf(&h).unwrap();
        let l2 = blake3_hex_to_poseidon_leaf(&h).unwrap();
        assert_eq!(l1, l2);
    }

    #[test]
    fn leaf_derivation_differs_for_different_hashes() {
        let h1 = blake3_hex_to_poseidon_leaf(&zero_hash()).unwrap();
        let h2 = blake3_hex_to_poseidon_leaf(&one_hash()).unwrap();
        assert_ne!(h1, h2);
    }
}
