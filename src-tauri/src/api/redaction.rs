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
use base64::{engine::general_purpose::STANDARD, Engine as _};
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
        // Audit B3: this endpoint does NOT cryptographically bind the supplied
        // chunk hashes to the committed `doc_hash` — full-file BLAKE3 cannot be
        // reconstructed from per-chunk hashes without the original chunk
        // boundary parameters, so that binding is enforced only by the
        // redaction_validity ZK proof. Previously this returned `verified:
        // true`, which overstated what was checked. It now reflects reality:
        // the commit exists, but the chunk↔document binding is unverified here.
        verified: false,
        note: format!(
            "Original commit found in the ledger and candidate redaction commitments computed \
             ({redacted_count} of {MAX_LEAVES} chunks redacted, {revealed_count} revealed). \
             NOTE: this endpoint does not verify that the supplied chunks belong to the \
             committed document — that binding is enforced by the redaction_validity ZK proof \
             (pending trusted setup). Do not treat this response as proof of redaction."
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
    /// 64-byte Ed25519 sig (lowercase hex) over the length-prefixed payload
    /// `"OLY:REDACTION_BUNDLE:V2" || lp(content_hash) || lp(original_root) ||
    /// lp(redacted_commitment) || lp(recipient_id)`, where `lp(x)` is a 4-byte
    /// big-endian length prefix and `recipient_id` is the **canonical decimal**
    /// of the recipient field element (so `"0001"` and `"1"` sign identically and
    /// match the proof). Verifiers MUST reconstruct the payload with the same
    /// length-prefix framing (the V1 raw-`|` form is retired — audit B2).
    pub signature_hex: String,
}

fn require_redact_scope(
    auth: &crate::api::middleware::auth::AuthenticatedKey,
) -> Result<(), ApiError> {
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
    Ok(())
}

async fn issue_redaction(
    State(state): State<AppState>,
    auth: crate::api::middleware::auth::AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<RedactionIssueRequest>,
) -> Result<Json<RedactionIssueResponse>, ApiError> {
    require_redact_scope(&auth)?;
    Ok(Json(build_redaction_bundle(&state, body).await?))
}

/// Shared proving core for `/redaction/issue` and `/redaction/redact`: validate
/// the `(content_hash, reveal_mask, recipient_id)` triple, look up the committed
/// chunk leaves + `original_root`, build + prove the redaction witness, and sign
/// the bundle. Callers perform the scope check first.
async fn build_redaction_bundle(
    state: &AppState,
    req: RedactionIssueRequest,
) -> Result<RedactionIssueResponse, ApiError> {
    // ── Input validation ─────────────────────────────────────────────────────

    let content_hash = req.content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }
    if req.reveal_mask.len() != crate::zk::witness::redaction::MAX_LEAVES {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!(
                "reveal_mask must have exactly {} entries; got {}.",
                crate::zk::witness::redaction::MAX_LEAVES,
                req.reveal_mask.len()
            ),
        ));
    }
    if req.reveal_mask.iter().any(|&b| b > 1) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "reveal_mask entries must be 0 or 1.",
        ));
    }
    let revealed_count = req.reveal_mask.iter().filter(|&&b| b == 1).count();
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
        // Audit A1: content_hash is per-shard unique only (migration 0038);
        // resolve to the earliest commit so a later cross-shard commit can't
        // supply the chunk/original_root inputs for someone else's redaction.
        "SELECT chunk_hashes, original_root FROM ingest_records \
         WHERE content_hash = $1 \
         ORDER BY ts ASC, proof_id ASC LIMIT 1",
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

    let reveal_mask_bool: Vec<bool> = req.reveal_mask.iter().map(|&b| b == 1).collect();

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

    let recipient_id_fr = parse_decimal_fr(&req.recipient_id).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("recipient_id: {e}"),
        )
    })?;
    // Sign/log the CANONICAL decimal form of the recipient field element, not the
    // raw request string: "0001" and "1" reduce to the same Fr (and the same
    // proof/nullifier), so the signed payload must use the canonical value or the
    // bundle isn't self-consistent for a verifier reconstructing from the proof.
    let recipient_id_dec = crate::zk::proof::fr_to_decimal(&recipient_id_fr);

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
    // Fail fast: resolve the Ed25519 bundle-signing key BEFORE the expensive
    // witness build + Groth16 prove, so a misconfigured node returns 503
    // without burning the proving path.
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

    // Audit B2: V1 joined variable-length fields (notably the attacker-supplied
    // `recipient_id`) with raw `|`, so a crafted recipient_id could shift the
    // field boundaries and make one signature satisfy a different
    // (commitment, recipient) decomposition. V2 length-prefixes every field
    // (unambiguous boundaries) and additionally binds `content_hash`, so a
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

    // Forensic breadcrumb: log a BLAKE3 digest of the issued mask so that
    // multiple redactions issued for the same (content_hash, recipient_id)
    // pair can be reconstructed from logs even though no DB row stores the
    // mask itself. Audit L-API-4.
    let mask_digest = blake3::hash(&req.reveal_mask).to_hex().to_string();
    tracing::info!(
        content_hash = %content_hash,
        recipient_id = %recipient_id_dec,
        mask_digest = %mask_digest,
        revealed_count = revealed_count,
        "redaction_issue",
    );

    // ── Collect revealed chunk hashes for the recipient's binding check ─────

    let revealed_chunk_hashes: Vec<String> = req
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

    Ok(RedactionIssueResponse {
        circuit: "redaction_validity".to_string(),
        content_hash,
        original_root: original_root_hex,
        proof_json,
        public_signals: public_signals_dec,
        reveal_mask: req.reveal_mask,
        revealed_chunk_hashes,
        signature_hex,
    })
}

// ── Route: POST /redaction/redact ────────────────────────────────────────────
//
// Olympus-owned redaction. Given the (already-committed) ORIGINAL file and the
// byte ranges to hide, produce a binding-compatible redacted artifact (same
// length, in-place blanked) plus the `redaction_validity` bundle. This is the
// piece that makes the chunk circuit's binding actually hold: an externally
// edited document re-serializes and never binds, so the redactor must own the
// byte transformation. Text-oriented by design (see `crate::zk::redact`).

#[derive(Deserialize)]
pub struct ByteRangeReq {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

#[derive(Deserialize)]
pub struct RedactionRedactRequest {
    /// Base64 of the original (already-committed) document's raw bytes.
    pub original_base64: String,
    /// Half-open byte ranges `[start, end)` to redact.
    pub ranges: Vec<ByteRangeReq>,
    /// Recipient field element (decimal string), as in `/redaction/issue`.
    pub recipient_id: String,
    /// Optional fill byte for blanked regions (cosmetic; default `0x00`).
    #[serde(default)]
    pub fill: Option<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionRedactResponse {
    /// Base64 of the redacted artifact (same length as the original).
    pub redacted_base64: String,
    /// The `redaction_validity` bundle bound to the artifact above.
    pub bundle: RedactionIssueResponse,
}

async fn redact_redaction(
    State(state): State<AppState>,
    auth: crate::api::middleware::auth::AuthenticatedKey,
    _rl: RateLimit,
    Json(body): Json<RedactionRedactRequest>,
) -> Result<Json<RedactionRedactResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let original = STANDARD.decode(body.original_base64.trim()).map_err(|e| {
        err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("original_base64: invalid base64: {e}"),
        )
    })?;

    // content_hash = plain BLAKE3 of the raw bytes (matches the ingest path), so
    // a committed-record match in build_redaction_bundle also proves this upload
    // IS that document — you can only redact something already on-ledger, and
    // the stored chunk leaves line up with the artifact's revealed chunks.
    let content_hash = blake3::hash(&original).to_hex().to_string();

    let ranges: Vec<(usize, usize)> = body.ranges.iter().map(|r| (r.start, r.end)).collect();
    let fill = body.fill.unwrap_or(crate::zk::redact::DEFAULT_FILL);
    let redaction = crate::zk::redact::redact_chunk_aligned(&original, &ranges, fill)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &format!("redact: {e}")))?;

    let redacted_base64 = STANDARD.encode(&redaction.redacted);

    let bundle = build_redaction_bundle(
        &state,
        RedactionIssueRequest {
            content_hash,
            reveal_mask: redaction.reveal_mask,
            recipient_id: body.recipient_id,
        },
    )
    .await?;

    Ok(Json(RedactionRedactResponse {
        redacted_base64,
        bundle,
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

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/redaction/link", post(link_redaction))
        .route("/redaction/issue", post(issue_redaction))
        .route("/redaction/redact", post(redact_redaction))
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
