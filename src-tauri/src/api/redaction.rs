//! Object-level redaction producer endpoints (ADR-0026).
//!
//! Routes
//! ------
//! * `POST /redaction/issue`  — prove a redaction of an already-committed PDF,
//!   selecting indirect objects to hide by id.
//! * `POST /redaction/redact` — Olympus-owned redaction: upload the committed
//!   PDF + object ids to hide, get back the zero-filled artifact **and** the
//!   `redaction_validity` bundle bound to it.
//!
//! Both build the 1024-leaf witness from the **object manifest persisted at
//! ingest** (`redaction_segment_manifests`, ADR-0026 Phase 4), so the proof's
//! `originalRoot` matches the object-level root committed on the ledger. The
//! per-object leaf is the hiding Pedersen commitment from
//! `olympus_crypto::redaction`; revealed objects' blindings are published in the
//! bundle so a recipient can recompute their leaves.
//!
//! The legacy chunk-based `/redaction/link` + `/redaction/redact` byte-range
//! path (ADR-0023/0025 chunk scheme) was removed with ADR-0026; `chunk.rs`
//! remains only as the general (non-PDF) ingest commitment.

use std::collections::HashSet;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

use olympus_crypto::redaction::derive_blinding;

use crate::api::middleware::auth::{AuthenticatedKey, RateLimit};
use crate::state::AppState;
use crate::zk::pdf_objects::{apply_redaction, witness_inputs, PdfObject, PdfObjectManifest, MAX_OBJECTS};

// ── Error helper ──────────────────────────────────────────────────────────────

type ApiError = (StatusCode, Json<serde_json::Value>);

fn err(status: StatusCode, detail: &str) -> ApiError {
    (status, Json(serde_json::json!({ "detail": detail })))
}

fn db_err(e: sqlx::Error) -> ApiError {
    tracing::error!("database error: {e}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "Database error.")
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedactionIssueRequest {
    /// BLAKE3 content hash (64-hex) of the original (already-committed) PDF.
    pub content_hash: String,
    /// Indirect-object ids to **hide**. Every other in-use object is revealed.
    pub redacted_obj_ids: Vec<u32>,
    /// Decimal-string Fr identifying the recipient (opaque to the circuit; by
    /// convention the recipient's BJJ public-key X coordinate).
    pub recipient_id: String,
}

/// Published blinding for one revealed object so the recipient can recompute its
/// hiding leaf `Poseidon(content·G + b·H)` (ADR-0026).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedSegment {
    pub segment_id: u32,
    /// Decimal Baby Jubjub subgroup scalar `b`.
    pub blinding_decimal: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionIssueResponse {
    pub circuit: String,
    pub content_hash: String,
    pub original_root: String,
    pub proof_json: serde_json::Value,
    pub public_signals: Vec<String>,
    /// The object ids that were hidden (mirrors the request, for the bundle).
    pub redacted_obj_ids: Vec<u32>,
    /// Per-revealed-object blindings — the recipient recomputes `content` from
    /// the artifact bytes and `leaf = Poseidon((content·G + b·H).x, .y)` and
    /// checks the redactedCommitment public signal.
    pub revealed_segments: Vec<RevealedSegment>,
    /// 64-byte Ed25519 sig (lowercase hex) over the length-prefixed payload
    /// `"OLY:REDACTION_BUNDLE:V2" || lp(content_hash) || lp(original_root) ||
    /// lp(redacted_commitment) || lp(recipient_id)` (canonical-decimal recipient).
    pub signature_hex: String,
}

fn require_redact_scope(auth: &AuthenticatedKey) -> Result<(), ApiError> {
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

// ── Manifest loading ────────────────────────────────────────────────────────

/// Load + reconstruct the object manifest committed at ingest for `content_hash`.
///
/// `content_hash` is per-shard unique (migration 0038); resolve to the earliest
/// row so a later cross-shard commit can't supply the inputs for someone else's
/// redaction (audit A1, carried over from the chunk path).
async fn load_object_manifest(
    state: &AppState,
    content_hash: &str,
) -> Result<PdfObjectManifest, ApiError> {
    let pool = state
        .pool
        .as_ref()
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable."))?;

    #[derive(sqlx::FromRow)]
    struct ManifestRow {
        original_root: String,
        tree_depth: i32,
        max_leaves: i32,
        segments: serde_json::Value,
    }

    let row: ManifestRow = sqlx::query_as::<_, ManifestRow>(
        "SELECT original_root, tree_depth, max_leaves, segments \
         FROM redaction_segment_manifests \
         WHERE content_hash = $1 \
         ORDER BY created_at ASC LIMIT 1",
    )
    .bind(content_hash)
    .fetch_optional(pool)
    .await
    .map_err(db_err)?
    .ok_or_else(|| {
        err(
            StatusCode::NOT_FOUND,
            "No object-level redaction manifest for this content_hash — the \
             document is not on-ledger, or was committed as a non-PDF (chunk) \
             record that isn't object-redactable.",
        )
    })?;

    #[derive(Deserialize)]
    struct SegmentRow {
        obj_id: u32,
        byte_offset: u64,
        byte_length: u64,
        leaf_hex: String,
    }
    let seg_rows: Vec<SegmentRow> = serde_json::from_value(row.segments).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("corrupt segment manifest: {e}"),
        )
    })?;

    // Defensive validation. This row is written by our own ingest path, but a
    // corrupt or forward-migrated manifest must fail cleanly (500), never panic
    // a fixed-size buffer copy downstream: `build_redaction_bundle`'s
    // original_root decode and `witness_inputs`' per-leaf decode both write into
    // a `[u8; 32]` and assume an exactly-`MAX_OBJECTS`-leaf tree.
    if !(0..=31).contains(&row.tree_depth) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest tree_depth out of range.",
        ));
    }
    let max_leaves = 1usize << (row.tree_depth as u32);
    if row.max_leaves < 0 || row.max_leaves as usize != max_leaves {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest max_leaves inconsistent with tree_depth.",
        ));
    }
    if seg_rows.len() > MAX_OBJECTS || seg_rows.len() > max_leaves {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest object count exceeds tree capacity.",
        ));
    }
    let root_bytes = hex::decode(&row.original_root).map_err(|_| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest original_root is not valid hex.",
        )
    })?;
    if root_bytes.len() != 32 {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "manifest original_root must be exactly 32 bytes.",
        ));
    }
    for s in &seg_rows {
        match hex::decode(&s.leaf_hex) {
            Ok(b) if b.len() == 32 => {}
            _ => {
                return Err(err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "manifest leaf_hex must be exactly 32 bytes.",
                ))
            }
        }
    }

    let objects = seg_rows
        .into_iter()
        .map(|s| PdfObject {
            obj_id: s.obj_id,
            generation: 0, // not needed for witness / redaction; not persisted
            byte_offset: s.byte_offset,
            byte_length: s.byte_length,
            leaf_hex: s.leaf_hex,
        })
        .collect();

    Ok(PdfObjectManifest {
        objects,
        original_root_hex: row.original_root,
        tree_depth: row.tree_depth as u8,
        max_leaves,
    })
}

/// Build the `MAX_OBJECTS`-wide reveal mask (real objects in obj-id order, then
/// zero-padding which is never revealed) and the revealed count. Errors if a
/// requested id is unknown, if nothing is redacted, or if everything is.
fn build_reveal_mask(
    manifest: &PdfObjectManifest,
    redacted: &HashSet<u32>,
) -> Result<(Vec<bool>, usize), ApiError> {
    for id in redacted {
        if !manifest.objects.iter().any(|o| o.obj_id == *id) {
            return Err(err(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("redacted_obj_ids contains unknown object {id}."),
            ));
        }
    }
    let mut mask = vec![false; MAX_OBJECTS];
    for (i, o) in manifest.objects.iter().enumerate() {
        mask[i] = !redacted.contains(&o.obj_id);
    }
    let revealed = mask.iter().filter(|&&b| b).count();
    if revealed == manifest.objects.len() {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "redacted_obj_ids is empty — nothing to redact; commit the original normally.",
        ));
    }
    if revealed == 0 {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "redacted_obj_ids hides every object — refusing to issue an empty disclosure.",
        ));
    }
    Ok((mask, revealed))
}

// ── POST /redaction/issue ─────────────────────────────────────────────────────

async fn issue_redaction(
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
async fn build_redaction_bundle(
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
    let content_hash_bytes = hex::decode(&content_hash)
        .map_err(|_| err(StatusCode::UNPROCESSABLE_ENTITY, "content_hash is not valid hex."))?;

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

    let recipient_id_fr = parse_decimal_fr(&req.recipient_id)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &format!("recipient_id: {e}")))?;
    let recipient_id_dec = crate::zk::proof::fr_to_decimal(&recipient_id_fr);

    // Audit M-2: in-circuit EdDSA-Poseidon issuer signature over the nullifier.
    let bjj_priv = state.bjj_authority_key.ok_or_else(|| {
        err(
            StatusCode::SERVICE_UNAVAILABLE,
            "OLYMPUS_BJJ_AUTHORITY_KEY not configured — cannot sign redaction proofs",
        )
    })?;
    let bjj_pub = state
        .bjj_authority_pubkey
        .ok_or_else(|| err(StatusCode::SERVICE_UNAVAILABLE, "BJJ authority pubkey not available"))?;
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

    let redacted_commitment_dec = public_signals_dec
        .get(2)
        .cloned()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "missing redactedCommitment signal"))?;

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
            blinding_decimal: derive_blinding(&blind_secret, &content_hash_bytes, &o.obj_id.to_be_bytes())
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

// ── POST /redaction/redact ────────────────────────────────────────────────────
//
// Olympus-owned object redaction. Given the (already-committed) original PDF and
// the object ids to hide, zero-fill those objects in place (length + offsets
// preserved) and return the artifact plus the bundle bound to it. The committed
// manifest supplies the byte spans; the uploaded bytes must match the on-ledger
// document (otherwise apply_redaction's span checks fail).

#[derive(Deserialize)]
pub struct RedactionRedactRequest {
    /// Base64 of the original (already-committed) PDF's raw bytes.
    pub original_base64: String,
    /// Indirect-object ids to hide.
    pub redacted_obj_ids: Vec<u32>,
    /// Recipient field element (decimal string), as in `/redaction/issue`.
    pub recipient_id: String,
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
    auth: AuthenticatedKey,
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

    // content_hash = BLAKE3 of the raw bytes (matches ingest), so a manifest
    // match also proves this upload IS the committed document.
    let content_hash = blake3::hash(&original).to_hex().to_string();

    // Apply the in-place object zero-fill using the committed manifest's spans.
    let manifest = load_object_manifest(&state, &content_hash).await?;
    let redacted = apply_redaction(&original, &manifest, &body.redacted_obj_ids)
        .map_err(|e| err(StatusCode::UNPROCESSABLE_ENTITY, &format!("redact: {e}")))?;
    let redacted_base64 = STANDARD.encode(&redacted);

    let bundle = build_redaction_bundle(
        &state,
        RedactionIssueRequest {
            content_hash,
            redacted_obj_ids: body.redacted_obj_ids,
            recipient_id: body.recipient_id,
        },
    )
    .await?;

    Ok(Json(RedactionRedactResponse {
        redacted_base64,
        bundle,
    }))
}

// ── GET /redaction/manifest/:content_hash ─────────────────────────────────────
//
// Operator-facing object listing for the producer UI: given an already-committed
// document's content_hash, return its committed objects (id + byte length) so a
// redactor can pick which to hide. Scope-gated like the producer endpoints —
// the object structure of a committed document is operator information.

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestObject {
    /// Indirect-object id (== `segment_id` in the bundle's `revealed_segments`).
    pub segment_id: u32,
    /// Length in bytes of the object's `N G obj … endobj` span.
    pub byte_length: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RedactionManifestResponse {
    pub content_hash: String,
    pub original_root: String,
    pub object_count: usize,
    pub objects: Vec<ManifestObject>,
}

async fn get_manifest(
    State(state): State<AppState>,
    auth: AuthenticatedKey,
    _rl: RateLimit,
    Path(content_hash): Path<String>,
) -> Result<Json<RedactionManifestResponse>, ApiError> {
    require_redact_scope(&auth)?;

    let content_hash = content_hash.trim().to_lowercase();
    if content_hash.len() != 64 || !content_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(err(
            StatusCode::UNPROCESSABLE_ENTITY,
            "content_hash must be a 64-character hex string.",
        ));
    }

    let manifest = load_object_manifest(&state, &content_hash).await?;
    let objects: Vec<ManifestObject> = manifest
        .objects
        .iter()
        .map(|o| ManifestObject {
            segment_id: o.obj_id,
            byte_length: o.byte_length,
        })
        .collect();

    Ok(Json(RedactionManifestResponse {
        content_hash,
        original_root: manifest.original_root_hex,
        object_count: objects.len(),
        objects,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
                &format!("redaction circuit artifact missing: {label} at {}", path.display()),
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
        .route("/redaction/manifest/{content_hash}", get(get_manifest))
        .route("/redaction/issue", post(issue_redaction))
        .route("/redaction/redact", post(redact_redaction))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(id: u32) -> PdfObject {
        PdfObject {
            obj_id: id,
            generation: 0,
            byte_offset: 0,
            byte_length: 0,
            leaf_hex: "00".repeat(32),
        }
    }

    fn manifest(ids: &[u32]) -> PdfObjectManifest {
        PdfObjectManifest {
            objects: ids.iter().map(|&i| obj(i)).collect(),
            original_root_hex: "00".repeat(32),
            tree_depth: 10,
            max_leaves: MAX_OBJECTS,
        }
    }

    #[test]
    fn reveal_mask_redacts_selected_objects() {
        let m = manifest(&[1, 2, 3]);
        let (mask, revealed) = build_reveal_mask(&m, &HashSet::from([2])).unwrap();
        assert_eq!(mask.len(), MAX_OBJECTS);
        assert_eq!(&mask[..3], &[true, false, true]); // object 2 hidden
        assert!(mask[3..].iter().all(|&b| !b)); // padding never revealed
        assert_eq!(revealed, 2);
    }

    #[test]
    fn reveal_mask_rejects_unknown_redacting_all_or_none() {
        let m = manifest(&[1, 2, 3]);
        // unknown id
        assert!(build_reveal_mask(&m, &HashSet::from([9])).is_err());
        // nothing redacted
        assert!(build_reveal_mask(&m, &HashSet::new()).is_err());
        // everything redacted
        assert!(build_reveal_mask(&m, &HashSet::from([1, 2, 3])).is_err());
    }

    #[test]
    fn parse_decimal_fr_is_canonical() {
        // "0001" and "1" reduce to the same field element (and same proof).
        assert_eq!(parse_decimal_fr("0001").unwrap(), parse_decimal_fr("1").unwrap());
        assert!(parse_decimal_fr("not-a-number").is_err());
    }
}
